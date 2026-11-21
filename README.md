# Shopping Sessions in Rust

A submission for the "Databricks - Shopping Sessions" track: one statically
linked Rust binary, no external crates, in a `FROM scratch` image. It reads the
CSV inputs under `DATA_DIR`, applies `rules.md` to the letter, and writes the
two Parquet tables under `OUTPUT_DIR`.

`rules.md` is the spec. Where this README and `rules.md` disagree, `rules.md`
wins.

## How it works

Everything is in memory; `SCRATCH_DIR` and `/tmp` are not used. The work is a
sequence of parallel stages on `NCPU` threads, each pulling items from a shared
atomic counter.

1. **Setup.** `manifest.json`, `products.csv` and `campaigns.csv` are read into
   small exact hash maps. Categories are numbered in byte-wise name order
   (`unknown` included), so "smallest category wins a tie" is an integer
   comparison. Every `*.csv` under `events/`, `clicks/` and `links/` is
   memory-mapped and cut into 4 MB ranges that are snapped to line boundaries;
   the first line of every file is its header. Header-only and empty files
   simply yield no ranges or no rows.
2. **CSV scanning** (`src/scan.rs`). A block of 64 bytes is turned into three
   bitmasks: delimiters, newlines, quotes (AVX2 on x86-64, NEON on arm64, a
   scalar loop elsewhere). A line is a walk over delimiter bits; splitting it
   into dequoted fields is branch-free. Every comma
   separates fields and only `\n` ends a line, so no quote state is needed; a
   line is malformed when its field count is wrong or when its number of quote
   characters is not exactly twice the number of fields that start and end
   with a quote.
3. **Exact keys** (`src/key.rs`). Every ID becomes a `u64` that represents
   the string exactly. A string of up to 10 bytes over `0-9 A-Z _ a-z` (every
   ID the generator makes) is written as one 6-bit code per byte, so integer
   order equals byte-wise string order; 16 bytes are classified at once (SSE2
   on x86-64, NEON on arm64). Any other string is interned in a global table.
   Equality is always on the exact key; hashes only choose partitions and
   table slots.
4. **Links.** Link lines are parsed in parallel, then one thread runs a
   union-find that keeps the byte-wise smallest ID at each root. The result is
   a map from each ID whose person has another name to that name, in buckets
   of one cache line; an ID that is not in it is its own person. This runs
   while the other threads already parse events.
5. **Events, one pass over the files.** Each row is parsed and validated on
   the spot (timestamps in all three forms, window, type, product, price,
   lateness), because validity is a property of the row. A valid row gets its
   person from the link map (the bucket is prefetched a few rows ahead) and is
   scattered by a hash of the person as a 16-byte record: the person and one
   word holding `ts - window_start`, price and category. That record is final
   and never moves again. Every row, valid or not, also leaves a 16-byte dedup
   record, scattered by a hash of the `event_id`: the ID and one word holding
   `ingest_ts` as a 21-bit offset and the address of the row's event record
   (null for an invalid row). Values that do not fit these words (a window of
   years, an `ingest_ts` weeks away from the window) go to side lists and stay
   exact. Rows parsed before the union-find has finished wait in a per-thread
   backlog.
6. **Dedup before validation.** Each `event_id` partition is deduplicated in a
   cache-sized hash table: the copy with the smallest `ingest_ts` wins, and
   every losing copy that is a valid event is struck out in place through its
   pointer. If the winner is an invalid row the event is gone, because all its
   valid copies were struck out.
7. **Clicks.** Parsed, validated and resolved to their person in one pass, and
   scattered into the same person partitions. Copies of a click are identical
   by the rules, and an identical copy can change neither the credited
   campaign nor the set of assisting campaigns, so no click dedup is needed.
8. **Sessions.** Per person partition, biggest first: events and clicks are
   grouped by person with a counting sort, each person's events are sorted by
   `ts` (the 8-byte word of the event record sorts by `ts` as it is; a 16-byte
   form is the fallback when that word is an index into a side list) and split
   into sessions (gap over 30 minutes; equal timestamps share a session).
   Clicks are sorted by `ts`, the smallest `click_id` of a tie is tracked, and
   a sliding 7-day window is moved over them as the sessions advance, keeping
   a count per campaign. An assist is not booked per session: a campaign covers a run of
   consecutive sessions, booked when the run or the day ends, so crediting and
   assists cost O(clicks + sessions) plus O(distinct campaigns) per day, even
   for the shared-device persons with thousands of merged people.
9. **Output** (`src/pq.rs`). A minimal Parquet writer: uncompressed, PLAIN
   encoding, data page v1. Each thread writes its own `user_daily` file as it
   goes; the per-thread `(campaign, day)` counters are summed and written as
   one `campaign_daily` file. `day` is `INT32` with the `DATE` logical type.
10. **Huge pages.** The scatter buffers and the link map are advised for
    transparent huge pages on Linux, but only for as much memory as the
    kernel reports free in blocks of 2 MB or more (`/proc/buddyinfo`) when
    the run starts. Asking for more would make every page fault compact
    memory first, which costs far more than small pages do; beyond the budget
    the system's own setting applies.
11. **Letting go.** Input files, the link maps and the scatter buffers are
    handed back to the kernel by the worker threads of the following stage,
    as soon as those run out of work (`MADV_DONTNEED` on Linux). What is
    still mapped at exit is torn down by one thread, and that time counts.

## Run and test

With Docker (as the scorer runs it):

```sh
make build        # linux/amd64 image
make fixtures     # all 36 fixtures through the image
make dev          # generate the 1M-event dev set (needs `generate` on PATH)
make run-dev      # run the image on dev/ with the scorer's flags, timed
make check-dev    # exact diff against dev-answer/
```

Without Docker (needs Rust 1.99 and Python 3.10+ with `polars`):

```sh
make native-fixtures
make native-fixtures-extra   # 5 more hand-written cases, see fixtures-extra/README.md
make native-run-dev && make check-dev
```

The binary takes no arguments. Environment:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATA_DIR` | `/data` | inputs |
| `OUTPUT_DIR` | `/output` | `user_daily/` and `campaign_daily/` are created here |
| `NCPU` | available cores | worker threads |
| `SS_TIME` | unset | print stage timings to stderr |
| `SS_THP` | unset | Linux: `1` always ask for huge pages, `0` always refuse them, `2` never advise; unset = ask within the free-memory budget |
| `SS_THP_MB` | unset | Linux: the huge-page budget in MB, instead of reading `/proc/buddyinfo` |
| `SS_POP` | unset | Linux: fault each file range in with one `MADV_POPULATE_READ` before it is parsed |
| `SS_CHUNK`, `SS_PE_BITS`, `SS_PP_BITS`, `SS_NOCAP`, `SS_SPARSE`, `SS_WIDE`, `SS_IBASE` | unset | testing knobs: range size, partition counts, thread cap, sparse campaign counters, the wide event form, a shifted base for the ingest offsets |

## Libraries

None at run time and none at build time: the crate has no dependencies beyond
the Rust standard library. The test scripts in `scripts/` come from the
organizers' starter and use `polars`.

## Layout

- `src/main.rs` pipeline stages
- `src/scan.rs` CSV scanner
- `src/key.rs` exact keys, hash maps, allocation
- `src/ts.rs` timestamp and number parsing
- `src/pq.rs` Parquet writer
- `fixtures/`, `scripts/`, `rules.md` from the organizers' kit
- `fixtures-extra/` six more hand-written edge cases (CRLF, duplicates, long IDs, leap day, number limits, NUL bytes)

## License

MIT, see `LICENSE`.
