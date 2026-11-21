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
   scalar loop elsewhere). A line is a walk over delimiter bits. Every comma
   separates fields and only `\n` ends a line, so no quote state is needed; a
   line is malformed when its field count is wrong or when its number of quote
   characters is not exactly twice the number of fields that start and end
   with a quote.
3. **Exact keys** (`src/key.rs`). Every ID becomes a `u128` that represents
   the string exactly: up to 15 bytes are stored inline with the length (and
   integer order equals byte-wise string order), longer strings are interned
   in a global table. Equality is always on the exact key; hashes only choose
   partitions and table slots.
4. **Links.** Link lines are parsed in parallel, then one thread runs a
   union-find and names each component by its byte-wise smallest ID. The
   result is one flat table from linked ID to person name; an ID that is not
   in it is its own person. This runs while the other threads parse events.
5. **Events, pass 1.** Each row is parsed and validated on the spot
   (timestamps in all three forms, window, type, product, price, lateness),
   because validity is a property of the row. Valid or not, the row is
   scattered into one of up to 2048 partitions by a hash of its `event_id`.
6. **Events, pass 2: dedup before validation.** Each partition is deduplicated
   in a cache-sized hash table: the copy with the smallest `ingest_ts` wins,
   and if that copy is invalid the event is gone. Survivors get their person
   from the link table (prefetched a few rows ahead) and are scattered by a
   hash of the person.
7. **Clicks.** Parsed, validated and resolved to their person in one pass, and
   scattered into the same person partitions. Copies of a click are identical
   by the rules, and an identical copy can change neither the credited
   campaign nor the set of assisting campaigns, so no click dedup is needed.
8. **Sessions.** Per person partition: events and clicks are grouped by person
   with a counting sort, each person's events are sorted by `ts` and split
   into sessions (gap over 30 minutes; equal timestamps share a session).
   Clicks are sorted by `(ts, click_id)` and a sliding 7-day window is moved
   over them as the sessions advance, keeping a count per campaign, so
   crediting and assists cost O(clicks + sessions x distinct campaigns) even
   for the shared-device persons with thousands of merged people.
9. **Output** (`src/pq.rs`). A minimal Parquet writer: uncompressed, PLAIN
   encoding, data page v1. Each thread writes its own `user_daily` file as it
   goes; the per-thread `(campaign, day)` counters are summed and written as
   one `campaign_daily` file. `day` is `INT32` with the `DATE` logical type.

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
| `SS_CHUNK`, `SS_PE_BITS`, `SS_PP_BITS`, `SS_NOCAP`, `SS_SPARSE` | unset | testing knobs: range size, partition counts, thread cap, sparse campaign counters |

## Libraries

None at run time and none at build time: the crate has no dependencies beyond
the Rust standard library. The test scripts in `scripts/` come from the
organizers' starter and use `polars`.

## Layout

- `src/main.rs` pipeline stages
- `src/scan.rs` CSV scanner
- `src/key.rs` exact keys, hash map, allocation
- `src/ts.rs` timestamp and number parsing
- `src/pq.rs` Parquet writer
- `fixtures/`, `scripts/`, `rules.md` from the organizers' kit
- `fixtures-extra/` six more hand-written edge cases (CRLF, duplicates, long IDs, leap day, number limits, NUL bytes)

## License

MIT, see `LICENSE`.
