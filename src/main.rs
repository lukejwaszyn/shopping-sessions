//! Shopping Sessions pipeline. See README.md for the design.

mod key;
mod pq;
mod scan;
mod ts;

use key::{big_alloc, compact_bytes, hash, is_long, key_bytes, key_cmp, make_key, map_ro, prefetch, release, BMap, KMap, Key, HUGE};
use pq::{Col, ColDef, Ty, Writer};
use scan::{chunk_bounds, fields, Scanner};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::OnceLock;
use std::time::Instant;
use ts::{parse_digits, parse_dt_c, parse_ts, DateCache};

const GAP_MS: i64 = 1_800_000;
const WEEK_MS: i64 = 604_800_000;
const DAY_MS: i64 = 86_400_000;

// ---------------------------------------------------------------- records

/// A parsed, valid event row waiting for its person to be resolved, 32 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
struct ERec {
    ek: Key,
    uk: Key,
    /// see `PRec`
    w: u64,
    /// ingest_ts, epoch seconds
    ing: i64,
}

/// One event row as the dedup sees it, 16 bytes: its ID and, in `x`, its
/// ingest time and where its `PRec` lives (null for a row that failed
/// validation).
///
/// `x` is `code << 43 | pointer >> 4`. The code is `ingest_ts - cx.ibase` in
/// seconds when that is in `0..ING_ESC` (24 days from one day before the
/// window: every row the generator makes). Any other row has the code
/// `ING_ESC` and, instead of the pointer, `thread << 32 | index` of an entry
/// in that thread's overflow list, which holds the exact values.
#[derive(Clone, Copy)]
#[repr(C)]
struct DRec {
    ek: Key,
    x: u64,
}

const ING_ESC: u64 = (1 << 21) - 1;
const PTR_BITS: u32 = 43;
const PTR_MASK: u64 = (1 << PTR_BITS) - 1;

/// Exact (ingest_ts, PRec address) of the rows that do not fit a `DRec`.
type Over = Vec<(i64, usize)>;

/// A valid event, attached to its person, 16 bytes. The dedup sets `w` to
/// `DEAD` when another copy of the event wins.
///
/// Narrow form (`cx.narrow`): `w` is `(ts - window_start) << cx.ts_shift |
/// price << cx.cat_bits | category`, price 0 for a view or a cart. It sorts
/// by `ts` as it is. Wide form, for windows or category counts too big for
/// that: `w` is `thread << 40 | index` into that thread's side list of
/// `(ts, price, category)`.
#[derive(Clone, Copy)]
#[repr(C)]
struct PRec {
    person: Key,
    w: u64,
}

/// No event has this `w`: in the narrow form its price field would be over
/// the limit, in the wide form its thread number would be.
const DEAD: u64 = u64::MAX;
const PRICE_BITS: u32 = 24;
const PRICE_MASK: u64 = (1 << PRICE_BITS) - 1;
const SIDE_BITS: u32 = 40;

type Side = Vec<(i64, u32, u32)>;

/// A valid click, attached to its person.
#[derive(Clone, Copy)]
#[repr(C)]
struct CRec {
    person: Key,
    ck: Key,
    ts: i64,
    camp: u32,
}

#[derive(Clone, Copy)]
struct Clk {
    ck: Key,
    ts: i64,
    camp: u32,
}

const DCAP: usize = 256;
const PCAP: usize = 256;
const CCAP: usize = 128;

// ---------------------------------------------------------------- buckets

const SLAB: usize = 8 << 20;

/// Bump allocator. Nothing is freed one by one; the slabs are released as a
/// whole when the stage that reads them is over.
struct Arena {
    ptr: *mut u8,
    left: usize,
    /// (address, bytes) of every slab
    slabs: Vec<(usize, usize)>,
}

impl Arena {
    fn alloc(&mut self, bytes: usize) -> *mut u8 {
        let bytes = (bytes + 15) & !15;
        if bytes > self.left {
            let sz = (SLAB.max(bytes) + HUGE - 1) & !(HUGE - 1);
            self.ptr = big_alloc(sz);
            self.left = sz;
            self.slabs.push((self.ptr as usize, sz));
        }
        let p = self.ptr;
        self.ptr = unsafe { p.add(bytes) };
        self.left -= bytes;
        p
    }
}

/// One thread's records, scattered into partitions as lists of fixed-size
/// chunks.
struct Buckets<T> {
    cap: u32,
    cur: Vec<(*mut T, u32)>,
    full: Vec<Vec<*mut T>>,
    arena: Arena,
}

unsafe impl<T> Send for Buckets<T> {}
unsafe impl<T> Sync for Buckets<T> {}

impl<T: Copy> Buckets<T> {
    fn new(parts: usize, cap: usize) -> Buckets<T> {
        Buckets {
            cap: cap as u32,
            cur: vec![(std::ptr::null_mut(), cap as u32); parts],
            full: (0..parts).map(|_| Vec::new()).collect(),
            arena: Arena { ptr: std::ptr::null_mut(), left: 0, slabs: Vec::new() },
        }
    }

    #[inline(always)]
    fn push(&mut self, p: usize, r: T) {
        if unsafe { self.cur.get_unchecked(p).1 } == self.cap {
            self.grow(p);
        }
        let c = unsafe { self.cur.get_unchecked_mut(p) };
        unsafe { c.0.add(c.1 as usize).write(r) };
        c.1 += 1;
    }

    /// Like `push`, and says where the record now lives. Records never move.
    #[inline(always)]
    fn push_ptr(&mut self, p: usize, r: T) -> *mut T {
        if unsafe { self.cur.get_unchecked(p).1 } == self.cap {
            self.grow(p);
        }
        let c = unsafe { self.cur.get_unchecked_mut(p) };
        let at = unsafe { c.0.add(c.1 as usize) };
        unsafe { at.write(r) };
        c.1 += 1;
        at
    }

    #[cold]
    #[inline(never)]
    fn grow(&mut self, p: usize) {
        let c = self.cur[p];
        if !c.0.is_null() {
            self.full[p].push(c.0);
        }
        let np = self.arena.alloc(self.cap as usize * std::mem::size_of::<T>()) as *mut T;
        self.cur[p] = (np, 0);
    }

    /// Number of records in partition `p`.
    fn len(&self, p: usize) -> usize {
        let c = self.cur[p];
        self.full[p].len() * self.cap as usize + if c.0.is_null() { 0 } else { c.1 as usize }
    }

    /// Append partition `p`'s chunks as (pointer, length). Full chunks first.
    fn chunks(&self, p: usize, out: &mut Vec<(*mut T, usize)>) {
        for &c in &self.full[p] {
            out.push((c, self.cap as usize));
        }
        let c = self.cur[p];
        if !c.0.is_null() && c.1 > 0 {
            out.push((c.0, c.1 as usize));
        }
    }
}

/// Memory nobody reads any more, cut into pieces that the threads of a later
/// stage release when they run out of work (see `key::release`).
struct Garbage {
    pieces: Vec<(usize, usize)>,
    next: AtomicUsize,
}

impl Garbage {
    fn new() -> Garbage {
        Garbage { pieces: Vec::new(), next: AtomicUsize::new(0) }
    }

    /// `ptr` is page-aligned and the range is whole pages of one mapping.
    fn add(&mut self, ptr: usize, len: usize) {
        const PIECE: usize = 16 << 20;
        let mut off = 0;
        while off < len {
            let n = PIECE.min(len - off);
            self.pieces.push((ptr + off, n));
            off += n;
        }
    }

    fn add_files(&mut self, files: &[MFile]) {
        for f in files {
            if f.mapped {
                self.add(f.ptr as usize, f.len);
            }
        }
    }

    fn add_slabs<T>(&mut self, bs: &[Buckets<T>]) {
        for b in bs {
            for &(ptr, len) in &b.arena.slabs {
                self.add(ptr, len);
            }
        }
    }

    fn drain(&self) {
        loop {
            let i = self.next.fetch_add(1, Relaxed);
            if i >= self.pieces.len() {
                break;
            }
            release(self.pieces[i].0 as *mut u8, self.pieces[i].1);
        }
    }
}

/// Partition `p`'s chunks of all threads.
fn all_chunks<T: Copy>(bs: &[Buckets<T>], p: usize, out: &mut Vec<(*mut T, usize)>) {
    out.clear();
    for b in bs {
        b.chunks(p, out);
    }
}

#[inline(always)]
fn part(h: u64, bits: u32) -> usize {
    ((h >> 1) >> (63 - bits)) as usize
}

// ---------------------------------------------------------------- files

struct MFile {
    ptr: *const u8,
    len: usize,
    /// memory-mapped, not read into the heap
    mapped: bool,
}
unsafe impl Send for MFile {}
unsafe impl Sync for MFile {}

impl MFile {
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

fn map_file(path: &Path) -> Option<MFile> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path.display(), e));
    let len = f.metadata().unwrap().len() as usize;
    if len == 0 {
        return None;
    }
    match map_ro(f.as_raw_fd(), len) {
        Some(ptr) => Some(MFile { ptr, len, mapped: true }),
        None => {
            let v = std::fs::read(path).unwrap().leak();
            Some(MFile { ptr: v.as_ptr(), len: v.len(), mapped: false })
        }
    }
}

/// Every `*.csv` file of a directory, memory-mapped. Empty files are skipped.
fn map_dir(dir: &Path) -> Vec<MFile> {
    let mut paths: Vec<PathBuf> = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let is_csv = p.file_name().and_then(|n| n.to_str()).map_or(false, |n| n.ends_with(".csv"));
            if is_csv && std::fs::metadata(&p).map_or(false, |m| m.is_file()) {
                paths.push(p);
            }
        }
    }
    paths.sort();
    paths.iter().filter_map(|p| map_file(p)).collect()
}

/// Raw byte ranges (file, start, end) of about `chunk` bytes, largest files
/// first so the big ones are spread over all threads from the start.
fn make_chunks(files: &[MFile], chunk: usize) -> Vec<(usize, usize, usize)> {
    let mut order: Vec<usize> = (0..files.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(files[i].len));
    let mut out = Vec::new();
    for i in order {
        let len = files[i].len;
        let n = len.div_ceil(chunk).max(1);
        let step = len.div_ceil(n);
        let mut s = 0;
        while s < len {
            let e = (s + step).min(len);
            out.push((i, s, e));
            s = e;
        }
    }
    out
}

// ---------------------------------------------------------------- threads

fn par_map<R: Send, F: Fn(usize) -> R + Sync>(nt: usize, f: F) -> Vec<R> {
    if nt <= 1 {
        return vec![f(0)];
    }
    std::thread::scope(|s| {
        let f = &f;
        let hs: Vec<_> = (1..nt).map(|t| s.spawn(move || f(t))).collect();
        let mut out = vec![f(0)];
        for h in hs {
            out.push(h.join().unwrap());
        }
        out
    })
}

// ---------------------------------------------------------------- context

struct Ctx {
    ws: i64,
    we: i64,
    /// click window start
    cws: i64,
    products: KMap,
    unknown_cat: u32,
    cats: Vec<Vec<u8>>,
    campaigns: KMap,
    camp_ids: Vec<Vec<u8>>,
    camp_channels: Vec<Vec<u8>>,
    pe_bits: u32,
    pp_bits: u32,
    /// Events are stored in the narrow form, see `PRec`.
    narrow: bool,
    ts_shift: u32,
    cat_bits: u32,
    /// Base of the ingest codes, epoch seconds, see `DRec`.
    ibase: i64,
    out_dir: PathBuf,
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name).ok().and_then(|v| v.trim().parse().ok())
}

/// Rows of a small two-column CSV file, dequoted, malformed lines dropped.
fn small_csv(path: &Path) -> Vec<(Vec<u8>, Vec<u8>)> {
    let buf = std::fs::read(path).unwrap_or_default();
    let (s, e) = chunk_bounds(&buf, 0, buf.len());
    let b = &buf[s..e];
    let mut sc = Scanner::new(b);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 2];
    let mut out = Vec::new();
    while let Some(l) = sc.next(&mut pos) {
        if fields(b, &l, &pos, &mut f) {
            out.push((b[f[0].0..f[0].1].to_vec(), b[f[1].0..f[1].1].to_vec()));
        }
    }
    out
}

/// products.csv: the product -> category map, the categories numbered in
/// byte-wise order (`unknown` is one of them), and the number of `unknown`.
fn load_products(path: &Path) -> (KMap, Vec<Vec<u8>>, u32) {
    let buf = std::fs::read(path).unwrap_or_default();
    let (s, e) = chunk_bounds(&buf, 0, buf.len());
    let b = &buf[s..e];
    let mut sc = Scanner::new(b);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 2];
    // Categories in order of first appearance, and each row's product with
    // its category's number in that order.
    let mut seen: HashMap<&[u8], u32> = HashMap::new();
    let mut names: Vec<&[u8]> = Vec::new();
    let mut rows: Vec<(Key, u32)> = Vec::new();
    let mut last: (&[u8], u32) = (&[], u32::MAX);
    while let Some(l) = sc.next(&mut pos) {
        if !fields(b, &l, &pos, &mut f) {
            continue;
        }
        let cat = &b[f[1].0..f[1].1];
        if last.1 == u32::MAX || last.0 != cat {
            let next = names.len() as u32;
            let id = *seen.entry(cat).or_insert(next);
            if id == next {
                names.push(cat);
            }
            last = (cat, id);
        }
        if f[0].0 != f[0].1 {
            rows.push((make_key(b, f[0].0, f[0].1), last.1));
        }
    }
    let mut cats: Vec<Vec<u8>> = names.iter().map(|c| c.to_vec()).collect();
    cats.push(b"unknown".to_vec());
    cats.sort();
    cats.dedup();
    let number = |c: &[u8]| cats.binary_search_by(|x| x.as_slice().cmp(c)).unwrap() as u32;
    let remap: Vec<u32> = names.iter().map(|c| number(c)).collect();
    let mut products = KMap::new(rows.len());
    for &(k, c) in &rows {
        // The first row of a product wins; the file has one row each.
        products.get_or_insert(k, remap[c as usize] as u64);
    }
    let unknown = number(b"unknown");
    (products, cats, unknown)
}

fn manifest_ts(text: &[u8], name: &str) -> i64 {
    let pat = format!("\"{}\"", name);
    let find = |h: &[u8], n: &[u8]| h.windows(n.len()).position(|w| w == n);
    let i = find(text, pat.as_bytes()).unwrap_or_else(|| panic!("manifest.json: no {}", name)) + pat.len();
    let rest = &text[i..];
    let a = rest.iter().position(|&c| c == b'"').expect("manifest.json: value") + 1;
    let b = a + rest[a..].iter().position(|&c| c == b'"').expect("manifest.json: value");
    parse_ts(&rest[a..b], &mut DateCache::new()).unwrap_or_else(|| panic!("manifest.json: bad {}", name))
}

// ---------------------------------------------------------------- parsing

fn parse_links(buf: &[u8], out: &mut Vec<(Key, Key)>) {
    let mut sc = Scanner::new(buf);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 2];
    while let Some(l) = sc.next(&mut pos) {
        if !fields(buf, &l, &pos, &mut f) {
            continue;
        }
        if f[0].0 == f[0].1 || f[1].0 == f[1].1 {
            continue;
        }
        out.push((make_key(buf, f[0].0, f[0].1), make_key(buf, f[1].0, f[1].1)));
    }
}

/// One thread's event output: dedup records scattered by event_id, valid
/// events scattered by person. A valid event needs the link map to find its
/// person; while the union-find is still running such events wait in
/// `backlog`, afterwards they pass through a small ring while the link-map
/// slot of their user is fetched from memory.
struct EvOut {
    t: usize,
    d: Buckets<DRec>,
    p: Buckets<PRec>,
    ring: [ERec; RING],
    n: usize,
    backlog: Vec<ERec>,
    over: Over,
    side: Side,
}

const RING: usize = 16;

impl EvOut {
    fn new(cx: &Ctx, t: usize) -> EvOut {
        assert!(t < 1 << 11);
        EvOut {
            t,
            d: Buckets::new(1 << cx.pe_bits, DCAP),
            p: Buckets::new(1 << cx.pp_bits, PCAP),
            ring: [ERec { ek: 0, uk: 0, w: 0, ing: 0 }; RING],
            n: 0,
            backlog: Vec::new(),
            over: Vec::new(),
            side: Vec::new(),
        }
    }

    /// Leave the dedup record of a row: `ptr` is its `PRec`, null for a row
    /// that failed validation.
    #[inline(always)]
    fn dedup_rec(&mut self, cx: &Ctx, ek: Key, ing: i64, ptr: *mut PRec) {
        let code = ing.wrapping_sub(cx.ibase) as u64;
        let addr = ptr as usize as u64;
        let x = if code < ING_ESC && addr >> (PTR_BITS + 4) == 0 {
            (code << PTR_BITS) | (addr >> 4)
        } else {
            self.escape(ing, ptr)
        };
        self.d.push(part(hash(ek), cx.pe_bits), DRec { ek, x });
    }

    #[cold]
    #[inline(never)]
    fn escape(&mut self, ing: i64, ptr: *mut PRec) -> u64 {
        let i = self.over.len() as u64;
        assert!(i < 1 << 32);
        self.over.push((ing, ptr as usize));
        (ING_ESC << PTR_BITS) | ((self.t as u64) << 32) | i
    }

    #[inline(always)]
    fn resolve(&mut self, cx: &Ctx, links: &BMap, r: ERec) {
        let person = links.get_or(r.uk, r.uk);
        let ptr = self.p.push_ptr(part(hash(person), cx.pp_bits), PRec { person, w: r.w });
        self.dedup_rec(cx, r.ek, r.ing, ptr);
    }

    /// Resolve everything that is waiting.
    fn flush(&mut self, cx: &Ctx, links: &BMap) {
        for i in 0..self.n.min(RING) {
            let r = self.ring[i];
            self.resolve(cx, links, r);
        }
        self.n = 0;
        let backlog = std::mem::take(&mut self.backlog);
        for i in 0..backlog.len() {
            if i + 12 < backlog.len() {
                prefetch(links.bucket_ptr(backlog[i + 12].uk));
            }
            self.resolve(cx, links, backlog[i]);
        }
    }
}

fn parse_events(buf: &[u8], cx: &Ctx, links: Option<&BMap>, out: &mut EvOut) {
    if let Some(l) = links {
        if !out.backlog.is_empty() {
            out.flush(cx, l);
        }
    }
    let mut sc = Scanner::new(buf);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 7];
    let mut dc = DateCache::new();
    while let Some(l) = sc.next(&mut pos) {
        if !fields(buf, &l, &pos, &mut f) {
            continue;
        }
        if f[0].0 == f[0].1 {
            continue;
        }
        let ek = make_key(buf, f[0].0, f[0].1);
        let ib = &buf[f[3].0..f[3].1];
        let ing = if ib.len() == 20 && ib[19] == b'Z' { parse_dt_c(ib, &mut dc) } else { None };
        // (user, w) of a row that passes validation
        let mut valid: Option<(Key, u64)> = None;
        'v: {
            let Some(ing) = ing else { break 'v };
            let (us, ue) = f[1];
            let (ps, pe) = f[5];
            if us == ue || ps == pe {
                break 'v;
            }
            let Some(ts) = parse_ts(&buf[f[2].0..f[2].1], &mut dc) else { break 'v };
            if ts < cx.ws || ts >= cx.we {
                break 'v;
            }
            if ing * 1000 - ts > DAY_MS {
                break 'v;
            }
            let purchase = match &buf[f[4].0..f[4].1] {
                b"view" | b"cart" => false,
                b"purchase" => true,
                _ => break 'v,
            };
            let (mut price, mut cat) = (0u32, 0u32);
            if purchase {
                let Some(p) = parse_digits(&buf[f[6].0..f[6].1], 8) else { break 'v };
                if p < 1 || p > 10_000_000 {
                    break 'v;
                }
                price = p as u32;
                cat = match cx.products.get(make_key(buf, ps, pe)) {
                    Some(c) => c as u32,
                    None => cx.unknown_cat,
                };
            }
            let w = if cx.narrow {
                (((ts - cx.ws) as u64) << cx.ts_shift) | ((price as u64) << cx.cat_bits) | cat as u64
            } else {
                out.side.push((ts, price, cat));
                ((out.t as u64) << SIDE_BITS) | (out.side.len() as u64 - 1)
            };
            valid = Some((make_key(buf, us, ue), w));
        }
        let Some((uk, w)) = valid else {
            // Not a surviving event, but it still takes part in the dedup.
            out.dedup_rec(cx, ek, ing.unwrap_or(i64::MAX), std::ptr::null_mut());
            continue;
        };
        // A valid row has a valid ingest_ts.
        let rec = ERec { ek, uk, w, ing: ing.unwrap_or(i64::MAX) };
        if let Some(links) = links {
            prefetch(links.bucket_ptr(uk));
            let slot = out.n % RING;
            if out.n >= RING {
                let r = out.ring[slot];
                out.resolve(cx, links, r);
            }
            out.ring[slot] = rec;
            out.n += 1;
        } else {
            out.backlog.push(rec);
        }
    }
}

fn parse_clicks(buf: &[u8], cx: &Ctx, links: &BMap, out: &mut Buckets<CRec>) {
    let mut sc = Scanner::new(buf);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 4];
    let mut dc = DateCache::new();
    // Valid clicks wait in a small ring while the link-map slot of their
    // user is fetched from memory.
    let mut ring = [CRec { person: 0, ck: 0, ts: 0, camp: 0 }; RING];
    let mut n = 0usize;
    let mut resolve = |r: CRec| {
        let person = links.get_or(r.person, r.person);
        out.push(part(hash(person), cx.pp_bits), CRec { person, ..r });
    };
    while let Some(l) = sc.next(&mut pos) {
        if !fields(buf, &l, &pos, &mut f) {
            continue;
        }
        if f[0].0 == f[0].1 || f[1].0 == f[1].1 || f[2].0 == f[2].1 {
            continue;
        }
        let Some(ts) = parse_ts(&buf[f[3].0..f[3].1], &mut dc) else { continue };
        if ts < cx.cws || ts >= cx.we {
            continue;
        }
        let Some(camp) = cx.campaigns.get(make_key(buf, f[2].0, f[2].1)) else { continue };
        let uk = make_key(buf, f[1].0, f[1].1);
        let ck = make_key(buf, f[0].0, f[0].1);
        prefetch(links.bucket_ptr(uk));
        let slot = n % RING;
        if n >= RING {
            resolve(ring[slot]);
        }
        // `person` holds the user ID until the click is resolved.
        ring[slot] = CRec { person: uk, ck, ts, camp: camp as u32 };
        n += 1;
    }
    for i in 0..n.min(RING) {
        resolve(ring[i]);
    }
}

// ---------------------------------------------------------------- links

/// Union-find over all linked IDs. The result maps every linked ID to its
/// person's name: the byte-wise smallest ID of the component.
fn build_links(lists: Vec<Vec<(Key, Key)>>) -> BMap {
    let lines: usize = lists.iter().map(|l| l.len()).sum();
    // IDs are numbered in 32 bits.
    assert!(lines < 1 << 31, "too many link lines");
    let mut map = BMap::new(2 * lines);
    let mut parent: Vec<u32> = Vec::with_capacity(2 * lines);
    let mut size: Vec<u32> = Vec::with_capacity(2 * lines);
    // best[root]: the smallest ID of the root's component
    let mut best: Vec<Key> = Vec::with_capacity(2 * lines);
    // the IDs in order of their numbers
    let mut ids: Vec<Key> = Vec::with_capacity(2 * lines);
    fn find(parent: &mut [u32], mut x: u32) -> u32 {
        while parent[x as usize] != x {
            let g = parent[parent[x as usize] as usize];
            parent[x as usize] = g;
            x = g;
        }
        x
    }
    const AHEAD: usize = 12;
    for l in &lists {
        for (i, &(a, b)) in l.iter().enumerate() {
            if let Some(&(pa, pb)) = l.get(i + AHEAD) {
                prefetch(map.bucket_ptr(pa));
                prefetch(map.bucket_ptr(pb));
            }
            let mut id = |k: Key| -> u32 {
                let next = best.len() as u64;
                let v = map.get_or_insert(k, next);
                if v == next {
                    best.push(k);
                    parent.push(next as u32);
                    size.push(1);
                    ids.push(k);
                }
                v as u32
            };
            let ia = id(a);
            let ib = id(b);
            if ia == ib {
                continue;
            }
            let (mut ra, mut rb) = (find(&mut parent, ia), find(&mut parent, ib));
            if ra == rb {
                continue;
            }
            if size[ra as usize] < size[rb as usize] {
                std::mem::swap(&mut ra, &mut rb);
            }
            parent[rb as usize] = ra;
            size[ra as usize] += size[rb as usize];
            if key_cmp(best[rb as usize], best[ra as usize]) == Ordering::Less {
                best[ra as usize] = best[rb as usize];
            }
        }
    }
    // The result holds only the IDs whose person has another name: an ID
    // that is not found is its own person anyway, and a smaller table means
    // fewer cache and TLB misses for the lookups of every event and click.
    let n = ids.len();
    let mut names: Vec<Key> = Vec::with_capacity(n);
    let mut renamed = 0usize;
    for i in 0..n {
        let name = best[find(&mut parent, i as u32) as usize];
        renamed += (name != ids[i]) as usize;
        names.push(name);
    }
    let mut out = BMap::new(renamed);
    for i in 0..n {
        if i + AHEAD < n {
            prefetch(out.bucket_ptr(ids[i + AHEAD]));
        }
        if names[i] != ids[i] {
            out.get_or_insert(ids[i], names[i]);
        }
    }
    let (ptr, len) = map.region();
    release(ptr, len);
    out
}

// ---------------------------------------------------------------- dedup

/// Exact (ingest_ts, PRec) of a dedup record.
#[inline(always)]
fn d_exact(x: u64, cx: &Ctx, overs: &[Over]) -> (i64, *mut PRec) {
    let code = x >> PTR_BITS;
    if code != ING_ESC {
        (cx.ibase + code as i64, ((x & PTR_MASK) << 4) as usize as *mut PRec)
    } else {
        let (ing, addr) = overs[((x >> 32) & 0x7FF) as usize][(x & 0xFFFF_FFFF) as usize];
        (ing, addr as *mut PRec)
    }
}

/// Dedup one event partition on event_id: the copy with the smallest
/// ingest_ts wins (before validation), every other copy that is a valid event
/// is struck out where it sits in its person partition.
fn dedup_partition(chunks: &[(*mut DRec, usize)], tbl: &mut Vec<u64>, cx: &Ctx, overs: &[Over]) {
    if chunks.is_empty() {
        return;
    }
    // Slot: tag (32 hash bits) << 32 | record number + 1. Records are numbered
    // chunk * DCAP + index; a tag match is confirmed on the full key.
    let nslots = (chunks.len() * DCAP * 2).next_power_of_two();
    tbl.clear();
    tbl.resize(nslots, 0);
    let mask = nslots - 1;
    unsafe {
        for (ci, &(ptr, len)) in chunks.iter().enumerate() {
            for i in 0..len {
                let r = ptr.add(i);
                let ek = (*r).ek;
                let h = hash(ek);
                let tag = (h >> 20) & 0xFFFF_FFFF;
                let me = (tag << 32) | ((ci * DCAP + i) as u64 + 1);
                let mut s = h as usize & mask;
                loop {
                    let v = *tbl.get_unchecked(s);
                    if v == 0 {
                        *tbl.get_unchecked_mut(s) = me;
                        break;
                    }
                    if v >> 32 == tag {
                        let og = (v & 0xFFFF_FFFF) as usize - 1;
                        let o = chunks.get_unchecked(og / DCAP).0.add(og % DCAP);
                        if (*o).ek == ek {
                            let (rx, ox) = ((*r).x, (*o).x);
                            let (rc, oc) = (rx >> PTR_BITS, ox >> PTR_BITS);
                            let (r_wins, rp, op) = if rc != ING_ESC && oc != ING_ESC {
                                let p = |x: u64| ((x & PTR_MASK) << 4) as usize as *mut PRec;
                                (rc < oc, p(rx), p(ox))
                            } else {
                                let (ri, rp) = d_exact(rx, cx, overs);
                                let (oi, op) = d_exact(ox, cx, overs);
                                (ri < oi, rp, op)
                            };
                            let loser = if r_wins {
                                *tbl.get_unchecked_mut(s) = me;
                                op
                            } else {
                                rp
                            };
                            if !loser.is_null() {
                                (*loser).w = DEAD;
                            }
                            break;
                        }
                    }
                    s = (s + 1) & mask;
                }
            }
        }
    }
}

// ---------------------------------------------------------------- output

static USER_SCHEMA: [ColDef; 6] = [
    ColDef { name: "user_id", ty: Ty::Str },
    ColDef { name: "day", ty: Ty::Date },
    ColDef { name: "sessions", ty: Ty::I32 },
    ColDef { name: "events", ty: Ty::I32 },
    ColDef { name: "revenue_cents", ty: Ty::I64 },
    ColDef { name: "top_category", ty: Ty::OptStr },
];

static CAMP_SCHEMA: [ColDef; 7] = [
    ColDef { name: "campaign_id", ty: Ty::Str },
    ColDef { name: "channel", ty: Ty::Str },
    ColDef { name: "day", ty: Ty::Date },
    ColDef { name: "sessions", ty: Ty::I64 },
    ColDef { name: "purchasing_sessions", ty: Ty::I64 },
    ColDef { name: "revenue_cents", ty: Ty::I64 },
    ColDef { name: "assisted_sessions", ty: Ty::I64 },
];

const ROW_GROUP_ROWS: usize = 100_000;

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s);
}

/// One thread's user_daily rows, flushed to its own Parquet file.
struct UserOut {
    path: PathBuf,
    writer: Option<Writer>,
    ids: Vec<u8>,
    day: Vec<i32>,
    sessions: Vec<i32>,
    events: Vec<i32>,
    revenue: Vec<i64>,
    valid: Vec<bool>,
    cats: Vec<u8>,
}

impl UserOut {
    fn new(path: PathBuf) -> UserOut {
        UserOut {
            path,
            writer: None,
            ids: Vec::new(),
            day: Vec::new(),
            sessions: Vec::new(),
            events: Vec::new(),
            revenue: Vec::new(),
            valid: Vec::new(),
            cats: Vec::new(),
        }
    }

    fn flush(&mut self) {
        if self.day.is_empty() {
            return;
        }
        let w = self.writer.get_or_insert_with(|| Writer::create(&self.path, &USER_SCHEMA));
        w.row_group(
            self.day.len(),
            &[
                Col::Str(&self.ids),
                Col::I32(&self.day),
                Col::I32(&self.sessions),
                Col::I32(&self.events),
                Col::I64(&self.revenue),
                Col::OptStr { valid: &self.valid, plain: &self.cats },
            ],
        );
        self.ids.clear();
        self.day.clear();
        self.sessions.clear();
        self.events.clear();
        self.revenue.clear();
        self.valid.clear();
        self.cats.clear();
    }

    /// Finish the file. With `force`, an empty file is written even if this
    /// thread produced no rows, so the table always has at least one file.
    fn finish(mut self, force: bool) {
        self.flush();
        if force && self.writer.is_none() {
            self.writer = Some(Writer::create(&self.path, &USER_SCHEMA));
        }
        if let Some(w) = self.writer.take() {
            w.finish();
        }
    }
}

/// Per-(campaign, day) counters: sessions, purchasing sessions, revenue,
/// assisted sessions. Dense when the campaign x day grid is small.
struct Agg {
    dense: bool,
    ndays: usize,
    day0: i64,
    cells: Vec<[u64; 4]>,
    map: HashMap<(u32, i32), [u64; 4]>,
}

impl Agg {
    fn new(cx: &Ctx) -> Agg {
        let day0 = cx.ws.div_euclid(DAY_MS);
        let ndays = ((cx.we - 1).div_euclid(DAY_MS) - day0 + 1).max(1) as usize;
        let ncells = (cx.camp_ids.len() + 1).saturating_mul(ndays);
        let dense = ncells <= (1 << 22) && std::env::var_os("SS_SPARSE").is_none();
        Agg { dense, ndays, day0, cells: if dense { vec![[0; 4]; ncells] } else { Vec::new() }, map: HashMap::new() }
    }

    #[inline(always)]
    fn cell(&mut self, camp: u32, day: i32) -> &mut [u64; 4] {
        if self.dense {
            let i = camp as usize * self.ndays + (day as i64 - self.day0) as usize;
            &mut self.cells[i]
        } else {
            self.map.entry((camp, day)).or_insert([0; 4])
        }
    }

    fn merge(&mut self, o: &Agg) {
        if self.dense {
            for (a, b) in self.cells.iter_mut().zip(&o.cells) {
                for k in 0..4 {
                    a[k] += b[k];
                }
            }
        } else {
            for (key, b) in &o.map {
                let a = self.map.entry(*key).or_insert([0; 4]);
                for k in 0..4 {
                    a[k] += b[k];
                }
            }
        }
    }

    fn rows(&self) -> Vec<(u32, i32, [u64; 4])> {
        let mut out = Vec::new();
        if self.dense {
            for (i, c) in self.cells.iter().enumerate() {
                if c[0] > 0 || c[3] > 0 {
                    out.push(((i / self.ndays) as u32, (self.day0 + (i % self.ndays) as i64) as i32, *c));
                }
            }
        } else {
            for (&(camp, day), c) in &self.map {
                if c[0] > 0 || c[3] > 0 {
                    out.push((camp, day, *c));
                }
            }
        }
        out
    }
}

// ---------------------------------------------------------------- sessions

#[inline(always)]
fn pack_ev(ts: i64, price: u32, cat: u32) -> u128 {
    (((ts as u64 ^ (1 << 63)) as u128) << 64) | ((price as u128) << 32) | cat as u128
}

/// An event as the sessionizer sorts it: ordered by `ts`.
trait Ev: Copy + Ord {
    fn ts(self, cx: &Ctx) -> i64;
    /// (price, category) of a purchase; price 0 for a view or a cart.
    fn buy(self, cx: &Ctx) -> (u32, u32);
}

/// Wide form, good for anything: ts, price and category side by side.
impl Ev for u128 {
    #[inline(always)]
    fn ts(self, _cx: &Ctx) -> i64 {
        ((self >> 64) as u64 ^ (1 << 63)) as i64
    }
    #[inline(always)]
    fn buy(self, _cx: &Ctx) -> (u32, u32) {
        ((self >> 32) as u32, self as u32)
    }
}

/// Narrow form: the `w` of a `PRec` as it is.
impl Ev for u64 {
    #[inline(always)]
    fn ts(self, cx: &Ctx) -> i64 {
        cx.ws + (self >> cx.ts_shift) as i64
    }
    #[inline(always)]
    fn buy(self, cx: &Ctx) -> (u32, u32) {
        (((self >> cx.cat_bits) & PRICE_MASK) as u32, (self & ((1 << cx.cat_bits) - 1)) as u32)
    }
}

/// Per-thread state of the sessionize stage.
struct Sess {
    tbl: Vec<u32>,
    persons: Vec<Key>,
    eoff: Vec<u32>,
    coff: Vec<u32>,
    eids: Vec<u32>,
    cids: Vec<u32>,
    evs: Vec<u128>,
    evs64: Vec<u64>,
    cls: Vec<Clk>,
    echunks: Vec<(*mut PRec, usize)>,
    cchunks: Vec<(*mut CRec, usize)>,
    /// the person being processed and its name: in `name` if the key is an
    /// interned one, else in the first `nlen` bytes of `nbuf`
    person: Key,
    name: Vec<u8>,
    nbuf: [u8; 16],
    nlen: usize,
    catsum: Vec<u64>,
    touched: Vec<u32>,
    ccount: Vec<u32>,
    /// For a campaign with clicks in the window: how many of the day's
    /// sessions came before the first one it assists in its current run.
    astart: Vec<u32>,
    inlist: Vec<bool>,
    active: Vec<u32>,
    organic: u32,
    agg: Agg,
    out: UserOut,
}

impl Sess {
    fn new(cx: &Ctx, t: usize) -> Sess {
        let ncamp = cx.camp_ids.len();
        Sess {
            tbl: Vec::new(),
            persons: Vec::new(),
            eoff: Vec::new(),
            coff: Vec::new(),
            eids: Vec::new(),
            cids: Vec::new(),
            evs: Vec::new(),
            evs64: Vec::new(),
            cls: Vec::new(),
            echunks: Vec::new(),
            cchunks: Vec::new(),
            person: 0,
            name: Vec::new(),
            nbuf: [0; 16],
            nlen: 0,
            catsum: vec![0; cx.cats.len()],
            touched: Vec::new(),
            ccount: vec![0; ncamp],
            astart: vec![0; ncamp],
            inlist: vec![false; ncamp],
            active: Vec::new(),
            organic: ncamp as u32,
            agg: Agg::new(cx),
            out: UserOut::new(cx.out_dir.join("user_daily").join(format!("part-{:03}.parquet", t))),
        }
    }

    /// Group one person partition by person, then process each person.
    fn partition(&mut self, cx: &Ctx, ebs: &[Buckets<PRec>], cbs: &[Buckets<CRec>], sides: &[Side], p: usize) {
        all_chunks(ebs, p, &mut self.echunks);
        // Upper bound: it still counts the events the dedup struck out.
        let total: usize = self.echunks.iter().map(|c| c.1).sum();
        if total == 0 {
            return;
        }
        all_chunks(cbs, p, &mut self.cchunks);
        let nslots = (2 * total).next_power_of_two().max(16);
        let mask = nslots - 1;
        self.tbl.clear();
        self.tbl.resize(nslots, 0);
        self.persons.clear();
        self.eoff.clear();
        self.eids.clear();
        self.cids.clear();
        unsafe {
            // Pass 1: number the persons, count their events.
            let mut n = 0usize;
            for &(ptr, len) in &self.echunks {
                for i in 0..len {
                    if (*ptr.add(i)).w == DEAD {
                        self.eids.push(u32::MAX);
                        continue;
                    }
                    n += 1;
                    let person = (*ptr.add(i)).person;
                    let mut s = hash(person) as usize & mask;
                    let id = loop {
                        let v = *self.tbl.get_unchecked(s);
                        if v == 0 {
                            let id = self.persons.len() as u32;
                            self.persons.push(person);
                            self.eoff.push(0);
                            *self.tbl.get_unchecked_mut(s) = id + 1;
                            break id;
                        }
                        if *self.persons.get_unchecked(v as usize - 1) == person {
                            break v - 1;
                        }
                        s = (s + 1) & mask;
                    };
                    *self.eoff.get_unchecked_mut(id as usize) += 1;
                    self.eids.push(id);
                }
            }
            let np = self.persons.len();
            // Counts to start offsets.
            let mut acc = 0u32;
            for c in self.eoff.iter_mut() {
                let k = *c;
                *c = acc;
                acc += k;
            }
            self.eoff.push(acc);
            // Pass 2: scatter the events to their person's run.
            let narrow = cx.narrow;
            self.evs.clear();
            self.evs64.clear();
            if narrow {
                self.evs64.resize(n, 0);
            } else {
                self.evs.resize(n, 0);
            }
            let mut j = 0;
            for &(ptr, len) in &self.echunks {
                for i in 0..len {
                    let r = *ptr.add(i);
                    let id = *self.eids.get_unchecked(j) as usize;
                    j += 1;
                    if id == u32::MAX as usize {
                        continue;
                    }
                    let o = self.eoff.get_unchecked_mut(id);
                    if narrow {
                        *self.evs64.get_unchecked_mut(*o as usize) = r.w;
                    } else {
                        let (ts, price, cat) = sides[(r.w >> SIDE_BITS) as usize][(r.w & ((1 << SIDE_BITS) - 1)) as usize];
                        *self.evs.get_unchecked_mut(*o as usize) = pack_ev(ts, price, cat);
                    }
                    *o += 1;
                }
            }
            // eoff[id] is now the end of run id, i.e. the start of run id + 1.
            // Clicks of persons with events, grouped the same way.
            self.coff.clear();
            self.coff.resize(np + 1, 0);
            let mut nc = 0u32;
            for &(ptr, len) in &self.cchunks {
                for i in 0..len {
                    let person = (*ptr.add(i)).person;
                    let mut s = hash(person) as usize & mask;
                    let id = loop {
                        let v = *self.tbl.get_unchecked(s);
                        if v == 0 {
                            break u32::MAX;
                        }
                        if *self.persons.get_unchecked(v as usize - 1) == person {
                            break v - 1;
                        }
                        s = (s + 1) & mask;
                    };
                    if id != u32::MAX {
                        *self.coff.get_unchecked_mut(id as usize) += 1;
                        nc += 1;
                    }
                    self.cids.push(id);
                }
            }
            let mut acc = 0u32;
            for c in self.coff.iter_mut() {
                let k = *c;
                *c = acc;
                acc += k;
            }
            self.cls.clear();
            self.cls.resize(nc as usize, Clk { ck: 0, ts: 0, camp: 0 });
            let mut j = 0;
            for &(ptr, len) in &self.cchunks {
                for i in 0..len {
                    let id = *self.cids.get_unchecked(j);
                    j += 1;
                    if id != u32::MAX {
                        let r = *ptr.add(i);
                        let o = self.coff.get_unchecked_mut(id as usize);
                        *self.cls.get_unchecked_mut(*o as usize) = Clk { ck: r.ck, ts: r.ts, camp: r.camp };
                        *o += 1;
                    }
                }
            }
            // Both offset arrays now hold run ends.
            let mut evs = std::mem::take(&mut self.evs);
            let mut evs64 = std::mem::take(&mut self.evs64);
            let mut cls = std::mem::take(&mut self.cls);
            let (mut e0, mut c0) = (0usize, 0usize);
            for id in 0..np {
                let e1 = self.eoff[id] as usize;
                let c1 = self.coff[id] as usize;
                let person = self.persons[id];
                if narrow {
                    self.person(cx, person, &mut evs64[e0..e1], &mut cls[c0..c1]);
                } else {
                    self.person(cx, person, &mut evs[e0..e1], &mut cls[c0..c1]);
                }
                e0 = e1;
                c0 = c1;
            }
            self.evs = evs;
            self.evs64 = evs64;
            self.cls = cls;
        }
        if self.out.day.len() >= ROW_GROUP_ROWS {
            self.out.flush();
        }
    }

    /// Sessionize one person's events, credit and assist each session, and
    /// emit the person's user_daily rows.
    fn person<E: Ev>(&mut self, cx: &Ctx, person: Key, evs: &mut [E], cls: &mut [Clk]) {
        if evs.len() > 1 {
            evs.sort_unstable();
        }
        if cls.len() > 1 {
            // By time only; the smallest click_id of a tie is picked below.
            cls.sort_unstable_by_key(|c| c.ts);
        }
        self.person = person;
        if is_long(person) {
            self.name.clear();
            key_bytes(person, &mut self.name);
        } else {
            self.nlen = compact_bytes(person, &mut self.nbuf);
        }

        let n = evs.len();
        let nc = cls.len();
        let mut i = 0;
        // user_daily row being built
        let mut row_day = i32::MIN;
        let (mut r_sessions, mut r_events, mut r_revenue) = (0u32, 0u32, 0u64);
        // click window [lo, hi): clicks with start - 7d <= ts <= start;
        // (grp_ck, grp_camp): the smallest click_id, and its campaign, of the
        // latest timestamp group below hi
        let (mut lo, mut hi) = (0usize, 0usize);
        let (mut grp_ck, mut grp_camp): (Key, u32) = (0, 0);
        while i < n {
            let start = evs[i].ts(cx);
            let day = start.div_euclid(DAY_MS) as i32;
            if day != row_day {
                if row_day != i32::MIN {
                    self.emit_row(cx, row_day, r_sessions, r_events, r_revenue);
                    self.flush_assists(row_day, r_sessions);
                }
                row_day = day;
                r_sessions = 0;
                r_events = 0;
                r_revenue = 0;
            }
            let mut prev = start;
            let mut count = 0u32;
            let mut revenue = 0u64;
            while i < n {
                let v = evs[i];
                let t = v.ts(cx);
                if t - prev > GAP_MS {
                    break;
                }
                prev = t;
                count += 1;
                let (price, cat) = v.buy(cx);
                if price != 0 {
                    let cat = cat as usize;
                    revenue += price as u64;
                    if self.catsum[cat] == 0 {
                        self.touched.push(cat as u32);
                    }
                    self.catsum[cat] += price as u64;
                }
                i += 1;
            }
            r_sessions += 1;
            r_events += count;
            r_revenue += revenue;

            let mut camp = self.organic;
            if nc != 0 {
                while hi < nc && cls[hi].ts <= start {
                    if hi == 0 || cls[hi].ts != cls[hi - 1].ts || key_cmp(cls[hi].ck, grp_ck) == Ordering::Less {
                        grp_ck = cls[hi].ck;
                        grp_camp = cls[hi].camp;
                    }
                    let c = cls[hi].camp as usize;
                    self.ccount[c] += 1;
                    if self.ccount[c] == 1 {
                        // The campaign starts assisting with this session.
                        self.astart[c] = r_sessions - 1;
                        if !self.inlist[c] {
                            self.inlist[c] = true;
                            self.active.push(c as u32);
                        }
                    }
                    hi += 1;
                }
                let limit = start - WEEK_MS;
                while lo < hi && cls[lo].ts < limit {
                    let c = cls[lo].camp as usize;
                    self.ccount[c] -= 1;
                    if self.ccount[c] == 0 {
                        // It assisted the day's sessions before this one,
                        // from the one it started with.
                        let k = r_sessions - 1 - self.astart[c];
                        if k > 0 {
                            self.agg.cell(c as u32, day)[3] += k as u64;
                        }
                    }
                    lo += 1;
                }
                if hi > lo {
                    camp = grp_camp;
                }
            }
            let cell = self.agg.cell(camp, day);
            cell[0] += 1;
            cell[1] += (revenue > 0) as u64;
            cell[2] += revenue;
        }
        if row_day != i32::MIN {
            self.emit_row(cx, row_day, r_sessions, r_events, r_revenue);
            self.flush_assists(row_day, r_sessions);
        }
        for c in self.active.drain(..) {
            self.ccount[c as usize] = 0;
            self.inlist[c as usize] = false;
        }
    }

    /// A day of the person is over after `sessions` sessions: book the
    /// sessions each still active campaign assisted, and start them afresh
    /// for the next day. An assisted session is not booked one at a time: a
    /// campaign's clicks cover a run of consecutive sessions, booked when the
    /// run or the day ends.
    fn flush_assists(&mut self, day: i32, sessions: u32) {
        let mut j = 0;
        while j < self.active.len() {
            let c = self.active[j] as usize;
            if self.ccount[c] == 0 {
                self.inlist[c] = false;
                self.active.swap_remove(j);
            } else {
                let k = sessions - self.astart[c];
                if k > 0 {
                    self.agg.cell(c as u32, day)[3] += k as u64;
                }
                self.astart[c] = 0;
                j += 1;
            }
        }
    }

    fn emit_row(&mut self, cx: &Ctx, day: i32, sessions: u32, events: u32, revenue: u64) {
        let o = &mut self.out;
        if is_long(self.person) {
            put_str(&mut o.ids, &self.name);
        } else {
            // A short name: copy all 16 bytes of its buffer at a fixed size
            // and keep the first `len` (no variable-length memcpy).
            let len = self.nlen;
            let at = o.ids.len();
            o.ids.reserve(20);
            // SAFETY: 20 bytes are reserved past `at`; 4 + len <= 19 of them
            // become part of the vector, all written here.
            unsafe {
                let p = o.ids.as_mut_ptr().add(at);
                std::ptr::copy_nonoverlapping((len as u32).to_le_bytes().as_ptr(), p, 4);
                std::ptr::copy_nonoverlapping(self.nbuf.as_ptr(), p.add(4), 16);
                o.ids.set_len(at + 4 + len);
            }
        }
        o.day.push(day);
        o.sessions.push(sessions as i32);
        o.events.push(events as i32);
        o.revenue.push(revenue as i64);
        if self.touched.is_empty() {
            o.valid.push(false);
        } else {
            // Categories are numbered in byte-wise name order, so the
            // smallest index breaks a tie.
            let mut best = u32::MAX;
            let mut best_sum = 0u64;
            for &c in &self.touched {
                let s = self.catsum[c as usize];
                if s > best_sum || (s == best_sum && c < best) {
                    best = c;
                    best_sum = s;
                }
                self.catsum[c as usize] = 0;
            }
            self.touched.clear();
            o.valid.push(true);
            put_str(&mut o.cats, &cx.cats[best as usize]);
        }
    }
}

unsafe impl Send for Sess {}

// ---------------------------------------------------------------- main

fn main() {
    let t0 = Instant::now();
    let timing = std::env::var_os("SS_TIME").is_some();
    let lap = |name: &str| {
        if timing {
            eprintln!("{:>8.1} ms  {}", t0.elapsed().as_secs_f64() * 1e3, name);
        }
    };
    let dir = |name: &str, default: &str| PathBuf::from(std::env::var_os(name).unwrap_or_else(|| default.into()));
    let data = dir("DATA_DIR", "/data");
    let out_dir = dir("OUTPUT_DIR", "/output");
    let ncpu = env_usize("NCPU")
        .filter(|&n| n > 0)
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(8, |n| n.get()));

    std::fs::create_dir_all(out_dir.join("user_daily")).expect("create user_daily");
    std::fs::create_dir_all(out_dir.join("campaign_daily")).expect("create campaign_daily");

    let manifest = std::fs::read(data.join("manifest.json")).expect("read manifest.json");
    let ws = manifest_ts(&manifest, "window_start");
    let we = manifest_ts(&manifest, "window_end");

    // The event files are mapped on a second thread while this one reads
    // the small tables and maps the rest.
    let (efiles, (products, cats, unknown_cat), cfiles, lfiles) = std::thread::scope(|s| {
        let ev = s.spawn(|| map_dir(&data.join("events")));
        let prod = load_products(&data.join("products.csv"));
        let cfiles = map_dir(&data.join("clicks"));
        let lfiles = map_dir(&data.join("links"));
        (ev.join().unwrap(), prod, cfiles, lfiles)
    });

    let crows = small_csv(&data.join("campaigns.csv"));
    let mut campaigns = KMap::new(crows.len());
    let mut camp_ids = Vec::new();
    let mut camp_channels = Vec::new();
    for (id, ch) in &crows {
        if id.is_empty() {
            continue;
        }
        let next = camp_ids.len() as u64;
        if campaigns.get_or_insert(make_key(id, 0, id.len()), next) == next {
            camp_ids.push(id.clone());
            camp_channels.push(ch.clone());
        }
    }

    let ebytes: usize = efiles.iter().map(|f| f.len).sum();
    let cbytes: usize = cfiles.iter().map(|f| f.len).sum();
    let lbytes: usize = lfiles.iter().map(|f| f.len).sum();

    let chunk = env_usize("SS_CHUNK").unwrap_or(4 << 20).max(1);
    let nt = if std::env::var_os("SS_NOCAP").is_some() {
        ncpu
    } else {
        ncpu.min(((ebytes + cbytes + lbytes) / (256 << 10)).max(1))
    };
    let est_rows = ebytes / 70;
    let bits_for = |per_part: usize, max_bits: u32| -> u32 {
        let want = (est_rows / per_part).max(1).next_power_of_two().trailing_zeros();
        want.min(max_bits)
    };
    let pe_bits = env_usize("SS_PE_BITS").map_or(bits_for(24_000, 11), |b| b as u32);
    let pp_bits = env_usize("SS_PP_BITS").map_or(bits_for(32_000, 11), |b| b as u32);

    // Bits for a category number and for `ts - window_start` (see `PRec`).
    let cat_bits = (usize::BITS - (cats.len().max(2) - 1).leading_zeros()).max(1);
    let ts_bits = match we.checked_sub(ws) {
        Some(d) if d >= 0 => 64 - (d as u64).leading_zeros(),
        _ => 64,
    };
    let cx = Ctx {
        ws,
        we,
        cws: ws - WEEK_MS,
        products,
        unknown_cat,
        cats,
        campaigns,
        camp_ids,
        camp_channels,
        pe_bits,
        pp_bits,
        narrow: ts_bits + PRICE_BITS + cat_bits <= 64 && std::env::var_os("SS_WIDE").is_none(),
        ts_shift: PRICE_BITS + cat_bits,
        cat_bits,
        // SS_IBASE (testing) moves the base by that many seconds, so that
        // some or all rows take the overflow path.
        ibase: ws
            .div_euclid(1000)
            .saturating_sub(86_400)
            .saturating_add(std::env::var("SS_IBASE").ok().and_then(|v| v.trim().parse::<i64>().ok()).unwrap_or(0)),
        out_dir,
    };
    let cx = &cx;
    lap("setup");

    // ---- links: parse in parallel
    let lchunks = make_chunks(&lfiles, chunk);
    let next = AtomicUsize::new(0);
    let link_lists: Vec<Vec<(Key, Key)>> = par_map(nt, |_| {
        let mut out = Vec::new();
        loop {
            let i = next.fetch_add(1, Relaxed);
            if i >= lchunks.len() {
                break;
            }
            let (fi, rs, re) = lchunks[i];
            let buf = lfiles[fi].bytes();
            let (s, e) = chunk_bounds(buf, rs, re);
            parse_links(&buf[s..e], &mut out);
        }
        out
    });
    lap("links parsed");

    // ---- events: parse, scatter the dedup records by event_id and the valid
    // events by person, while one more thread runs the union-find
    let echunks = make_chunks(&efiles, chunk);
    let next = AtomicUsize::new(0);
    let link_cell: OnceLock<BMap> = OnceLock::new();
    let link_cell = &link_cell;
    let eouts: Vec<EvOut> = std::thread::scope(|s| {
        s.spawn(move || {
            let _ = link_cell.set(build_links(link_lists));
            if timing {
                eprintln!("{:>8.1} ms  (links joined)", t0.elapsed().as_secs_f64() * 1e3);
            }
        });
        par_map(nt, |t| {
            let mut out = EvOut::new(cx, t);
            loop {
                let i = next.fetch_add(1, Relaxed);
                if i >= echunks.len() {
                    break;
                }
                let (fi, rs, re) = echunks[i];
                let buf = efiles[fi].bytes();
                let (s, e) = chunk_bounds(buf, rs, re);
                parse_events(&buf[s..e], cx, link_cell.get(), &mut out);
            }
            let links = loop {
                match link_cell.get() {
                    Some(l) => break l,
                    None => std::thread::yield_now(),
                }
            };
            out.flush(cx, links);
            out
        })
    });
    let links = link_cell.get().unwrap();
    // The event files are done with; the threads of the next stage let go of
    // them. Each stage does this for what the stage before it read last.
    let mut garbage = Garbage::new();
    garbage.add_files(&efiles);
    let garbage = &garbage;
    let mut dbuckets = Vec::with_capacity(eouts.len());
    let mut pbuckets = Vec::with_capacity(eouts.len());
    let mut overs: Vec<Over> = Vec::with_capacity(eouts.len());
    let mut sides: Vec<Side> = Vec::with_capacity(eouts.len());
    for o in eouts {
        dbuckets.push(o.d);
        pbuckets.push(o.p);
        overs.push(o.over);
        sides.push(o.side);
    }
    let (overs, sides) = (&overs, &sides);
    lap("events parsed, links joined");

    // ---- clicks: parse, validate, resolve the person, scatter by person
    let cchunks = make_chunks(&cfiles, chunk);
    let next = AtomicUsize::new(0);
    let cbuckets: Vec<Buckets<CRec>> = par_map(nt, |_| {
        let mut out = Buckets::new(1 << cx.pp_bits, CCAP);
        loop {
            let i = next.fetch_add(1, Relaxed);
            if i >= cchunks.len() {
                break;
            }
            let (fi, rs, re) = cchunks[i];
            let buf = cfiles[fi].bytes();
            let (s, e) = chunk_bounds(buf, rs, re);
            parse_clicks(&buf[s..e], cx, links, &mut out);
        }
        garbage.drain();
        out
    });
    lap("clicks parsed");

    // ---- events: dedup per event_id partition
    let mut garbage = Garbage::new();
    garbage.add_files(&cfiles);
    garbage.add_files(&lfiles);
    let (ptr, len) = links.region();
    garbage.add(ptr as usize, len);
    let garbage = &garbage;
    let next = AtomicUsize::new(0);
    let dbuckets = &dbuckets;
    par_map(nt, |_| {
        let mut tbl: Vec<u64> = Vec::new();
        let mut chunks: Vec<(*mut DRec, usize)> = Vec::new();
        loop {
            let p = next.fetch_add(1, Relaxed);
            if p >= 1 << cx.pe_bits {
                break;
            }
            all_chunks(dbuckets, p, &mut chunks);
            dedup_partition(&chunks, &mut tbl, cx, overs);
        }
        garbage.drain();
    });
    lap("events deduped");

    // ---- sessions: per person partition; each thread writes its own
    // user_daily file
    let mut garbage = Garbage::new();
    garbage.add_slabs(dbuckets);
    let garbage = &garbage;
    let next = AtomicUsize::new(0);
    let (pbuckets, cbuckets) = (&pbuckets, &cbuckets);
    // Biggest partitions first, so that one holding a huge person does not
    // end up alone at the tail.
    let mut order: Vec<(usize, u32)> = (0..1usize << cx.pp_bits)
        .map(|p| (pbuckets.iter().map(|b| b.len(p)).sum::<usize>(), p as u32))
        .filter(|x| x.0 > 0)
        .collect();
    order.sort_unstable_by(|a, b| b.cmp(a));
    let order = &order;
    let aggs: Vec<Agg> = par_map(nt, |t| {
        let mut st = Sess::new(cx, t);
        loop {
            let i = next.fetch_add(1, Relaxed);
            if i >= order.len() {
                break;
            }
            st.partition(cx, pbuckets, cbuckets, sides, order[i].1 as usize);
        }
        st.out.finish(t == 0);
        garbage.drain();
        st.agg
    });
    lap("sessions done, user_daily written");

    // ---- campaign_daily, while the other threads let go of the events and
    // clicks
    let mut garbage = Garbage::new();
    garbage.add_slabs(pbuckets);
    garbage.add_slabs(cbuckets);
    let garbage = &garbage;
    std::thread::scope(|s| {
        for _ in 1..nt {
            s.spawn(move || garbage.drain());
        }
        write_campaign_daily(cx, aggs);
        garbage.drain();
    });
    lap("campaign_daily written");
    // Skip destructors: whatever is left is the kernel's job at exit.
    std::process::exit(0);
}

fn write_campaign_daily(cx: &Ctx, aggs: Vec<Agg>) {
    let mut aggs = aggs.into_iter();
    let mut agg = aggs.next().unwrap();
    for a in aggs {
        agg.merge(&a);
    }
    let rows = agg.rows();
    let organic = cx.camp_ids.len() as u32;
    let (mut ids, mut chans) = (Vec::new(), Vec::new());
    let mut days = Vec::with_capacity(rows.len());
    let mut cols: [Vec<i64>; 4] = Default::default();
    for (camp, day, c) in &rows {
        if *camp == organic {
            put_str(&mut ids, b"organic");
            put_str(&mut chans, b"organic");
        } else {
            put_str(&mut ids, &cx.camp_ids[*camp as usize]);
            put_str(&mut chans, &cx.camp_channels[*camp as usize]);
        }
        days.push(*day);
        for k in 0..4 {
            cols[k].push(c[k] as i64);
        }
    }
    let mut w = Writer::create(&cx.out_dir.join("campaign_daily").join("part-000.parquet"), &CAMP_SCHEMA);
    w.row_group(
        rows.len(),
        &[
            Col::Str(&ids),
            Col::Str(&chans),
            Col::I32(&days),
            Col::I64(&cols[0]),
            Col::I64(&cols[1]),
            Col::I64(&cols[2]),
            Col::I64(&cols[3]),
        ],
    );
    w.finish();
}
