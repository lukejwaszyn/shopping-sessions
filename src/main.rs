//! Shopping Sessions pipeline. See README.md for the design.

mod key;
mod pq;
mod scan;
mod ts;

use key::{hash, key_bytes, key_cmp, make_key, prefetch, KMap, Key};
use pq::{Col, ColDef, Ty, Writer};
use scan::{chunk_bounds, fields, Scanner};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;
use ts::{parse_digits, parse_dt, parse_ts};

const GAP_MS: i64 = 1_800_000;
const WEEK_MS: i64 = 604_800_000;
const DAY_MS: i64 = 86_400_000;
/// `ts` of an event that does not survive (invalid, late, or lost the dedup).
const INVALID: i64 = i64::MIN;

// ---------------------------------------------------------------- records

/// A parsed event row on its way to the dedup, 56 bytes.
#[derive(Clone, Copy)]
#[repr(C, packed(8))]
struct ERec {
    ek: Key,
    uk: Key,
    ts: i64,
    /// ingest_ts, epoch seconds
    ing: i64,
    /// price_cents of a purchase, 0 for view and cart
    price: u32,
    cat: u32,
}

/// A surviving event, attached to its person.
#[derive(Clone, Copy)]
#[repr(C)]
struct PRec {
    person: Key,
    ts: i64,
    price: u32,
    cat: u32,
}

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

const ECAP: usize = 128;
const PCAP: usize = 256;
const CCAP: usize = 128;

// ---------------------------------------------------------------- buckets

const SLAB: usize = 4 << 20;

/// Bump allocator. Memory is never returned: the process exits when done.
struct Arena {
    ptr: *mut u8,
    left: usize,
}

impl Arena {
    fn alloc(&mut self, bytes: usize) -> *mut u8 {
        let bytes = (bytes + 15) & !15;
        if bytes > self.left {
            let sz = SLAB.max(bytes);
            let layout = std::alloc::Layout::from_size_align(sz, 4096).unwrap();
            let p = unsafe { std::alloc::alloc(layout) };
            if p.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            self.ptr = p;
            self.left = sz;
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
            arena: Arena { ptr: std::ptr::null_mut(), left: 0 },
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
}
unsafe impl Send for MFile {}
unsafe impl Sync for MFile {}

impl MFile {
    fn bytes(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
}

fn map_file(path: &Path) -> Option<MFile> {
    use std::os::fd::AsRawFd;
    let f = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {}", path.display(), e));
    let len = f.metadata().unwrap().len() as usize;
    if len == 0 {
        return None;
    }
    // PROT_READ = 1, MAP_PRIVATE = 2 on Linux and macOS.
    let p = unsafe { mmap(std::ptr::null_mut(), len, 1, 2, f.as_raw_fd(), 0) };
    if p as isize == -1 || p.is_null() {
        let v = std::fs::read(path).unwrap().leak();
        return Some(MFile { ptr: v.as_ptr(), len: v.len() });
    }
    Some(MFile { ptr: p, len })
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
    nt: usize,
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

fn manifest_ts(text: &[u8], name: &str) -> i64 {
    let pat = format!("\"{}\"", name);
    let find = |h: &[u8], n: &[u8]| h.windows(n.len()).position(|w| w == n);
    let i = find(text, pat.as_bytes()).unwrap_or_else(|| panic!("manifest.json: no {}", name)) + pat.len();
    let rest = &text[i..];
    let a = rest.iter().position(|&c| c == b'"').expect("manifest.json: value") + 1;
    let b = a + rest[a..].iter().position(|&c| c == b'"').expect("manifest.json: value");
    parse_ts(&rest[a..b]).unwrap_or_else(|| panic!("manifest.json: bad {}", name))
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

fn parse_events(buf: &[u8], cx: &Ctx, out: &mut Buckets<ERec>) {
    let mut sc = Scanner::new(buf);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 7];
    while let Some(l) = sc.next(&mut pos) {
        if !fields(buf, &l, &pos, &mut f) {
            continue;
        }
        if f[0].0 == f[0].1 {
            continue;
        }
        let ek = make_key(buf, f[0].0, f[0].1);
        let ib = &buf[f[3].0..f[3].1];
        let ing = if ib.len() == 20 && ib[19] == b'Z' { parse_dt(ib) } else { None };
        let mut rec = ERec { ek, uk: 0, ts: INVALID, ing: ing.unwrap_or(i64::MAX), price: 0, cat: 0 };
        'v: {
            let Some(ing) = ing else { break 'v };
            let (us, ue) = f[1];
            let (ps, pe) = f[5];
            if us == ue || ps == pe {
                break 'v;
            }
            let Some(ts) = parse_ts(&buf[f[2].0..f[2].1]) else { break 'v };
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
            if purchase {
                let Some(p) = parse_digits(&buf[f[6].0..f[6].1], 8) else { break 'v };
                if p < 1 || p > 10_000_000 {
                    break 'v;
                }
                rec.price = p as u32;
                rec.cat = match cx.products.get(make_key(buf, ps, pe)) {
                    Some(c) => c as u32,
                    None => cx.unknown_cat,
                };
            }
            rec.uk = make_key(buf, us, ue);
            rec.ts = ts;
        }
        out.push(part(hash(ek), cx.pe_bits), rec);
    }
}

fn parse_clicks(buf: &[u8], cx: &Ctx, links: &KMap, out: &mut Buckets<CRec>) {
    let mut sc = Scanner::new(buf);
    let mut pos = [0usize; 8];
    let mut f = [(0usize, 0usize); 4];
    while let Some(l) = sc.next(&mut pos) {
        if !fields(buf, &l, &pos, &mut f) {
            continue;
        }
        if f[0].0 == f[0].1 || f[1].0 == f[1].1 || f[2].0 == f[2].1 {
            continue;
        }
        let Some(ts) = parse_ts(&buf[f[3].0..f[3].1]) else { continue };
        if ts < cx.cws || ts >= cx.we {
            continue;
        }
        let Some(camp) = cx.campaigns.get(make_key(buf, f[2].0, f[2].1)) else { continue };
        let uk = make_key(buf, f[1].0, f[1].1);
        let person = links.get(uk).unwrap_or(uk);
        let ck = make_key(buf, f[0].0, f[0].1);
        out.push(part(hash(person), cx.pp_bits), CRec { person, ck, ts, camp: camp as u32 });
    }
}

// ---------------------------------------------------------------- links

/// Union-find over all linked IDs. The result maps every linked ID to its
/// person's name: the byte-wise smallest ID of the component.
fn build_links(lists: Vec<Vec<(Key, Key)>>) -> KMap {
    let lines: usize = lists.iter().map(|l| l.len()).sum();
    let mut map = KMap::new(2 * lines);
    let mut parent: Vec<u32> = Vec::new();
    let mut size: Vec<u32> = Vec::new();
    let mut keys: Vec<Key> = Vec::new();
    fn find(parent: &mut [u32], mut x: u32) -> u32 {
        while parent[x as usize] != x {
            let g = parent[parent[x as usize] as usize];
            parent[x as usize] = g;
            x = g;
        }
        x
    }
    for l in &lists {
        for &(a, b) in l {
            let mut id = |k: Key| -> u32 {
                let next = keys.len() as u128;
                let v = map.get_or_insert(k, next);
                if v == next {
                    keys.push(k);
                    parent.push(next as u32);
                    size.push(1);
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
        }
    }
    let mut best = keys.clone();
    for i in 0..keys.len() {
        let r = find(&mut parent, i as u32) as usize;
        if key_cmp(keys[i], best[r]) == Ordering::Less {
            best[r] = keys[i];
        }
    }
    for s in map.slots.iter_mut() {
        if s.k != 0 {
            s.v = best[find(&mut parent, s.v as u32) as usize];
        }
    }
    map
}

// ---------------------------------------------------------------- dedup

/// Dedup one event partition on event_id (smallest ingest_ts wins, before
/// validation), then send the survivors to their person's partition.
fn dedup_partition(chunks: &[(*mut ERec, usize)], tbl: &mut Vec<u64>, links: &KMap, cx: &Ctx, out: &mut Buckets<PRec>) {
    if chunks.is_empty() {
        return;
    }
    // Slot: tag (32 hash bits) << 32 | record number + 1. Records are numbered
    // chunk * ECAP + index; a tag match is confirmed on the full key.
    let nslots = (chunks.len() * ECAP * 2).next_power_of_two();
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
                let me = (tag << 32) | ((ci * ECAP + i) as u64 + 1);
                let mut s = h as usize & mask;
                loop {
                    let v = *tbl.get_unchecked(s);
                    if v == 0 {
                        *tbl.get_unchecked_mut(s) = me;
                        break;
                    }
                    if v >> 32 == tag {
                        let og = (v & 0xFFFF_FFFF) as usize - 1;
                        let o = chunks.get_unchecked(og / ECAP).0.add(og % ECAP);
                        if (*o).ek == ek {
                            if (*r).ing < (*o).ing {
                                (*o).ts = INVALID;
                                *tbl.get_unchecked_mut(s) = me;
                            } else {
                                (*r).ts = INVALID;
                            }
                            break;
                        }
                    }
                    s = (s + 1) & mask;
                }
            }
        }
        for &(ptr, len) in chunks {
            for i in 0..len {
                if i + 8 < len {
                    prefetch(links.slot_ptr((*ptr.add(i + 8)).uk));
                }
                let r = ptr.add(i).read();
                if r.ts != INVALID {
                    let person = links.get(r.uk).unwrap_or(r.uk);
                    out.push(part(hash(person), cx.pp_bits), PRec { person, ts: r.ts, price: r.price, cat: r.cat });
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

#[inline(always)]
fn ev_ts(v: u128) -> i64 {
    ((v >> 64) as u64 ^ (1 << 63)) as i64
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
    cls: Vec<Clk>,
    echunks: Vec<(*mut PRec, usize)>,
    cchunks: Vec<(*mut CRec, usize)>,
    name: Vec<u8>,
    catsum: Vec<u64>,
    touched: Vec<u32>,
    ccount: Vec<u32>,
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
            cls: Vec::new(),
            echunks: Vec::new(),
            cchunks: Vec::new(),
            name: Vec::new(),
            catsum: vec![0; cx.cats.len()],
            touched: Vec::new(),
            ccount: vec![0; ncamp],
            inlist: vec![false; ncamp],
            active: Vec::new(),
            organic: ncamp as u32,
            agg: Agg::new(cx),
            out: UserOut::new(cx.out_dir.join("user_daily").join(format!("part-{:03}.parquet", t))),
        }
    }

    /// Group one person partition by person, then process each person.
    fn partition(&mut self, cx: &Ctx, ebs: &[Buckets<PRec>], cbs: &[Buckets<CRec>], p: usize) {
        all_chunks(ebs, p, &mut self.echunks);
        let n: usize = self.echunks.iter().map(|c| c.1).sum();
        if n == 0 {
            return;
        }
        all_chunks(cbs, p, &mut self.cchunks);
        let nslots = (2 * n).next_power_of_two().max(16);
        let mask = nslots - 1;
        self.tbl.clear();
        self.tbl.resize(nslots, 0);
        self.persons.clear();
        self.eoff.clear();
        self.eids.clear();
        self.cids.clear();
        unsafe {
            // Pass 1: number the persons, count their events.
            for &(ptr, len) in &self.echunks {
                for i in 0..len {
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
            self.evs.clear();
            self.evs.resize(n, 0);
            let mut j = 0;
            for &(ptr, len) in &self.echunks {
                for i in 0..len {
                    let r = *ptr.add(i);
                    let id = *self.eids.get_unchecked(j) as usize;
                    j += 1;
                    let o = self.eoff.get_unchecked_mut(id);
                    *self.evs.get_unchecked_mut(*o as usize) = pack_ev(r.ts, r.price, r.cat);
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
            let mut cls = std::mem::take(&mut self.cls);
            let (mut e0, mut c0) = (0usize, 0usize);
            for id in 0..np {
                let e1 = self.eoff[id] as usize;
                let c1 = self.coff[id] as usize;
                let person = self.persons[id];
                self.person(cx, person, &mut evs[e0..e1], &mut cls[c0..c1]);
                e0 = e1;
                c0 = c1;
            }
            self.evs = evs;
            self.cls = cls;
        }
        if self.out.day.len() >= ROW_GROUP_ROWS {
            self.out.flush();
        }
    }

    /// Sessionize one person's events, credit and assist each session, and
    /// emit the person's user_daily rows.
    fn person(&mut self, cx: &Ctx, person: Key, evs: &mut [u128], cls: &mut [Clk]) {
        if evs.len() > 1 {
            evs.sort_unstable();
        }
        if cls.len() > 1 {
            cls.sort_unstable_by(|a, b| a.ts.cmp(&b.ts).then_with(|| key_cmp(a.ck, b.ck)));
        }
        self.name.clear();
        key_bytes(person, &mut self.name);

        let n = evs.len();
        let nc = cls.len();
        let mut i = 0;
        // user_daily row being built
        let mut row_day = i32::MIN;
        let (mut r_sessions, mut r_events, mut r_revenue) = (0u32, 0u32, 0u64);
        // click window [lo, hi): clicks with start - 7d <= ts <= start;
        // grp: first click of the latest timestamp group below hi
        let (mut lo, mut hi, mut grp) = (0usize, 0usize, 0usize);
        while i < n {
            let start = ev_ts(evs[i]);
            let day = start.div_euclid(DAY_MS) as i32;
            if day != row_day {
                if row_day != i32::MIN {
                    self.emit_row(cx, row_day, r_sessions, r_events, r_revenue);
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
                let t = ev_ts(v);
                if t - prev > GAP_MS {
                    break;
                }
                prev = t;
                count += 1;
                let price = (v >> 32) as u32;
                if price != 0 {
                    let cat = v as u32 as usize;
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
                    if hi == 0 || cls[hi].ts != cls[hi - 1].ts {
                        grp = hi;
                    }
                    let c = cls[hi].camp as usize;
                    self.ccount[c] += 1;
                    if !self.inlist[c] {
                        self.inlist[c] = true;
                        self.active.push(c as u32);
                    }
                    hi += 1;
                }
                let limit = start - WEEK_MS;
                while lo < hi && cls[lo].ts < limit {
                    self.ccount[cls[lo].camp as usize] -= 1;
                    lo += 1;
                }
                if hi > lo {
                    camp = cls[grp].camp;
                    let mut j = 0;
                    while j < self.active.len() {
                        let c = self.active[j];
                        if self.ccount[c as usize] == 0 {
                            self.inlist[c as usize] = false;
                            self.active.swap_remove(j);
                        } else {
                            self.agg.cell(c, day)[3] += 1;
                            j += 1;
                        }
                    }
                }
            }
            let cell = self.agg.cell(camp, day);
            cell[0] += 1;
            cell[1] += (revenue > 0) as u64;
            cell[2] += revenue;
        }
        if row_day != i32::MIN {
            self.emit_row(cx, row_day, r_sessions, r_events, r_revenue);
        }
        for c in self.active.drain(..) {
            self.ccount[c as usize] = 0;
            self.inlist[c as usize] = false;
        }
    }

    fn emit_row(&mut self, cx: &Ctx, day: i32, sessions: u32, events: u32, revenue: u64) {
        let o = &mut self.out;
        put_str(&mut o.ids, &self.name);
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

    // Categories, numbered in byte-wise order; `unknown` is one of them.
    let prows = small_csv(&data.join("products.csv"));
    let mut cats: Vec<Vec<u8>> = prows.iter().map(|r| r.1.clone()).collect();
    cats.push(b"unknown".to_vec());
    cats.sort();
    cats.dedup();
    let cat_idx: HashMap<&[u8], u32> = cats.iter().enumerate().map(|(i, c)| (c.as_slice(), i as u32)).collect();
    let mut products = KMap::new(prows.len());
    for (id, cat) in &prows {
        if !id.is_empty() {
            products.get_or_insert(make_key(id, 0, id.len()), cat_idx[cat.as_slice()] as u128);
        }
    }
    let unknown_cat = cat_idx[&b"unknown"[..]];

    let crows = small_csv(&data.join("campaigns.csv"));
    let mut campaigns = KMap::new(crows.len());
    let mut camp_ids = Vec::new();
    let mut camp_channels = Vec::new();
    for (id, ch) in &crows {
        if id.is_empty() {
            continue;
        }
        let next = camp_ids.len() as u128;
        if campaigns.get_or_insert(make_key(id, 0, id.len()), next) == next {
            camp_ids.push(id.clone());
            camp_channels.push(ch.clone());
        }
    }

    let efiles = map_dir(&data.join("events"));
    let cfiles = map_dir(&data.join("clicks"));
    let lfiles = map_dir(&data.join("links"));
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
        nt,
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

    // ---- events: parse and scatter by event_id, while one thread runs the
    // union-find
    let echunks = make_chunks(&efiles, chunk);
    let next = AtomicUsize::new(0);
    let (links, ebuckets) = std::thread::scope(|s| {
        let uf = s.spawn(move || build_links(link_lists));
        let eb: Vec<Buckets<ERec>> = par_map(nt, |_| {
            let mut out = Buckets::new(1 << cx.pe_bits, ECAP);
            loop {
                let i = next.fetch_add(1, Relaxed);
                if i >= echunks.len() {
                    break;
                }
                let (fi, rs, re) = echunks[i];
                let buf = efiles[fi].bytes();
                let (s, e) = chunk_bounds(buf, rs, re);
                parse_events(&buf[s..e], cx, &mut out);
            }
            out
        });
        (uf.join().unwrap(), eb)
    });
    let links = &links;
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
        out
    });
    lap("clicks parsed");

    // ---- events: dedup per partition, resolve the person, scatter by person
    let next = AtomicUsize::new(0);
    let ebuckets = &ebuckets;
    let pbuckets: Vec<Buckets<PRec>> = par_map(nt, |_| {
        let mut out = Buckets::new(1 << cx.pp_bits, PCAP);
        let mut tbl: Vec<u64> = Vec::new();
        let mut chunks: Vec<(*mut ERec, usize)> = Vec::new();
        loop {
            let p = next.fetch_add(1, Relaxed);
            if p >= 1 << cx.pe_bits {
                break;
            }
            all_chunks(ebuckets, p, &mut chunks);
            dedup_partition(&chunks, &mut tbl, links, cx, &mut out);
        }
        out
    });
    lap("events deduped");

    // ---- sessions: per person partition; each thread writes its own
    // user_daily file
    let next = AtomicUsize::new(0);
    let (pbuckets, cbuckets) = (&pbuckets, &cbuckets);
    let aggs: Vec<Agg> = par_map(nt, |t| {
        let mut st = Sess::new(cx, t);
        loop {
            let p = next.fetch_add(1, Relaxed);
            if p >= 1 << cx.pp_bits {
                break;
            }
            st.partition(cx, pbuckets, cbuckets, p);
        }
        st.out.finish(t == 0);
        st.agg
    });
    lap("sessions done, user_daily written");

    // ---- campaign_daily
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
    lap("campaign_daily written");
    let _ = cx.nt;
    // Skip destructors: unmapping gigabytes is the kernel's job at exit.
    std::process::exit(0);
}
