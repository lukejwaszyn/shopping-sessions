//! Exact 64-bit string keys.
//!
//! Every ID (event, click, user, product, campaign) is turned into a `u64`
//! that represents the string *exactly*, so equality on keys is equality on
//! strings and no hash is ever trusted for identity.
//!
//! * Compact: a string of 1..=10 bytes, all from `0-9 A-Z _ a-z`, is written
//!   as one 6-bit code per byte (1..=63, in byte order), first byte in the top
//!   bits, unused codes zero, and the low 4 bits zero. No code is zero, so the
//!   codes alone identify the string, and integer order on two compact keys is
//!   byte-wise string order. Every ID the generator makes is of this kind.
//! * Interned: any other string is stored in a global table and its key is
//!   `index << 4 | 0xF`. This path is slow and exists so that arbitrary input
//!   stays exact.
//!
//! Key 0 is never produced (a field is never empty here) and marks empty
//! slots.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Mutex;

pub type Key = u64;

struct LongTab {
    map: HashMap<Vec<u8>, u64>,
    list: Vec<Vec<u8>>,
}

static LONG: Mutex<Option<LongTab>> = Mutex::new(None);

/// Longest string a compact key holds.
pub const COMPACT_MAX: usize = 10;
const INVALID: u8 = 0x80;

/// The alphabet in byte order; code = index + 1.
const ALPHA: &[u8; 63] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

const fn code_table() -> [u8; 256] {
    let mut t = [INVALID; 256];
    let mut i = 0;
    while i < 63 {
        t[ALPHA[i] as usize] = i as u8 + 1;
        i += 1;
    }
    t
}
static CODE: [u8; 256] = code_table();

/// `KEEP[len]`: the bits of the first `len` codes.
const fn keep_table() -> [u64; COMPACT_MAX + 1] {
    let mut m = [0u64; COMPACT_MAX + 1];
    let mut i = 1;
    while i <= COMPACT_MAX {
        m[i] = !0u64 << (64 - 6 * i);
        i += 1;
    }
    m
}
static KEEP: [u64; COMPACT_MAX + 1] = keep_table();

#[cold]
#[inline(never)]
fn long_key(s: &[u8]) -> Key {
    let mut g = LONG.lock().unwrap();
    let t = g.get_or_insert_with(|| LongTab { map: HashMap::new(), list: Vec::new() });
    let idx = match t.map.get(s) {
        Some(&i) => i,
        None => {
            let i = t.list.len() as u64;
            t.list.push(s.to_vec());
            t.map.insert(s.to_vec(), i);
            i
        }
    };
    (idx << 4) | 0xF
}

/// Key of the non-empty field `buf[s..e]`.
#[inline(always)]
pub fn make_key(buf: &[u8], s: usize, e: usize) -> Key {
    let len = e - s;
    debug_assert!(len > 0 && e <= buf.len());
    if len > COMPACT_MAX {
        return long_key(&buf[s..e]);
    }
    let (lo, hi) = if s + 16 <= buf.len() {
        // SAFETY: 16 bytes starting at s are inside buf.
        unsafe {
            let p = buf.as_ptr().add(s);
            (
                u64::from_le(std::ptr::read_unaligned(p as *const u64)),
                u64::from_le(std::ptr::read_unaligned(p.add(8) as *const u64)),
            )
        }
    } else {
        let mut t = [0u8; 16];
        t[..len].copy_from_slice(&buf[s..e]);
        (u64::from_le_bytes(t[..8].try_into().unwrap()), u64::from_le_bytes(t[8..].try_into().unwrap()))
    };
    // All ten positions are coded; those past the field are cut off after.
    let mut k = 0u64;
    let mut bad = 0u32;
    let mut i = 0;
    while i < COMPACT_MAX {
        let byte = if i < 8 { (lo >> (8 * i)) as u8 } else { (hi >> (8 * (i - 8))) as u8 };
        let c = CODE[byte as usize];
        k |= ((c & 63) as u64) << (58 - 6 * i);
        bad |= ((c >> 7) as u32) << i;
        i += 1;
    }
    if bad & ((1u32 << len) - 1) != 0 {
        return long_key(&buf[s..e]);
    }
    k & KEEP[len]
}

#[inline(always)]
pub fn is_long(k: Key) -> bool {
    k & 0xF != 0
}

/// Write the string of a compact key to `out`, return its length.
#[inline(always)]
pub fn compact_bytes(k: Key, out: &mut [u8; 16]) -> usize {
    let mut n = 0;
    while n < COMPACT_MAX {
        let c = ((k >> (58 - 6 * n)) & 63) as usize;
        if c == 0 {
            break;
        }
        out[n] = ALPHA[c - 1];
        n += 1;
    }
    n
}

/// Append the string a key stands for.
pub fn key_bytes(k: Key, out: &mut Vec<u8>) {
    if !is_long(k) {
        let mut b = [0u8; 16];
        let n = compact_bytes(k, &mut b);
        out.extend_from_slice(&b[..n]);
    } else {
        let g = LONG.lock().unwrap();
        out.extend_from_slice(&g.as_ref().unwrap().list[(k >> 4) as usize]);
    }
}

#[cold]
#[inline(never)]
fn cmp_slow(a: Key, b: Key) -> Ordering {
    let (mut x, mut y) = (Vec::new(), Vec::new());
    key_bytes(a, &mut x);
    key_bytes(b, &mut y);
    x.cmp(&y)
}

/// Byte-wise order of the strings behind two keys.
#[inline(always)]
pub fn key_cmp(a: Key, b: Key) -> Ordering {
    if (a | b) & 0xF == 0 {
        a.cmp(&b)
    } else {
        cmp_slow(a, b)
    }
}

#[inline(always)]
pub fn hash(k: Key) -> u64 {
    let x = k.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let x = (x ^ (x >> 32)).wrapping_mul(0xD6E8_FEB8_6659_FD93);
    x ^ (x >> 32)
}

#[inline(always)]
pub fn prefetch<T>(p: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch(p as *const i8, core::arch::x86_64::_MM_HINT_T0);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("prfm pldl1keep, [{0}]", in(reg) p, options(nostack, preserves_flags, readonly));
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let _ = p;
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Slot {
    pub k: Key,
    pub v: u64,
}

extern "C" {
    fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    #[cfg(target_os = "linux")]
    fn madvise(addr: *mut u8, len: usize, advice: i32) -> i32;
}

/// Map a whole file read-only. `None` if the kernel refuses.
pub fn map_ro(fd: i32, len: usize) -> Option<*const u8> {
    // PROT_READ = 1, MAP_PRIVATE = 2 on Linux and macOS.
    let p = unsafe { mmap(std::ptr::null_mut(), len, 1, 2, fd, 0) };
    if p as isize == -1 || p.is_null() {
        None
    } else {
        Some(p)
    }
}

/// Zeroed memory that is never freed, committed lazily. On Linux it is
/// aligned to 2 MB and advised for transparent huge pages, which cuts page
/// faults and TLB misses for the scatter buffers and the link map.
pub fn big_alloc(bytes: usize) -> *mut u8 {
    const HUGE: usize = 2 << 20;
    let len = (bytes.max(1) + HUGE - 1) & !(HUGE - 1);
    // MAP_PRIVATE | MAP_ANONYMOUS
    #[cfg(target_os = "linux")]
    const FLAGS: i32 = 0x22;
    #[cfg(not(target_os = "linux"))]
    const FLAGS: i32 = 0x1002;
    // PROT_READ | PROT_WRITE
    let p = unsafe { mmap(std::ptr::null_mut(), len + HUGE, 3, FLAGS, -1, 0) };
    if p as isize != -1 && !p.is_null() {
        let a = ((p as usize + HUGE - 1) & !(HUGE - 1)) as *mut u8;
        #[cfg(target_os = "linux")]
        unsafe {
            madvise(a, len, 14); // MADV_HUGEPAGE; fine if it is refused
        }
        return a;
    }
    let layout = std::alloc::Layout::from_size_align(bytes.max(1), 4096).unwrap();
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    if p.is_null() {
        std::alloc::handle_alloc_error(layout);
    }
    p
}

/// Fixed-capacity open-addressing map from exact keys to a 64-bit value.
pub struct KMap {
    slots: *mut Slot,
    mask: usize,
}

unsafe impl Send for KMap {}
unsafe impl Sync for KMap {}

impl KMap {
    /// `max` is an upper bound on the number of distinct keys.
    pub fn new(max: usize) -> KMap {
        let cap = (max * 3 / 2 + 8).next_power_of_two();
        let slots = big_alloc(cap * std::mem::size_of::<Slot>()) as *mut Slot;
        KMap { slots, mask: cap - 1 }
    }

    pub fn slots_mut(&mut self) -> &mut [Slot] {
        unsafe { std::slice::from_raw_parts_mut(self.slots, self.mask + 1) }
    }

    #[inline(always)]
    pub fn slot_ptr(&self, k: Key) -> *const Slot {
        unsafe { self.slots.add(hash(k) as usize & self.mask) }
    }

    #[inline(always)]
    pub fn get(&self, k: Key) -> Option<u64> {
        let mut i = hash(k) as usize & self.mask;
        loop {
            let s = unsafe { &*self.slots.add(i) };
            if s.k == k {
                return Some(s.v);
            }
            if s.k == 0 {
                return None;
            }
            i = (i + 1) & self.mask;
        }
    }

    /// Like `get_or_insert`, and says which slot holds `k`.
    #[inline(always)]
    pub fn get_or_insert_at(&mut self, k: Key, v: u64) -> (u64, usize) {
        let mut i = hash(k) as usize & self.mask;
        loop {
            let s = unsafe { &mut *self.slots.add(i) };
            if s.k == k {
                return (s.v, i);
            }
            if s.k == 0 {
                s.k = k;
                s.v = v;
                return (v, i);
            }
            i = (i + 1) & self.mask;
        }
    }

    /// Value already stored for `k`, or `v` after storing it.
    #[inline(always)]
    pub fn get_or_insert(&mut self, k: Key, v: u64) -> u64 {
        let mut i = hash(k) as usize & self.mask;
        loop {
            let s = unsafe { &mut *self.slots.add(i) };
            if s.k == k {
                return s.v;
            }
            if s.k == 0 {
                s.k = k;
                s.v = v;
                return v;
            }
            i = (i + 1) & self.mask;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_exact_and_ordered() {
        let mut x = 0x1234_5678_9ABC_DEF1u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let pool: &[u8] = b"09AZ_az\0 ,\"-/:@[`{\x7f\x80\xff5Qq^";
        let mut strs: Vec<Vec<u8>> = Vec::new();
        for _ in 0..6000 {
            let len = 1 + (rnd() % 13) as usize;
            // Mostly alphabet bytes, so that many strings are compact and
            // many share prefixes.
            let alpha_only = rnd() % 4 != 0;
            let s: Vec<u8> = (0..len)
                .map(|_| {
                    let r = rnd();
                    if alpha_only {
                        ALPHA[((r >> 8) % if r & 1 == 0 { 63 } else { 3 }) as usize]
                    } else {
                        pool[(r % pool.len() as u64) as usize]
                    }
                })
                .collect();
            strs.push(s);
        }
        for a in ALPHA.iter() {
            strs.push(vec![*a]);
        }
        for b in 0..=255u8 {
            strs.push(vec![b]);
            strs.push(vec![b'a', b]);
            strs.push(vec![b'a'; 9].into_iter().chain([b]).collect());
        }
        let keys: Vec<Key> = strs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                // The field in the middle of a buffer and at its very end.
                let mut buf = b",,".to_vec();
                buf.extend_from_slice(s);
                let k1 = make_key(&buf, 2, 2 + s.len());
                buf.extend_from_slice(b"\",zzzzzzzzzzzzzzzzzzzzzzzz\n");
                let k2 = make_key(&buf, 2, 2 + s.len());
                assert_eq!(k1, k2, "string {}", i);
                assert_ne!(k1, 0);
                let compact = s.len() <= COMPACT_MAX && s.iter().all(|c| ALPHA.contains(c));
                assert_eq!(!is_long(k1), compact);
                let mut back = Vec::new();
                key_bytes(k1, &mut back);
                assert_eq!(&back, s);
                k1
            })
            .collect();
        for i in 0..strs.len() {
            for j in (i + 1..strs.len()).step_by(1 + i % 7) {
                assert_eq!(keys[i] == keys[j], strs[i] == strs[j]);
                assert_eq!(key_cmp(keys[i], keys[j]), strs[i].cmp(&strs[j]), "{:?} {:?}", strs[i], strs[j]);
            }
        }
    }
}
