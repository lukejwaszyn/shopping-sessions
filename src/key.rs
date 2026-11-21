//! Exact fixed-width string keys.
//!
//! Every ID (event, click, user, product, campaign) is turned into a `u128`
//! that represents the string *exactly*, so equality on keys is equality on
//! strings and no hash is ever trusted for identity.
//!
//! * 1..=15 bytes: the bytes sit big-endian in the top 15 bytes and the length
//!   in the low byte. Integer order on two such keys is byte-wise string order.
//! * 16+ bytes: the string is interned in a global table and the key is
//!   `index << 8 | 0xFF`. The generator never produces these; the path exists
//!   only so that arbitrary input stays exact.
//!
//! Key 0 is never produced (the length byte is non-zero) and marks empty slots.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Mutex;

pub type Key = u128;

struct LongTab {
    map: HashMap<Vec<u8>, u64>,
    list: Vec<Vec<u8>>,
}

static LONG: Mutex<Option<LongTab>> = Mutex::new(None);

const fn masks() -> [u128; 16] {
    let mut m = [0u128; 16];
    let mut i = 0;
    while i < 16 {
        m[i] = (1u128 << (8 * i)) - 1;
        i += 1;
    }
    m
}
static MASKS: [u128; 16] = masks();

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
    ((idx as u128) << 8) | 0xFF
}

/// Key of the non-empty field `buf[s..e]`.
#[inline(always)]
pub fn make_key(buf: &[u8], s: usize, e: usize) -> Key {
    let len = e - s;
    debug_assert!(len > 0 && e <= buf.len());
    if len <= 15 {
        let x = if s + 16 <= buf.len() {
            // SAFETY: 16 bytes starting at s are inside buf.
            unsafe { std::ptr::read_unaligned(buf.as_ptr().add(s) as *const u128) }
        } else {
            let mut t = [0u8; 16];
            t[..len].copy_from_slice(&buf[s..e]);
            u128::from_ne_bytes(t)
        };
        (u128::from_le(x) & MASKS[len]).swap_bytes() | len as u128
    } else {
        long_key(&buf[s..e])
    }
}

#[inline(always)]
pub fn is_long(k: Key) -> bool {
    k as u8 == 0xFF
}

/// Append the string a key stands for.
pub fn key_bytes(k: Key, out: &mut Vec<u8>) {
    if !is_long(k) {
        let len = (k as u8) as usize;
        out.extend_from_slice(&k.to_be_bytes()[..len]);
    } else {
        let g = LONG.lock().unwrap();
        out.extend_from_slice(&g.as_ref().unwrap().list[(k >> 8) as usize]);
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
    if !is_long(a) && !is_long(b) {
        a.cmp(&b)
    } else {
        cmp_slow(a, b)
    }
}

#[inline(always)]
pub fn hash(k: Key) -> u64 {
    let lo = k as u64;
    let hi = (k >> 64) as u64;
    let mut x = hi.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ lo;
    x = (x ^ (x >> 32)).wrapping_mul(0xD6E8_FEB8_6659_FD93);
    x = (x ^ (x >> 29)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
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
    pub v: u128,
}

/// Fixed-capacity open-addressing map from exact keys to a 128-bit value.
pub struct KMap {
    pub slots: Vec<Slot>,
    mask: usize,
    pub len: usize,
}

impl KMap {
    /// `max` is an upper bound on the number of distinct keys.
    pub fn new(max: usize) -> KMap {
        let cap = (max * 3 / 2 + 8).next_power_of_two();
        // Zeroed allocation: untouched pages cost nothing.
        let slots = unsafe {
            let layout = std::alloc::Layout::array::<Slot>(cap).unwrap();
            let p = std::alloc::alloc_zeroed(layout) as *mut Slot;
            if p.is_null() {
                std::alloc::handle_alloc_error(layout);
            }
            Vec::from_raw_parts(p, cap, cap)
        };
        KMap { slots, mask: cap - 1, len: 0 }
    }

    #[inline(always)]
    pub fn slot_ptr(&self, k: Key) -> *const Slot {
        unsafe { self.slots.as_ptr().add(hash(k) as usize & self.mask) }
    }

    #[inline(always)]
    pub fn get(&self, k: Key) -> Option<u128> {
        let mut i = hash(k) as usize & self.mask;
        loop {
            let s = unsafe { self.slots.get_unchecked(i) };
            if s.k == k {
                return Some(s.v);
            }
            if s.k == 0 {
                return None;
            }
            i = (i + 1) & self.mask;
        }
    }

    /// Value already stored for `k`, or `v` after storing it.
    #[inline(always)]
    pub fn get_or_insert(&mut self, k: Key, v: u128) -> u128 {
        let mut i = hash(k) as usize & self.mask;
        loop {
            let s = unsafe { self.slots.get_unchecked_mut(i) };
            if s.k == k {
                return s.v;
            }
            if s.k == 0 {
                s.k = k;
                s.v = v;
                self.len += 1;
                return v;
            }
            i = (i + 1) & self.mask;
        }
    }
}
