//! Timestamp and number parsing, strict to the letter of rules.md.

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant).
#[inline(always)]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `YYYY-MM-DDTHH:MM:SS` in `b[0..19]` to epoch seconds. `b.len() >= 19`.
#[inline(always)]
pub fn parse_dt(b: &[u8]) -> Option<i64> {
    debug_assert!(b.len() >= 19);
    let d = |i: usize| -> u32 { unsafe { *b.get_unchecked(i) }.wrapping_sub(b'0') as u32 };
    let mut bad = 0u32;
    for i in [0usize, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        bad |= (d(i) > 9) as u32;
    }
    let c = |i: usize| -> u8 { unsafe { *b.get_unchecked(i) } };
    if bad != 0 || c(4) != b'-' || c(7) != b'-' || c(10) != b'T' || c(13) != b':' || c(16) != b':' {
        return None;
    }
    let y = d(0) * 1000 + d(1) * 100 + d(2) * 10 + d(3);
    let mo = d(5) * 10 + d(6);
    let da = d(8) * 10 + d(9);
    let h = d(11) * 10 + d(12);
    let mi = d(14) * 10 + d(15);
    let s = d(17) * 10 + d(18);
    if mo < 1 || mo > 12 || da < 1 || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    const DIM: [u32; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let dim = if mo == 2 && leap { 29 } else { DIM[mo as usize] };
    if da > dim {
        return None;
    }
    let days = days_from_civil(y as i64, mo as i64, da as i64);
    Some(days * 86_400 + (h * 3600 + mi * 60 + s) as i64)
}

#[inline(always)]
fn load64(b: &[u8], i: usize) -> u64 {
    debug_assert!(i + 8 <= b.len());
    u64::from_le(unsafe { std::ptr::read_unaligned(b.as_ptr().add(i) as *const u64) })
}

/// True when all 8 bytes are in 0..=9.
#[inline(always)]
fn all_le9(t: u64) -> bool {
    (t.wrapping_add(0x7676_7676_7676_7676) | t) & 0x8080_8080_8080_8080 == 0
}

/// Remembers the epoch seconds of the dates seen, keyed by the exact bytes
/// `YYYY-MM-DDT`, so the calendar work is done once per distinct date.
pub struct DateCache {
    k1: [u64; 32],
    k2: [u32; 32],
    secs: [i64; 32],
}

impl DateCache {
    pub fn new() -> DateCache {
        // No valid date has zero bytes, so the empty entries never match.
        DateCache { k1: [0; 32], k2: [0; 32], secs: [0; 32] }
    }
}

/// Same as `parse_dt`, through the date cache. `b.len() >= 19`.
#[inline(always)]
pub fn parse_dt_c(b: &[u8], dc: &mut DateCache) -> Option<i64> {
    let k1 = load64(b, 0); // YYYY-MM-
    let k2 = load64(b, 3) >> 32; // -DDT
    let k2 = k2 as u32;
    let i = ((((k2 >> 8) & 15) * 10 + ((k2 >> 16) & 15)) & 31) as usize;
    if dc.k1[i] == k1 && dc.k2[i] == k2 {
        // HH:MM:SS
        let t = load64(b, 11) ^ 0x3030_3A30_303A_3030;
        if !all_le9(t) || t & 0x0000_FF00_00FF_0000 != 0 {
            return None;
        }
        let h = (t & 15) * 10 + ((t >> 8) & 15);
        let mi = ((t >> 24) & 15) * 10 + ((t >> 32) & 15);
        let s = ((t >> 48) & 15) * 10 + (t >> 56);
        if h > 23 || mi > 59 || s > 59 {
            return None;
        }
        return Some(dc.secs[i] + (h * 3600 + mi * 60 + s) as i64);
    }
    let r = parse_dt(b)?;
    dc.k1[i] = k1;
    dc.k2[i] = k2;
    dc.secs[i] = r - r.rem_euclid(86_400);
    Some(r)
}

/// Value of 8 ASCII digits loaded little-endian, or `None`.
#[inline(always)]
fn parse8(x: u64) -> Option<u64> {
    let t = x ^ 0x3030_3030_3030_3030;
    if !all_le9(t) {
        return None;
    }
    let v = (t.wrapping_mul(10) + (t >> 8)) & 0x00FF_00FF_00FF_00FF;
    let v = (v.wrapping_mul(100) + (v >> 16)) & 0x0000_FFFF_0000_FFFF;
    Some((v.wrapping_mul(10_000) + (v >> 32)) & 0xFFFF_FFFF)
}

/// A `ts` field (F1, F2 or F3) to epoch milliseconds; `None` if it is bad.
/// An F3 value too large to matter (more than 18 significant digits) is
/// reported as `None`: it is outside every window.
#[inline(always)]
pub fn parse_ts(b: &[u8], dc: &mut DateCache) -> Option<i64> {
    let n = b.len();
    if n == 20 && b[19] == b'Z' {
        return parse_dt_c(b, dc).map(|s| s * 1000);
    }
    if n == 13 {
        // The usual F3: 13 digits, as two overlapping groups of 8.
        let hi = parse8(load64(b, 0))?;
        let lo = parse8(load64(b, 5))?;
        return Some((hi * 100_000 + lo % 100_000) as i64);
    }
    if n == 25 && (b[19] == b'+' || b[19] == b'-') {
        let s = parse_dt_c(b, dc)?;
        let d = |i: usize| -> u32 { b[i].wrapping_sub(b'0') as u32 };
        if d(20) > 9 || d(21) > 9 || b[22] != b':' || d(23) > 9 || d(24) > 9 {
            return None;
        }
        let oh = d(20) * 10 + d(21);
        let om = d(23) * 10 + d(24);
        if oh > 23 || om > 59 {
            return None;
        }
        let off = (oh * 3600 + om * 60) as i64;
        let s = if b[19] == b'+' { s - off } else { s + off };
        return Some(s * 1000);
    }
    parse_digits(b, 18).map(|v| v as i64)
}

/// A field of ASCII digits only (at least one), leading zeros allowed, to its
/// value. `None` if it has any other byte, is empty, or has more than
/// `max_sig` significant digits.
#[inline(always)]
pub fn parse_digits(b: &[u8], max_sig: usize) -> Option<u64> {
    if b.is_empty() {
        return None;
    }
    let mut v = 0u64;
    let mut sig = 0usize;
    for &c in b {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        if v != 0 || d != 0 {
            sig += 1;
            if sig > max_sig {
                // Too large; a non-digit further on would be bad as well.
                return None;
            }
            v = v * 10 + d as u64;
        }
    }
    Some(v)
}
