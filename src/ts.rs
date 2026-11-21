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

/// A `ts` field (F1, F2 or F3) to epoch milliseconds; `None` if it is bad.
/// An F3 value too large to matter (more than 18 significant digits) is
/// reported as `None`: it is outside every window.
#[inline(always)]
pub fn parse_ts(b: &[u8]) -> Option<i64> {
    let n = b.len();
    if n == 20 && b[19] == b'Z' {
        return parse_dt(b).map(|s| s * 1000);
    }
    if n == 25 && (b[19] == b'+' || b[19] == b'-') {
        let s = parse_dt(b)?;
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
