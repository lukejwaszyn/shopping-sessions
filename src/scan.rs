//! Line and field scanner for the contest's CSV dialect.
//!
//! The buffer is classified 64 bytes at a time into three bitmasks (delimiters
//! = commas and newlines, newlines, quotes). A line is then just a walk over
//! the set bits of the delimiter mask; the number of quote characters in the
//! line falls out of a popcount. Every comma separates fields and only `\n`
//! ends a line, so no quote state has to be tracked while scanning.

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline(always)]
unsafe fn masks64(p: *const u8) -> (u64, u64, u64) {
    use core::arch::x86_64::*;
    let a = _mm256_loadu_si256(p as *const __m256i);
    let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
    let m = |c: u8| -> u64 {
        let v = _mm256_set1_epi8(c as i8);
        (_mm256_movemask_epi8(_mm256_cmpeq_epi8(a, v)) as u32 as u64)
            | ((_mm256_movemask_epi8(_mm256_cmpeq_epi8(b, v)) as u32 as u64) << 32)
    };
    let nl = m(b'\n');
    (m(b',') | nl, nl, m(b'"'))
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn masks64(p: *const u8) -> (u64, u64, u64) {
    use core::arch::aarch64::*;
    const POW: [u8; 16] = [1, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128];
    let pow = vld1q_u8(POW.as_ptr());
    let v = [vld1q_u8(p), vld1q_u8(p.add(16)), vld1q_u8(p.add(32)), vld1q_u8(p.add(48))];
    let m = |c: u8| -> u64 {
        let cv = vdupq_n_u8(c);
        let t0 = vandq_u8(vceqq_u8(v[0], cv), pow);
        let t1 = vandq_u8(vceqq_u8(v[1], cv), pow);
        let t2 = vandq_u8(vceqq_u8(v[2], cv), pow);
        let t3 = vandq_u8(vceqq_u8(v[3], cv), pow);
        let s0 = vpaddq_u8(t0, t1);
        let s1 = vpaddq_u8(t2, t3);
        let s0 = vpaddq_u8(s0, s1);
        let s0 = vpaddq_u8(s0, s0);
        vgetq_lane_u64(vreinterpretq_u64_u8(s0), 0)
    };
    let nl = m(b'\n');
    (m(b',') | nl, nl, m(b'"'))
}

#[cfg(not(any(all(target_arch = "x86_64", target_feature = "avx2"), target_arch = "aarch64")))]
#[inline(always)]
unsafe fn masks64(p: *const u8) -> (u64, u64, u64) {
    let (mut d, mut nl, mut q) = (0u64, 0u64, 0u64);
    for i in 0..64 {
        let c = *p.add(i);
        nl |= ((c == b'\n') as u64) << i;
        d |= ((c == b',' || c == b'\n') as u64) << i;
        q |= ((c == b'"') as u64) << i;
    }
    (d, nl, q)
}

/// One line: `buf[start..end]`, with `n` commas (so `n + 1` fields) and `qc`
/// quote characters.
#[derive(Clone, Copy)]
pub struct Line {
    pub start: usize,
    pub end: usize,
    pub n: usize,
    pub qc: u32,
}

pub struct Scanner<'a> {
    buf: &'a [u8],
    base: usize,
    d: u64,
    nl: u64,
    q: u64,
    line_start: usize,
}

impl<'a> Scanner<'a> {
    pub fn new(buf: &'a [u8]) -> Scanner<'a> {
        let mut s = Scanner { buf, base: 0, d: 0, nl: 0, q: 0, line_start: 0 };
        if !buf.is_empty() {
            s.load();
        }
        s
    }

    #[inline(always)]
    fn load(&mut self) {
        let len = self.buf.len();
        let (d, nl, q) = if self.base + 64 <= len {
            unsafe { masks64(self.buf.as_ptr().add(self.base)) }
        } else {
            let mut t = [0u8; 64];
            t[..len - self.base].copy_from_slice(&self.buf[self.base..]);
            unsafe { masks64(t.as_ptr()) }
        };
        self.d = d;
        self.nl = nl;
        self.q = q;
    }

    /// Next line. The positions of its first 8 commas go to `pos`. A final
    /// line without a trailing newline is still a line.
    #[inline(always)]
    pub fn next(&mut self, pos: &mut [usize; 8]) -> Option<Line> {
        let len = self.buf.len();
        if self.line_start >= len {
            return None;
        }
        let start = self.line_start;
        let mut n = 0usize;
        let mut qc = 0u32;
        loop {
            if self.d == 0 {
                qc += self.q.count_ones();
                self.q = 0;
                self.base += 64;
                if self.base >= len {
                    self.line_start = len;
                    return Some(Line { start, end: len, n, qc });
                }
                self.load();
                continue;
            }
            let bit = self.d.trailing_zeros();
            let p = self.base + bit as usize;
            self.d &= self.d - 1;
            if (self.nl >> bit) & 1 != 0 {
                let low = (1u64 << bit) - 1;
                qc += (self.q & low).count_ones();
                self.q &= !low;
                self.line_start = p + 1;
                return Some(Line { start, end: p, n, qc });
            }
            if n < 8 {
                pos[n] = p;
            }
            n += 1;
        }
    }
}

/// Split a line into exactly `N` fields with surrounding quotes removed.
/// Returns false when the line is malformed: wrong field count, or a quote
/// anywhere except around a whole field. Branch-free per field: which fields
/// are quoted is random, so a branch on it would be mispredicted all the time.
#[inline(always)]
pub fn fields<const N: usize>(buf: &[u8], l: &Line, pos: &[usize; 8], f: &mut [(usize, usize); N]) -> bool {
    if l.n != N - 1 {
        return false;
    }
    // A line exists, so the buffer is not empty.
    let top = buf.len() - 1;
    let mut s = l.start;
    let mut nq = 0u32;
    let mut bad = false;
    for i in 0..N {
        let e = if i < N - 1 { pos[i] } else { l.end };
        // SAFETY: both indices are clamped into the buffer; a clamped read is
        // only ever used when it was in range anyway (s < e <= buf.len()).
        let first = unsafe { *buf.get_unchecked(s.min(top)) };
        let last = unsafe { *buf.get_unchecked(e.wrapping_sub(1).min(top)) };
        let q = (s < e) & (first == b'"');
        // An opening quote needs its closing quote: at least two bytes.
        bad |= q & !((e - s >= 2) & (last == b'"'));
        f[i] = (s + q as usize, e - q as usize);
        nq += q as u32;
        s = e + 1;
    }
    !bad & (l.qc == 2 * nq)
}

/// Turn a raw byte range of a file into the range of whole lines that start
/// in it. The header (the file's first line) belongs to no range. A line
/// belongs to the range holding the byte just before its first byte, so
/// adjacent raw ranges give adjacent, non-overlapping line ranges.
pub fn chunk_bounds(buf: &[u8], raw_s: usize, raw_e: usize) -> (usize, usize) {
    let after_nl = |from: usize| -> usize {
        match buf[from..].iter().position(|&b| b == b'\n') {
            Some(i) => from + i + 1,
            None => buf.len(),
        }
    };
    let s = if raw_s == 0 { after_nl(0) } else { after_nl(raw_s - 1) };
    let e = if raw_e >= buf.len() { buf.len() } else { after_nl(raw_e - 1) };
    (s, e.max(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-by-byte reference: (start, end, commas, quotes, first 8 commas).
    fn reference(buf: &[u8]) -> Vec<(usize, usize, usize, u64, Vec<usize>)> {
        let mut out = Vec::new();
        let mut start = 0;
        while start < buf.len() {
            let end = buf[start..].iter().position(|&b| b == b'\n').map_or(buf.len(), |i| start + i);
            let line = &buf[start..end];
            let commas: Vec<usize> = (0..line.len()).filter(|&i| line[i] == b',').map(|i| start + i).collect();
            let quotes = line.iter().filter(|&&b| b == b'"').count() as u64;
            out.push((start, end, commas.len(), quotes, commas.into_iter().take(8).collect()));
            start = end + 1;
        }
        out
    }

    fn scanned(buf: &[u8]) -> Vec<(usize, usize, usize, u64, Vec<usize>)> {
        let mut sc = Scanner::new(buf);
        let mut pos = [0usize; 8];
        let mut out = Vec::new();
        while let Some(l) = sc.next(&mut pos) {
            out.push((l.start, l.end, l.n, l.qc as u64, pos[..l.n.min(8)].to_vec()));
        }
        out
    }

    #[test]
    fn scanner_matches_reference() {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        let mut rnd = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for case in 0..20_000 {
            // Mixes of mostly-delimiter and mostly-text buffers, short and
            // long, so that lines span blocks and refills in every way.
            let len = match case % 4 {
                0 => rnd() % 70,
                1 => rnd() % 300,
                2 => rnd() % 3000,
                _ => rnd() % 9000,
            } as usize;
            let dense = rnd() % 5;
            let nl_rate = [3u64, 12, 80, 700, 5000][(rnd() % 5) as usize];
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    let r = rnd();
                    if r % nl_rate == 0 {
                        b'\n'
                    } else {
                        match (r >> 20) % (2 + 6 * dense) {
                            0 => b',',
                            1 => b'"',
                            _ => b'a' + ((r >> 40) % 26) as u8,
                        }
                    }
                })
                .collect();
            assert_eq!(scanned(&buf), reference(&buf), "case {} len {}", case, len);
        }
    }
}
