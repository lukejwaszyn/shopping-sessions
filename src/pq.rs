//! Minimal Parquet writer: uncompressed, PLAIN-encoded, data page v1, one
//! page per column chunk, any number of row groups per file.

use std::fs::File;
use std::io::Write;

#[derive(Clone, Copy, PartialEq)]
pub enum Ty {
    /// INT32, required
    I32,
    /// INT32 with logical type DATE, required
    Date,
    /// INT64, required
    I64,
    /// BYTE_ARRAY / STRING, required
    Str,
    /// BYTE_ARRAY / STRING, optional
    OptStr,
}

pub struct ColDef {
    pub name: &'static str,
    pub ty: Ty,
}

pub enum Col<'a> {
    I32(&'a [i32]),
    I64(&'a [i64]),
    /// PLAIN-encoded byte arrays: (u32 LE length, bytes) per row.
    Str(&'a [u8]),
    /// `valid[i]` says whether row i has a value; `plain` holds the values of
    /// the valid rows only.
    OptStr { valid: &'a [bool], plain: &'a [u8] },
}

// ---- Thrift compact protocol ----

struct Th {
    b: Vec<u8>,
    last: i16,
    stack: Vec<i16>,
}

const T_I32: u8 = 5;
const T_I64: u8 = 6;
const T_BIN: u8 = 8;
const T_LIST: u8 = 9;
const T_STRUCT: u8 = 12;

impl Th {
    fn new() -> Th {
        Th { b: Vec::new(), last: 0, stack: Vec::new() }
    }
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.b.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.b.push(v as u8);
    }
    fn zz(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64);
    }
    fn field(&mut self, id: i16, ty: u8) {
        let delta = id - self.last;
        if delta > 0 && delta <= 15 {
            self.b.push(((delta as u8) << 4) | ty);
        } else {
            self.b.push(ty);
            self.zz(id as i64);
        }
        self.last = id;
    }
    fn i32(&mut self, id: i16, v: i32) {
        self.field(id, T_I32);
        self.zz(v as i64);
    }
    fn i64(&mut self, id: i16, v: i64) {
        self.field(id, T_I64);
        self.zz(v);
    }
    fn bin(&mut self, id: i16, s: &[u8]) {
        self.field(id, T_BIN);
        self.varint(s.len() as u64);
        self.b.extend_from_slice(s);
    }
    fn struct_begin(&mut self, id: i16) {
        self.field(id, T_STRUCT);
        self.elem_begin();
    }
    /// Start a struct that is a list element (no field header).
    fn elem_begin(&mut self) {
        self.stack.push(self.last);
        self.last = 0;
    }
    fn struct_end(&mut self) {
        self.b.push(0);
        self.last = self.stack.pop().unwrap();
    }
    fn list(&mut self, id: i16, elem: u8, n: usize) {
        self.field(id, T_LIST);
        if n < 15 {
            self.b.push(((n as u8) << 4) | elem);
        } else {
            self.b.push(0xF0 | elem);
            self.varint(n as u64);
        }
    }
}

struct ChunkMeta {
    offset: u64,
    size: u64,
    num_values: u64,
}

struct RgMeta {
    rows: u64,
    cols: Vec<ChunkMeta>,
}

pub struct Writer {
    file: File,
    schema: &'static [ColDef],
    offset: u64,
    rgs: Vec<RgMeta>,
    buf: Vec<u8>,
}

fn as_bytes<T>(s: &[T]) -> &[u8] {
    // Parquet PLAIN is little-endian; so are all supported targets.
    unsafe { std::slice::from_raw_parts(s.as_ptr() as *const u8, std::mem::size_of_val(s)) }
}

impl Writer {
    pub fn create(path: &std::path::Path, schema: &'static [ColDef]) -> Writer {
        let mut file = File::create(path).unwrap_or_else(|e| panic!("create {}: {}", path.display(), e));
        file.write_all(b"PAR1").unwrap();
        Writer { file, schema, offset: 4, rgs: Vec::new(), buf: Vec::new() }
    }

    /// Append one row group of `rows` rows.
    pub fn row_group(&mut self, rows: usize, cols: &[Col]) {
        assert_eq!(cols.len(), self.schema.len());
        if rows == 0 {
            return;
        }
        // Page headers and levels are gathered in `buf`; the column data is
        // written straight from the caller's buffers, one write per column.
        let mut metas = Vec::with_capacity(cols.len());
        for c in cols {
            // Definition levels for the optional column: RLE/bit-packed
            // hybrid, bit width 1, as a single bit-packed run.
            let mut levels: Vec<u8> = Vec::new();
            let data: &[u8] = match c {
                Col::I32(v) => {
                    assert_eq!(v.len(), rows);
                    as_bytes(v)
                }
                Col::I64(v) => {
                    assert_eq!(v.len(), rows);
                    as_bytes(v)
                }
                Col::Str(p) => p,
                Col::OptStr { valid, plain } => {
                    assert_eq!(valid.len(), rows);
                    let groups = rows.div_ceil(8);
                    let mut run = Th::new();
                    run.varint(((groups as u64) << 1) | 1);
                    let mut bits = vec![0u8; groups];
                    for (i, &v) in valid.iter().enumerate() {
                        bits[i >> 3] |= (v as u8) << (i & 7);
                    }
                    let len = (run.b.len() + bits.len()) as u32;
                    levels.extend_from_slice(&len.to_le_bytes());
                    levels.extend_from_slice(&run.b);
                    levels.extend_from_slice(&bits);
                    plain
                }
            };
            let page_size = (levels.len() + data.len()) as i32;
            let mut h = Th::new();
            h.i32(1, 0); // DATA_PAGE
            h.i32(2, page_size);
            h.i32(3, page_size);
            h.struct_begin(5);
            h.i32(1, rows as i32);
            h.i32(2, 0); // PLAIN
            h.i32(3, 3); // definition levels: RLE
            h.i32(4, 3); // repetition levels: RLE
            h.struct_end();
            h.b.push(0);
            self.buf.clear();
            self.buf.extend_from_slice(&h.b);
            self.buf.extend_from_slice(&levels);
            let size = (self.buf.len() + data.len()) as u64;
            if data.len() < 4096 {
                self.buf.extend_from_slice(data);
                self.file.write_all(&self.buf).unwrap();
            } else {
                self.file.write_all(&self.buf).unwrap();
                self.file.write_all(data).unwrap();
            }
            metas.push(ChunkMeta { offset: self.offset, size, num_values: rows as u64 });
            self.offset += size;
        }
        self.rgs.push(RgMeta { rows: rows as u64, cols: metas });
    }

    pub fn finish(mut self) {
        let mut t = Th::new();
        t.i32(1, 1); // version
        t.list(2, T_STRUCT, self.schema.len() + 1);
        t.elem_begin();
        t.bin(4, b"schema");
        t.i32(5, self.schema.len() as i32);
        t.struct_end();
        for c in self.schema {
            t.elem_begin();
            let (pt, rep) = match c.ty {
                Ty::I32 | Ty::Date => (1, 0),
                Ty::I64 => (2, 0),
                Ty::Str => (6, 0),
                Ty::OptStr => (6, 1),
            };
            t.i32(1, pt);
            t.i32(3, rep);
            t.bin(4, c.name.as_bytes());
            match c.ty {
                Ty::Str | Ty::OptStr => {
                    t.i32(6, 0); // ConvertedType UTF8
                    t.struct_begin(10); // LogicalType
                    t.struct_begin(1); // STRING
                    t.struct_end();
                    t.struct_end();
                }
                Ty::Date => {
                    t.i32(6, 6); // ConvertedType DATE
                    t.struct_begin(10);
                    t.struct_begin(6); // DATE
                    t.struct_end();
                    t.struct_end();
                }
                _ => {}
            }
            t.struct_end();
        }
        let total_rows: u64 = self.rgs.iter().map(|r| r.rows).sum();
        t.i64(3, total_rows as i64);
        t.list(4, T_STRUCT, self.rgs.len());
        for rg in &self.rgs {
            t.elem_begin();
            t.list(1, T_STRUCT, rg.cols.len());
            for (c, m) in self.schema.iter().zip(&rg.cols) {
                t.elem_begin();
                t.i64(2, m.offset as i64); // file_offset
                t.struct_begin(3); // ColumnMetaData
                let pt = match c.ty {
                    Ty::I32 | Ty::Date => 1,
                    Ty::I64 => 2,
                    _ => 6,
                };
                t.i32(1, pt);
                t.list(2, T_I32, 2); // encodings: PLAIN, RLE
                t.zz(0);
                t.zz(3);
                t.list(3, T_BIN, 1); // path_in_schema
                t.varint(c.name.len() as u64);
                t.b.extend_from_slice(c.name.as_bytes());
                t.i32(4, 0); // UNCOMPRESSED
                t.i64(5, m.num_values as i64);
                t.i64(6, m.size as i64);
                t.i64(7, m.size as i64);
                t.i64(9, m.offset as i64); // data_page_offset
                t.struct_end();
                t.struct_end();
            }
            let bytes: u64 = rg.cols.iter().map(|m| m.size).sum();
            t.i64(2, bytes as i64);
            t.i64(3, rg.rows as i64);
            t.struct_end();
        }
        t.bin(6, b"shopping-sessions");
        t.b.push(0);
        let n = t.b.len() as u32;
        t.b.extend_from_slice(&n.to_le_bytes());
        t.b.extend_from_slice(b"PAR1");
        self.file.write_all(&t.b).unwrap();
    }
}
