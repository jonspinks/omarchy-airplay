//! Minimal Apple binary-plist (`bplist00`) writer, byte-compatible with
//! CPython's `plistlib.dumps(obj, fmt=FMT_BINARY)` (the encoder the probe uses
//! for every SETUP body).
//!
//! The `plist` crate's binary encoder does not reproduce plistlib's object
//! table byte-for-byte (scalar de-duplication, `sort_keys=True`, integer width
//! selection, trailer layout), so the SETUP wire spec requires emitting the
//! binary plist manually. This module matches plistlib's `_BinaryPlistWriter`:
//! `_flatten` order (dict appended, then all sorted keys, then all values),
//! scalar dedup by `(type, value)`, `_write_object`, and the 32-byte trailer.

use std::collections::HashMap;

/// An ordered plist value used to build SETUP bodies.
#[derive(Debug, Clone)]
pub enum Node {
    Bool(bool),
    /// Non-negative integer; widths chosen as plistlib does (1/2/4/8 bytes).
    Int(u64),
    Str(String),
    Data(Vec<u8>),
    Array(Vec<Node>),
    /// Insertion order preserved on the builder side; the writer sorts keys
    /// (plistlib `sort_keys=True`).
    Dict(Vec<(String, Node)>),
}

/// Scalar de-duplication key — plistlib keys `_objtable` by `(type, value)`.
#[derive(PartialEq, Eq, Hash, Clone)]
enum SKey {
    Bool(bool),
    Int(u64),
    Str(String),
    Data(Vec<u8>),
}

fn scalar_key(node: &Node) -> Option<SKey> {
    match node {
        Node::Bool(b) => Some(SKey::Bool(*b)),
        Node::Int(i) => Some(SKey::Int(*i)),
        Node::Str(s) => Some(SKey::Str(s.clone())),
        Node::Data(d) => Some(SKey::Data(d.clone())),
        _ => None,
    }
}

/// A flattened object ready to write. Dict keys become `Obj::Str`.
enum Obj {
    Bool(bool),
    Int(u64),
    Str(String),
    Data(Vec<u8>),
    Array(Vec<usize>),
    Dict(Vec<usize>, Vec<usize>),
}

fn count_to_size(count: usize) -> usize {
    if count < 1 << 8 {
        1
    } else if count < 1 << 16 {
        2
    } else if count < 1usize << 32 {
        4
    } else {
        8
    }
}

/// Encode `root` as a binary plist, byte-identical to plistlib FMT_BINARY.
pub fn encode(root: &Node) -> Vec<u8> {
    let objects = flatten(root);

    let ref_size = count_to_size(objects.len());
    let mut out = Vec::new();
    out.extend_from_slice(b"bplist00");
    let mut offsets = vec![0usize; objects.len()];

    for (i, obj) in objects.iter().enumerate() {
        offsets[i] = out.len();
        write_object(&mut out, obj, ref_size);
    }

    let offset_table_offset = out.len();
    let offset_size = count_to_size(offset_table_offset);
    for &off in &offsets {
        write_be_sized(&mut out, off as u64, offset_size);
    }

    // Trailer: 5 unused, sort_version(0), offset_size, ref_size, num_objects,
    // top_object(0), offset_table_offset — all big-endian.
    out.extend_from_slice(&[0u8; 5]);
    out.push(0); // sort_version
    out.push(offset_size as u8);
    out.push(ref_size as u8);
    out.extend_from_slice(&(objects.len() as u64).to_be_bytes());
    out.extend_from_slice(&0u64.to_be_bytes()); // top object index
    out.extend_from_slice(&(offset_table_offset as u64).to_be_bytes());
    out
}

/// Flatten the tree into `objects` in plistlib order, returning writable
/// objects with resolved child refnums.
fn flatten(root: &Node) -> Vec<Obj> {
    let mut objects: Vec<Obj> = Vec::new();
    let mut scalars: HashMap<SKey, usize> = HashMap::new();
    // Containers are never structurally shared in our builder, so a per-call
    // identity map is unnecessary — each container is visited exactly once.
    walk(root, &mut objects, &mut scalars);
    objects
}

/// Append `node` (and, for containers, its children) in plistlib order and
/// return its refnum. Scalars are de-duplicated by value.
fn walk(node: &Node, objects: &mut Vec<Obj>, scalars: &mut HashMap<SKey, usize>) -> usize {
    if let Some(k) = scalar_key(node) {
        if let Some(&r) = scalars.get(&k) {
            return r;
        }
        let refnum = objects.len();
        scalars.insert(k, refnum);
        objects.push(match node {
            Node::Bool(b) => Obj::Bool(*b),
            Node::Int(i) => Obj::Int(*i),
            Node::Str(s) => Obj::Str(s.clone()),
            Node::Data(d) => Obj::Data(d.clone()),
            _ => unreachable!(),
        });
        return refnum;
    }

    // Container: reserve its slot (plistlib appends before recursing).
    let refnum = objects.len();
    match node {
        Node::Array(items) => {
            objects.push(Obj::Array(Vec::new()));
            let child_refs: Vec<usize> = items.iter().map(|c| walk(c, objects, scalars)).collect();
            objects[refnum] = Obj::Array(child_refs);
        }
        Node::Dict(items) => {
            objects.push(Obj::Dict(Vec::new(), Vec::new()));
            let mut sorted: Vec<&(String, Node)> = items.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            // plistlib flattens all keys first, then all values.
            let key_refs: Vec<usize> = sorted
                .iter()
                .map(|(k, _)| walk(&Node::Str(k.clone()), objects, scalars))
                .collect();
            let val_refs: Vec<usize> = sorted.iter().map(|(_, v)| walk(v, objects, scalars)).collect();
            objects[refnum] = Obj::Dict(key_refs, val_refs);
        }
        _ => unreachable!(),
    }
    refnum
}

fn write_be_sized(out: &mut Vec<u8>, value: u64, size: usize) {
    let bytes = value.to_be_bytes();
    out.extend_from_slice(&bytes[8 - size..]);
}

/// plistlib `_write_size(token, size)`.
fn write_size(out: &mut Vec<u8>, token: u8, size: usize) {
    if size < 15 {
        out.push((token << 4) | size as u8);
    } else {
        out.push((token << 4) | 0x0f);
        write_int_object(out, size as u64);
    }
}

/// plistlib integer object: marker `0x1n` + big-endian value of 1/2/4/8 bytes.
fn write_int_object(out: &mut Vec<u8>, value: u64) {
    if value < 1 << 8 {
        out.push(0x10);
        out.push(value as u8);
    } else if value < 1 << 16 {
        out.push(0x11);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 1u64 << 32 {
        out.push(0x12);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0x13);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn write_object(out: &mut Vec<u8>, obj: &Obj, ref_size: usize) {
    match obj {
        Obj::Bool(false) => out.push(0x08),
        Obj::Bool(true) => out.push(0x09),
        Obj::Int(i) => write_int_object(out, *i),
        Obj::Str(s) => {
            if s.is_ascii() {
                write_size(out, 0b0101, s.len());
                out.extend_from_slice(s.as_bytes());
            } else {
                let units: Vec<u16> = s.encode_utf16().collect();
                write_size(out, 0b0110, units.len());
                for u in units {
                    out.extend_from_slice(&u.to_be_bytes());
                }
            }
        }
        Obj::Data(d) => {
            write_size(out, 0b0100, d.len());
            out.extend_from_slice(d);
        }
        Obj::Array(child_refs) => {
            write_size(out, 0b1010, child_refs.len());
            for &r in child_refs {
                write_be_sized(out, r as u64, ref_size);
            }
        }
        Obj::Dict(key_refs, val_refs) => {
            write_size(out, 0b1101, key_refs.len());
            for &r in key_refs {
                write_be_sized(out, r as u64, ref_size);
            }
            for &r in val_refs {
                write_be_sized(out, r as u64, ref_size);
            }
        }
    }
}

// -- convenience constructors -------------------------------------------------

impl Node {
    pub fn str(s: impl Into<String>) -> Node {
        Node::Str(s.into())
    }
    pub fn int(i: u64) -> Node {
        Node::Int(i)
    }
    pub fn boolean(b: bool) -> Node {
        Node::Bool(b)
    }
    pub fn data(d: impl Into<Vec<u8>>) -> Node {
        Node::Data(d.into())
    }
}
