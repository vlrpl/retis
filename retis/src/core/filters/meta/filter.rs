//! # FilterMeta
//!
//! Object for metadata filtering. It takes as input a filter string
//! under the form struct_name.member1.member2.[...].leafmember
//! generating a sequence of actions.

use std::fmt;

use anyhow::{anyhow, bail, Result};
use btf_rs::*;
use plain::Plain;

use crate::core::inspect::inspector;

const META_OPS_MAX: u32 = 32;
const META_TARGET_MAX: usize = 32;

const PTR_BIT: u8 = 1 << 6;
const SIGN_BIT: u8 = 1 << 7;

#[derive(Default)]
struct LhsNode<'a> {
    member: &'a str,
    mask: u64,
    tgt_type: Option<&'a str>,
}

#[derive(Eq, PartialEq)]
enum MetaCmp {
    Eq = 0,
    Gt = 1,
    Lt = 2,
    Ge = 3,
    Le = 4,
    Ne = 5,
}

impl MetaCmp {
    fn from_str(op: &str) -> Result<MetaCmp> {
        let op = match op {
            "==" => MetaCmp::Eq,
            ">" => MetaCmp::Gt,
            "<" => MetaCmp::Lt,
            ">=" => MetaCmp::Ge,
            "<=" => MetaCmp::Le,
            "!=" => MetaCmp::Ne,
            _ => bail!("unknown comparison operator ({op})."),
        };

        Ok(op)
    }
}

impl fmt::Display for MetaCmp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MetaCmp::Eq => write!(f, "=="),
            MetaCmp::Gt => write!(f, ">"),
            MetaCmp::Lt => write!(f, "<"),
            MetaCmp::Ge => write!(f, ">="),
            MetaCmp::Le => write!(f, "<="),
            MetaCmp::Ne => write!(f, "!="),
        }
    }
}

enum MetaType {
    Char = 1,
    Short = 2,
    Int = 3,
    Long = 4,
}

// In Rust alignment can only be specified at struct level whereas in
// C you can easily do it on different levels. This means md must be
// kept first to honour the layout contract between user and eBPF.
// C representation, although allows more flexibility, follows the
// one below.
#[repr(C, align(8))]
#[derive(Copy, Clone)]
struct MetaTarget {
    md: [u8; META_TARGET_MAX],
    sz: u8,
    cmp: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct MetaLoad {
    // Type of data we're going to load
    // bit 0-4: [char|short|int|long], bit5: reserved, bit6: is_ptr, bit7: sign
    r#type: u8,
    // Usually zero.
    // nmemb > 0 is valid iff MetaOp::r#type == MetaType::Char
    nmemb: u8,
    // Byte offset if bf_size is zero. Bit offset otherwise.
    offt: u16,
    // Zero for no bitfield.
    bf_size: u8,
    // Mask to apply. Only numbers are supported.
    mask: u64,
}

impl MetaLoad {
    fn is_num(&self) -> bool {
        self.is_byte() || self.is_short() || self.is_int() || self.is_long()
    }

    fn is_byte(&self) -> bool {
        self.r#type & 0x1f == MetaType::Char as u8
    }

    fn is_short(&self) -> bool {
        self.r#type & 0x1f == MetaType::Short as u8
    }

    fn is_int(&self) -> bool {
        self.r#type & 0x1f == MetaType::Int as u8
    }

    fn is_long(&self) -> bool {
        self.r#type & 0x1f == MetaType::Long as u8
    }

    fn is_ptr(&self) -> bool {
        self.r#type & PTR_BIT > 0
    }

    fn is_signed(&self) -> bool {
        self.r#type & SIGN_BIT > 0
    }

    fn is_arr(&self) -> bool {
        self.nmemb > 0
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(crate) union MetaOp {
    l: MetaLoad,
    t: MetaTarget,
}
unsafe impl Plain for MetaOp {}

impl MetaOp {
    fn new() -> MetaOp {
        unsafe { std::mem::zeroed::<_>() }
    }

    fn load_ref(&self) -> &MetaLoad {
        unsafe { &self.l }
    }

    fn load_ref_mut(&mut self) -> &mut MetaLoad {
        unsafe { &mut self.l }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn target_ref(&self) -> &MetaTarget {
        unsafe { &self.t }
    }

    pub(self) fn target_ref_mut(&mut self) -> &mut MetaTarget {
        unsafe { &mut self.t }
    }

    fn bail_on_arr(load: &MetaLoad, tn: &str) -> Result<()> {
        if load.is_arr() {
            bail!("array of {tn} are not supported.");
        }

        Ok(())
    }

    fn bail_on_ptr(load: &MetaLoad, tn: &str) -> Result<()> {
        if load.is_ptr() {
            bail!("pointers to {tn} are not supported.");
        }

        Ok(())
    }

    fn emit_load_ptr(offt: u32, mask: u64) -> Result<MetaOp> {
        let mut op: MetaOp = MetaOp::new();
        op.l.offt = u16::try_from(offt / 8)?;
        op.l.r#type = PTR_BIT;
        op.l.mask = mask;

        Ok(op)
    }

    fn emit_load(btf: &Btf, r#type: &Type, offt: u32, bfs: u32, mask: u64) -> Result<MetaOp> {
        let mut op: MetaOp = MetaOp::new();
        let lop = op.load_ref_mut();
        let mut t = r#type.clone();
        let mut type_iter = btf.type_iter(
            r#type
                .as_btf_type()
                .ok_or_else(|| anyhow!("Unable to retrieve iterable BTF type"))?,
        );

        loop {
            match t {
                Type::Ptr(_) => {
                    Self::bail_on_ptr(lop, t.name())?;
                    lop.r#type |= PTR_BIT
                }
                Type::Array(ref a) => {
                    // Pointers to array are not supported.
                    Self::bail_on_ptr(lop, t.name())?;
                    // Retrieve the number of elements
                    lop.nmemb = u8::try_from(a.len())?;
                }
                Type::Enum(ref e) => {
                    // Pointers to enum are not supported.
                    Self::bail_on_ptr(lop, t.name())?;
                    // Always assume size 4B
                    lop.r#type |= MetaType::Int as u8;
                    if e.is_signed() {
                        lop.r#type |= SIGN_BIT;
                    }
                }
                Type::Enum64(ref e64) => {
                    // Pointers to enum64 are not supported.
                    Self::bail_on_ptr(lop, t.name())?;
                    // Always assume size 8B
                    lop.r#type |= MetaType::Long as u8;
                    if e64.is_signed() {
                        lop.r#type |= SIGN_BIT;
                    }
                }
                Type::Int(ref i) => {
                    if i.is_signed() {
                        lop.r#type |= SIGN_BIT;
                    }

                    match i.size() {
                        8 => lop.r#type |= MetaType::Long as u8,
                        4 => lop.r#type |= MetaType::Int as u8,
                        2 => lop.r#type |= MetaType::Short as u8,
                        1 => lop.r#type |= MetaType::Char as u8,
                        _ => bail!("unsupported type."),
                    }

                    // Array or Ptr are not supported for types other than
                    // chars
                    if !lop.is_byte() {
                        Self::bail_on_arr(lop, t.name())?;
                        Self::bail_on_ptr(lop, t.name())?;
                    }
                }
                Type::Typedef(_)
                | Type::Volatile(_)
                | Type::Const(_)
                | Type::Restrict(_)
                | Type::DeclTag(_)
                | Type::TypeTag(_) => (),
                _ => bail!(
                    "found unsupported type while emitting operation ({}).",
                    t.name()
                ),
            }

            t = match type_iter.next() {
                Some(x) => x,
                None => break,
            };
        }

        if mask > 0 {
            if lop.is_ptr() || (lop.is_num() && !lop.is_signed()) {
                lop.mask = mask;
            } else {
                bail!("mask is only supported for pointers and unsigned numeric members.");
            }
        }

        lop.bf_size = u8::try_from(bfs)?;
        lop.offt = u16::try_from(offt)?;

        if bfs == 0 {
            lop.offt /= 8;
        }

        Ok(op)
    }

    fn emit_target(lmo: &MetaLoad, rval: Rval, cmp_op: MetaCmp) -> Result<MetaOp> {
        let mut op: MetaOp = MetaOp::new();
        let top = op.target_ref_mut();

        if lmo.is_ptr() || lmo.nmemb > 0 {
            if cmp_op != MetaCmp::Eq && cmp_op != MetaCmp::Ne {
                bail!(
                    "wrong comparison operator. Only '{}' and '{}' are supported for strings.",
                    MetaCmp::Eq,
                    MetaCmp::Ne
                );
            }

            if let Rval::Str(val) = rval {
                let rval_len = val.len();
                let md = &mut top.md;
                if rval_len >= md.len() {
                    bail!("invalid rval size (max {}).", md.len() - 1);
                }

                md[..rval_len].copy_from_slice(val.as_bytes());
                top.sz = rval_len as u8;
            } else {
                bail!("invalid target value for array or ptr type. Only strings are supported.");
            }
        } else if lmo.is_num() {
            let long = match rval {
                Rval::Dec(val) => {
                    if val.starts_with('-') {
                        if !lmo.is_signed() {
                            bail!("invalid target value (value is signed while type is unsigned)");
                        }

                        val.parse::<i64>()? as u64
                    } else {
                        val.parse::<u64>()?
                    }
                }
                Rval::Hex(val) => u64::from_str_radix(&val, 16)?,
                _ => bail!("invalid target value (neither decimal nor hex)."),
            };

            top.md[..std::mem::size_of_val(&long)].copy_from_slice(&long.to_ne_bytes());

            top.sz = if lmo.is_byte() {
                1
            } else if lmo.is_short() {
                2
            } else if lmo.is_int() {
                4
            } else if lmo.is_long() {
                8
            } else {
                bail!("unexpected numeric type");
            };
        }

        top.cmp = cmp_op as u8;

        Ok(op)
    }
}

fn walk_btf_node(
    btf: &Btf,
    r#type: &Type,
    node_name: &str,
    offset: u32,
) -> Option<(u32, Option<u32>, Type)> {
    let r#type = match r#type {
        Type::Struct(r#struct) | Type::Union(r#struct) => r#struct,
        _ => {
            return None;
        }
    };

    for member in r#type.members.iter() {
        let fname = btf.resolve_name(member).unwrap();
        if fname.eq(node_name) {
            match btf.resolve_chained_type(member).ok() {
                Some(ty) => {
                    return Some((offset + member.bit_offset(), member.bitfield_size(), ty))
                }
                None => return None,
            }
        } else if fname.is_empty() {
            let s = btf.resolve_chained_type(member).ok();
            let ty = s.as_ref()?;

            match ty {
                s @ Type::Struct(_) | s @ Type::Union(_) => {
                    match walk_btf_node(btf, s, node_name, offset + member.bit_offset()) {
                        Some((offt, bfs, x)) => return Some((offt, bfs, x)),
                        _ => continue,
                    }
                }
                _ => return None,
            };
        }
    }

    None
}

#[derive(Eq, PartialEq)]
enum Rval {
    Dec(String),
    Hex(String),
    Str(String),
    // Btf,
}

impl Rval {
    fn from_str(rval: &str) -> Result<Rval> {
        let detected = if (rval.starts_with('"') && rval.ends_with('"'))
            || (rval.starts_with('\'') && rval.ends_with('\''))
        {
            Rval::Str(rval[1..rval.len() - 1].to_string())
        } else {
            let base = if rval.starts_with("0x") {
                Rval::Hex(rval.trim_start_matches("0x").to_string())
            } else {
                Rval::Dec(rval.to_string())
            };

            base
        };

        Ok(detected)
    }
}

#[derive(Clone)]
pub(crate) struct FilterMeta(pub(crate) Vec<MetaOp>);

impl FilterMeta {
    fn check_one_walkable(t: &Type, ind: &mut u8, casted: bool) -> Result<bool> {
        match t {
            Type::Int(i)
                if i.size() == std::mem::size_of::<*const std::ffi::c_void>() && casted =>
            {
                *ind += 1
            }
            Type::Ptr(_) => *ind += 1,
            Type::Struct(_) | Type::Union(_) => {
                return Ok(true);
            }
            Type::Typedef(_)
            | Type::Volatile(_)
            | Type::Const(_)
            | Type::Restrict(_)
            | Type::DeclTag(_)
            | Type::TypeTag(_) => (),
            _ => bail!(
                "unexpected type ({}) while walking struct members",
                t.name()
            ),
        };

        Ok(false)
    }

    // Return all comparable and walkable types Ptr, Int, Array, Enum[64],
    // Struct, Union
    fn next_walkable(btf: &Btf, r#type: Type, casted: bool) -> Result<(u8, Type)> {
        let btf_type = r#type.as_btf_type();
        let mut ind = 0;

        // Return early if r#type is already walkable
        if Self::check_one_walkable(&r#type, &mut ind, casted)? {
            return Ok((0, r#type));
        } else if casted {
            return Ok((ind, r#type));
        }

        let btf_type = btf_type.ok_or_else(|| {
            anyhow!("cannot convert to iterable type while retrieving next walkable")
        })?;

        for x in btf.type_iter(btf_type) {
            if Self::check_one_walkable(&x, &mut ind, casted)? {
                return Ok((ind, x));
            }
        }

        bail!("failed to retrieve next walkable object.")
    }

    fn parse_mask(el: &str) -> Result<u64> {
        let (el, not) = match el.strip_prefix('~') {
            Some(num) => (num, true),
            None => (el, false),
        };

        let (base, mask_str) = if let Some(hex) = el.strip_prefix("0x") {
            (16, hex)
        } else if let Some(bin) = el.strip_prefix("0b") {
            (2, bin)
        } else {
            (10, el)
        };

        let mut mask = u64::from_str_radix(mask_str, base).map_err(|_| {
            anyhow!(
                "invalid mask. Use an hex, binary or decimal mask (0x<hex>, 0b<bin>, <decimal>)"
            )
        })?;

        mask = if not { !mask } else { mask };
        if mask == 0 {
            bail!("mask cannot be zero");
        }

        Ok(mask)
    }

    // Parse (in a very simple way) the filter string splitting it
    // into rhs op and lhs.
    // Requires spaces as separator among elements.
    fn parse_filter(filter: &str) -> Result<(Vec<LhsNode>, MetaCmp, &str)> {
        let expr = filter.split(' ').collect::<Vec<_>>();

        let [lhs, op, rhs]: [&str; 3] = match expr.len() {
            3 => expr
                .try_into()
                .map_err(|_| anyhow!("cannot split filter ({filter})"))?,
            1 => [expr[0], "!=", "0"],
            _ => bail!("invalid filter ({filter})"),
        };

        let lhs: Vec<_> = lhs
            .split('.')
            .enumerate()
            .map(|x| {
                let first = x.0 == 0;
                let mut elem = x.1.split(':');
                // member is mandatory.
                let member = elem.next().ok_or_else(|| anyhow!("member is mandatory"))?;

                if first && member != "sk_buff" {
                    bail!("starting struct isn't supported (not sk_buff)");
                }
                // mask is optional and must be a number.
                // Can be under the form [~]{hex, bin, dec}
                let mask = if let Some(el) = elem.next() {
                    if first {
                        bail!("initial type must be a base type only");
                    }
                    Self::parse_mask(el)?
                } else {
                    0x0
                };

                // tgt_type is optional.
                let tgt_type = elem.next();

                if elem.next().is_some() {
                    bail!(
                        "unexpected field expression (must be under the form field[:mask[:type]])"
                    );
                }

                Ok(LhsNode {
                    member,
                    mask,
                    tgt_type,
                })
            })
            .collect::<Result<Vec<LhsNode<'_>>>>()?;

        if lhs.len() <= 1 {
            bail!("expression does not point to a member");
        }

        Ok((lhs, MetaCmp::from_str(op)?, rhs))
    }

    pub(crate) fn from_string(fstring: String) -> Result<Self> {
        let btf_info = &inspector()?.kernel.btf;
        let mut ops: Vec<_> = Vec::new();
        let mut offt: u32 = 0;
        let mut stored_offset: u32 = 0;
        let mut stored_bf_size: u32 = 0;
        let mut mask = 0;

        let (mut fields, op, rval) = Self::parse_filter(&fstring)?;

        // At least two elements are present
        let init_sym = fields.remove(0).member;

        let mut types = btf_info
            .resolve_types_by_name(init_sym)
            .map_err(|e| anyhow!("unable to resolve sk_buff data type {e}"))?;

        let (mut btf, ref mut r#type) =
            match types.iter_mut().find(|(_, t)| matches!(t, Type::Struct(_))) {
                Some(r#struct) => r#struct,
                None => bail!("Could not resolve {init_sym} to a struct"),
            };

        for (pos, field) in fields.iter().enumerate() {
            let sub_node = walk_btf_node(btf, r#type, field.member, offt);
            match sub_node {
                Some((offset, bfs, snode)) => {
                    if pos < fields.len() - 1 {
                        // Type::Ptr needs indirect actions (Load *Ptr).
                        //   Offset need to be reset
                        // Named Structs or Union return (level matched) but are
                        //   still part of the parent Struct, so the offset has to
                        //   be preserved.
                        let (ind, x) = Self::next_walkable(btf, snode, field.tgt_type.is_some())?;
                        let one = 1;

                        match ind.cmp(&one) {
                            std::cmp::Ordering::Equal => {
                                offt = 0;
                                // Emit load Ptr
                                ops.push(MetaOp::emit_load_ptr(offset, field.mask)?);
                            }
                            std::cmp::Ordering::Greater => {
                                bail!("pointers of pointers are not supported")
                            }
                            _ => {
                                if field.mask != 0 {
                                    bail!("intermediate members masking is only supported for pointers and unsigned numbers");
                                }
                                offt = offset
                            }
                        }

                        if let Some(tgt) = field.tgt_type {
                            let mut types = btf_info
                                .resolve_types_by_name(tgt)
                                .map_err(|e| anyhow!("unable to resolve data type: {e}"))?;

                            (btf, *r#type) = match types.iter_mut().find(|(_, t)| {
                                matches!(t, Type::Union(_))
                                    || matches!(t, Type::Struct(_))
                                    || matches!(t, Type::Typedef(_))
                            }) {
                                Some((ref btf, r#type)) => {
                                    let nw = Self::next_walkable(btf, r#type.clone(), false)?;
                                    if nw.0 > 0 {
                                        bail!(
                                            "cast type ({tgt}: {}) cannot be an alias to a pointer",
                                            r#type.name()
                                        );
                                    }
                                    (btf, nw.1)
                                }
                                None => bail!("Could not resolve {tgt} to a struct or typedef"),
                            };
                        } else {
                            *r#type = x.clone();
                        }
                    } else {
                        if let Some(tgt) = field.tgt_type {
                            bail!("trying to cast a leaf member into {tgt}");
                        }

                        *r#type = snode;
                        mask = field.mask;
                    }

                    stored_offset = offset;
                    if let Some(bfs) = bfs {
                        stored_bf_size = bfs;
                    }
                }
                None => bail!("field {} not found in type {}", field.member, r#type.name()),
            }
        }

        let lmo = MetaOp::emit_load(btf, r#type, stored_offset, stored_bf_size, mask)?;
        ops.push(lmo);

        let rval = Rval::from_str(rval)?;

        ops.insert(0, MetaOp::emit_target(lmo.load_ref(), rval, op)?);
        Ok(FilterMeta(ops))
    }
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn init_meta_map() -> Result<libbpf_rs::MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: std::mem::size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };

    Ok(libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::Array,
        Some("filter_meta_map"),
        std::mem::size_of::<u32>() as u32,
        std::mem::size_of::<MetaOp>() as u32,
        META_OPS_MAX,
        &opts,
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

    #[test]
    fn meta_negative_generic() {
        // sk_buff is mandatory.
        assert!(FilterMeta::from_string("dev.mark == 0xc0de".to_string()).is_err());
        // unsupported type (struct)
        assert!(FilterMeta::from_string("sk_buff.dev == 0xbad".to_string()).is_err());
        // pointers to int are not supported
        assert!(FilterMeta::from_string("sk_buff.dev.pcpu_refcnt == 0xbad".to_string()).is_err());
    }

    #[test_case("==" ; "op is eq")]
    #[test_case("!=" ; "op is ne")]
    #[test_case("<" ; "op is lt")]
    #[test_case("<=" ; "op is le")]
    #[test_case(">" ; "op is gt")]
    #[test_case(">=" ; "op is ge")]
    fn meta_negative_filter_string(op_str: &'static str) {
        // Target string must be quoted.
        assert!(
            FilterMeta::from_string(format!("sk_buff.dev.name {op_str} dummy0").to_string())
                .is_err()
        );
        // Only MetaCmp::{Eq,Ne} are allowed for strings.
        if op_str != "==" && op_str != "!=" {
            assert!(FilterMeta::from_string(format!("sk_buff.dev.name {op_str} 'dummy0'")).is_err())
        }
        // Target value must be a string.
        assert!(FilterMeta::from_string("sk_buff.mark {op_str} 'dummy0'".to_string()).is_err());
    }

    #[test_case("==", MetaCmp::Eq ; "op is eq")]
    #[test_case("!=", MetaCmp::Ne ; "op is ne")]
    fn meta_filter_string(op_str: &'static str, op: MetaCmp) {
        let filter =
            FilterMeta::from_string(format!("sk_buff.dev.name {op_str} 'dummy0'").to_string())
                .unwrap();
        assert_eq!(filter.0.len(), 3);
        let meta_load = &filter.0[1].load_ref();
        assert!(!meta_load.is_num());
        assert!(!meta_load.is_arr());
        assert!(meta_load.is_ptr());
        assert_eq!(meta_load.offt, 16);

        let meta_load = &filter.0[2].load_ref();
        assert!(!meta_load.is_ptr());
        assert!(meta_load.is_byte());
        assert_eq!(meta_load.nmemb, 16);
        assert_eq!(meta_load.offt, 0);

        let meta_target = &filter.0[0].target_ref();
        assert_eq!(meta_target.cmp, op as u8);
        assert_eq!(meta_target.sz, 6);
        let target_str = std::str::from_utf8(&meta_target.md)
            .unwrap()
            .trim_end_matches(char::from(0));
        assert_eq!(target_str, "dummy0");
    }

    #[test]
    fn meta_negative_filter_u32() {
        assert!(FilterMeta::from_string("sk_buff.mark == -1".to_string()).is_err());
        // u32::MAX + 1 is an allowed value for u32 (user has to specify values inside the range).
        assert!(FilterMeta::from_string("sk_buff.mark == 4294967296".to_string()).is_ok());
    }

    #[test_case("==", MetaCmp::Eq ; "op is eq")]
    #[test_case("!=", MetaCmp::Ne ; "op is ne")]
    #[test_case("<", MetaCmp::Lt ; "op is lt")]
    #[test_case("<=", MetaCmp::Le ; "op is le")]
    #[test_case(">", MetaCmp::Gt ; "op is gt")]
    #[test_case(">=", MetaCmp::Ge ; "op is ge")]
    fn meta_filter_u32(op_str: &'static str, op: MetaCmp) {
        let filter =
            FilterMeta::from_string(format!("sk_buff.mark {op_str} 0xc0de").to_string()).unwrap();
        assert_eq!(filter.0.len(), 2);
        let meta_load = filter.0[1].load_ref();
        assert!(!meta_load.is_arr());
        assert!(!meta_load.is_ptr());
        assert!(!meta_load.is_signed());
        assert!(meta_load.is_int());
        assert_eq!(meta_load.offt, 168);

        let meta_target = filter.0[0].target_ref();
        assert_eq!(meta_target.cmp, op as u8);
        assert_eq!(meta_target.sz, 4);
        let target = u64::from_ne_bytes(
            meta_target.md[..std::mem::size_of::<u64>()]
                .try_into()
                .unwrap(),
        );
        assert_eq!(target, 0xc0de);
    }

    #[test_case("==", MetaCmp::Eq ; "op is eq")]
    #[test_case("!=", MetaCmp::Ne ; "op is ne")]
    #[test_case("<", MetaCmp::Lt ; "op is lt")]
    #[test_case("<=", MetaCmp::Le ; "op is le")]
    #[test_case(">", MetaCmp::Gt ; "op is gt")]
    #[test_case(">=", MetaCmp::Ge ; "op is ge")]
    fn meta_filter_bitfields(op_str: &'static str, op: MetaCmp) {
        let filter =
            FilterMeta::from_string(format!("sk_buff.pkt_type {op_str} 1").to_string()).unwrap();
        assert_eq!(filter.0.len(), 2);
        let meta_load = filter.0[1].load_ref();
        assert!(!meta_load.is_arr());
        assert!(!meta_load.is_ptr());
        assert!(!meta_load.is_signed());
        assert!(meta_load.is_byte());
        assert_eq!(meta_load.bf_size, 3);
        // Offset in bits for bitfields
        assert_eq!(meta_load.offt, 1024);

        let meta_target = filter.0[0].target_ref();
        assert_eq!(meta_target.cmp, op as u8);
        assert_eq!(meta_target.sz, 1);
        let target = u64::from_ne_bytes(
            meta_target.md[..std::mem::size_of::<u64>()]
                .try_into()
                .unwrap(),
        );
        assert_eq!(target, 1);
    }

    // Only validates for what type of targets lhs-only expressions
    // are allowed. The offset extraction is not required as it is
    // already performed by previous tests.
    #[test_case("dev" => matches Err(_); "pointer")]
    #[test_case("dev.name" => matches Err(_); "string failure")]
    #[test_case("headers" => matches Err(_); "named struct failure")]
    #[test_case("mark" => matches Ok(_); "u32")]
    #[test_case("headers.skb_iif" => matches Ok(_); "signed int")]
    #[test_case("cloned" => matches Ok(_); "unsigned bitfield")]
    fn meta_filter_lhs_only(field: &'static str) -> Result<()> {
        let filter = FilterMeta::from_string(format!("sk_buff.{field}").to_string())?;
        let meta_target = filter.0[0].target_ref();

        assert_eq!(meta_target.cmp, MetaCmp::Ne as u8);
        assert!(meta_target.md.iter().all(|&x| x == 0));

        Ok(())
    }

    #[test_case("dev.name:~0x00" => matches Err(_); "string failure")]
    #[test_case("dev:~0x00.mtu" => matches Ok(l) if l == MetaLoad { r#type: PTR_BIT, nmemb: 0, offt: 16, bf_size: 0, mask: !0x00 }; "pointer")]
    #[test_case("mark:0xff" => matches Ok(l) if l == MetaLoad { r#type: MetaType::Int as u8, nmemb: 0, offt: 168, bf_size: 0, mask: 0xff }; "u32")]
    #[test_case("mark:0x0" => matches Err(_); "zero hex mask failure")]
    #[test_case("mark:~0xffffffffffffffff" => matches Err(_); "bitwise not u64 hex mask failure")]
    #[test_case("mark:0b00" => matches Err(_); "zero bin mask failure")]
    #[test_case("mark:0" => matches Err(_); "mask format failure")]
    #[test_case("headers.skb_iif:0xbad" => matches Err(_); "signed int failure")]
    #[test_case("pkt_type:0x2" => matches Ok(l) if l == MetaLoad { r#type: MetaType::Char as u8, nmemb: 0, offt: 1024, bf_size: 3, mask: 0x2 }; "unsigned bitfield")]
    #[test_case("pkt_type:0b10" => matches Ok(l) if l == MetaLoad { r#type: MetaType::Char as u8, nmemb: 0, offt: 1024, bf_size: 3, mask: 0x2 }; "binary unsigned bitfield")]
    #[test_case("pkt_type:~0b10" => matches Ok(l) if l == MetaLoad { r#type: MetaType::Char as u8, nmemb: 0, offt: 1024, bf_size: 3, mask: !0x2 }; "bitwise not binary unsigned bitfield")]
    fn meta_filter_masks(expr: &'static str) -> Result<MetaLoad> {
        let filter = FilterMeta::from_string(format!("sk_buff.{expr}").to_string())?;

        Ok(filter.0[1].load_ref().clone())
    }

    #[test]
    fn meta_filter_cast() {
        // Casting a field smaller than a pointer is not allowed
        assert!(
            FilterMeta::from_string(format!("sk_buff.cloned:~0x0:nf_conn").to_string()).is_err()
        );
        assert!(FilterMeta::from_string(format!("sk_buff.len:~0x0:nf_conn").to_string()).is_err());
        assert!(
            FilterMeta::from_string(format!("sk_buff.mac_len:~0x0:nf_conn").to_string()).is_err()
        );
        // Arrays cannot be casted
        assert!(FilterMeta::from_string(format!("sk_buff.cb:~0x0:nf_conn").to_string()).is_err());
        // Cast to non-walkable types is not allowed
        assert!(
            FilterMeta::from_string(format!("sk_buff._nfct:~0x0:u32.mark").to_string()).is_err()
        );
        // Casting a leaf is not allowed
        assert!(
            FilterMeta::from_string(format!("sk_buff._nfct.mark:~0x0:nf_conn").to_string())
                .is_err()
        );

        let filter =
            FilterMeta::from_string(format!("sk_buff._nfct:~0x0:nf_conn.mark").to_string())
                .unwrap();
        // Two for loads and one for the target
        assert_eq!(filter.0.len(), 3);
        let load = filter.0[1].load_ref();
        // '_nfct' type_id=? bits_offset=832
        assert_eq!(
            *load,
            MetaLoad {
                r#type: PTR_BIT,
                nmemb: 0,
                offt: 104,
                bf_size: 0,
                mask: !0
            }
        );
        // STRUCT 'nf_conn' size=248 vlen=14
        //   'mark' type_id=? bits_offset=1344
        let load = filter.0[2].load_ref();
        assert_eq!(
            *load,
            MetaLoad {
                r#type: MetaType::Int as u8,
                nmemb: 0,
                offt: 168,
                bf_size: 0,
                mask: 0
            }
        );
    }
}
