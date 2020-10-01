use std::convert::TryFrom;
use std::fmt;

use super::dwarf_utils::SearchAction;
use super::*;

pub struct Frame<'a> {
    dwarf: &'a gimli::Dwarf<Reader<'a>>,
    unit: Option<&'a gimli::Unit<Reader<'a>>>,
    frame: addr2line::Frame<'a, Reader<'a>>,
}

impl<'a> Frame<'a> {
    pub fn function_debuginfo(
        &self,
    ) -> Option<(
        &'a gimli::Dwarf<Reader<'a>>,
        &'a gimli::Unit<Reader<'a>>,
        gimli::UnitOffset<usize>,
    )> {
        self.frame
            .dw_die_offset
            .map(|unit_offset| (self.dwarf, self.unit.unwrap(), unit_offset))
    }

    pub fn print_debuginfo(&self) {
        println!(
            "{}:",
            self.frame
                .function
                .as_ref()
                .map(|name| name.raw_name().unwrap().into_owned())
                .unwrap_or_else(|| "<unknown name>".to_owned())
        );
        if let Some((_dwarf, unit, dw_die_offset)) = self.function_debuginfo() {
            let _: Option<()> =
                dwarf_utils::search_tree(unit, Some(dw_die_offset), |entry, indent| {
                    if entry.tag() == gimli::DW_TAG_inlined_subroutine
                        && entry.offset() != dw_die_offset
                    {
                        return Ok(SearchAction::SkipChildren); // Already visited by addr2line frame iter
                    }

                    println!("{:indent$}{}", "", entry.tag(), indent = indent * 2);

                    let mut attrs = entry.attrs();
                    while let Some(attr) = attrs.next()? {
                        println!("{:indent$}{}", "", attr.name(), indent = indent * 2 + 2);
                    }

                    Ok(SearchAction::VisitChildren)
                })
                .map_err(|e: Box<dyn std::error::Error + Send + Sync>| e)
                .unwrap();
        } else {
            println!("no dwarf entry for function");
        }
    }

    pub fn each_argument<
        C: super::dwarf_utils::EvalContext,
        F: Fn(Local<'_, 'a>) -> CrabResult<()>,
    >(
        &self,
        eval_ctx: &C,
        addr: u64,
        f: F,
    ) -> CrabResult<()> {
        let (dwarf, unit, dw_die_offset) = self
            .function_debuginfo()
            .ok_or_else(|| "No dwarf debuginfo for function".to_owned())?;

        dwarf_utils::search_tree(unit, Some(dw_die_offset), |entry, _indent| {
            if entry.offset() == dw_die_offset {
                return Ok(SearchAction::VisitChildren);
            }

            if entry.tag() == gimli::DW_TAG_formal_parameter {
                f(Local::from_entry(dwarf, unit, entry, eval_ctx, addr)?)?;
            }

            Ok(SearchAction::SkipChildren)
        })
        .map(|_: Option<()>| ())
    }

    pub fn each_local<
        C: super::dwarf_utils::EvalContext,
        F: Fn(Local<'_, 'a>) -> CrabResult<()>,
    >(
        &self,
        eval_ctx: &C,
        addr: u64,
        f: F,
    ) -> CrabResult<()> {
        let (dwarf, unit, dw_die_offset) = self
            .function_debuginfo()
            .ok_or_else(|| "No dwarf debuginfo for function".to_owned())?;
        dwarf_utils::search_tree(unit, Some(dw_die_offset), |entry, _indent| {
            if entry.tag() == gimli::DW_TAG_inlined_subroutine && entry.offset() != dw_die_offset {
                return Ok(SearchAction::SkipChildren); // Already visited by addr2line frame iter
            }

            if entry.tag() == gimli::DW_TAG_lexical_block {
                if !super::dwarf_utils::in_range(dwarf, &unit, Some(&entry), addr)? {
                    return Ok(SearchAction::SkipChildren);
                }
            }

            if entry.tag() == gimli::DW_TAG_variable {
                f(Local::from_entry(dwarf, unit, entry, eval_ctx, addr)?)?;
            }

            Ok(SearchAction::VisitChildren)
        })
        .map(|_: Option<()>| ())
    }
}

pub struct Local<'a, 'ctx> {
    name: Option<Reader<'ctx>>,
    type_: gimli::DebuggingInformationEntry<'a, 'a, Reader<'ctx>>,
    value: LocalValue<'ctx>,
}

impl fmt::Debug for Local<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Local")
            .field(
                "name",
                &self
                    .name
                    .as_ref()
                    .and_then(|n| n.to_slice().ok())
                    .as_deref()
                    .map(String::from_utf8_lossy),
            )
            .field("type_", &"...")
            .field("values", &self.value)
            .finish()
    }
}

#[derive(Debug)]
pub enum LocalValue<'ctx> {
    Pieces(Vec<gimli::Piece<Reader<'ctx>>>),
    Const(u64),
    OptimizedOut,
    Unknown,
}

impl<'ctx> LocalValue<'ctx> {
    pub fn primitive_value(
        &self,
        ty: &gimli::DebuggingInformationEntry<'_, '_, Reader<'ctx>>,
        eval_ctx: &impl super::dwarf_utils::EvalContext,
    ) -> CrabResult<Option<PrimitiveValue>> {
        match ty.tag() {
            gimli::DW_TAG_base_type => {
                let size = dwarf_attr!(udata ty.DW_AT_byte_size || error);
                let encoding = dwarf_attr!(encoding ty.DW_AT_encoding || error);
                match encoding {
                    gimli::DW_ATE_unsigned | gimli::DW_ATE_signed => {
                        let size = u8::try_from(size).map_err(|_| {
                            format!("`{}` is too big for DW_ATE_unsigned or DW_ATE_signed", size,)
                        })?;
                        let data = match self {
                            LocalValue::Pieces(pieces) => {
                                if pieces.len() != 1 {
                                    return Err("too many pieces for an integer value".into());
                                }

                                if pieces[0].size_in_bits.is_none()
                                    || pieces[0].size_in_bits.unwrap() == u64::from(size) * 8
                                {
                                } else {
                                    return Err(
                                        format!("wrong size for piece {:?}", pieces[0]).into()
                                    );
                                }
                                // FIXME handle this
                                assert!(
                                    pieces[0].bit_offset.is_none(),
                                    "unhandled bit_offset for piece {:?}",
                                    pieces[0]
                                );

                                let value = match &pieces[0].location {
                                    gimli::Location::Empty => {
                                        return Err("found empty piece for an integer value".into())
                                    }
                                    gimli::Location::Register { register } => {
                                        eval_ctx.register(
                                            *register,
                                            gimli::ValueType::Generic, /* FIXME */
                                        )
                                    }
                                    gimli::Location::Address { address } => eval_ctx.memory(
                                        *address,
                                        size,
                                        None,
                                        gimli::ValueType::Generic, /* FIXME */
                                    ),
                                    gimli::Location::Value { value } => *value,
                                    gimli::Location::Bytes { value: _ } => todo!(),
                                    gimli::Location::ImplicitPointer {
                                        value: _,
                                        byte_offset: _,
                                    } => {
                                        return Err(
                                            "found implicit pointer for an integer value".into()
                                        )
                                    }
                                };
                                match value {
                                    gimli::Value::Generic(data) => data,
                                    gimli::Value::I8(data) => data as u64,
                                    gimli::Value::U8(data) => data as u64,
                                    gimli::Value::I16(data) => data as u64,
                                    gimli::Value::U16(data) => data as u64,
                                    gimli::Value::I32(data) => data as u64,
                                    gimli::Value::U32(data) => data as u64,
                                    gimli::Value::I64(data) => data as u64,
                                    gimli::Value::U64(data) => data,
                                    gimli::Value::F32(_) | gimli::Value::F64(_) => {
                                        return Err("found float piece for an integer value".into())
                                    }
                                }
                            }
                            LocalValue::Const(data) => *data,
                            LocalValue::OptimizedOut => return Ok(None),
                            LocalValue::Unknown => return Ok(None),
                        };
                        Ok(Some(PrimitiveValue::Int {
                            size,
                            signed: encoding == gimli::DW_ATE_signed,
                            data,
                        }))
                    }
                    _ => todo!("{:?}", encoding),
                }
            }
            gimli::DW_TAG_structure_type => Ok(None),
            tag => todo!("{:?}", tag),
        }
    }
}

pub enum PrimitiveValue {
    Int { size: u8, signed: bool, data: u64 },
    Float { is_64: bool, data: u64 },
}

impl<'a, 'ctx> Local<'a, 'ctx> {
    pub fn from_entry<C: super::dwarf_utils::EvalContext>(
        dwarf: &'a gimli::Dwarf<Reader<'ctx>>,
        unit: &'a gimli::Unit<Reader<'ctx>>,
        entry: gimli::DebuggingInformationEntry<'a, 'a, Reader<'ctx>>,
        eval_ctx: &C,
        addr: u64,
    ) -> CrabResult<Self> {
        let origin_entry = if let Some(origin) = entry.attr(gimli::DW_AT_abstract_origin)? {
            let origin = match origin.value() {
                gimli::AttributeValue::UnitRef(offset) => offset,
                _ => panic!("{:?}", origin.value()),
            };
            unit.entry(origin)?
        } else {
            entry.clone()
        };

        let name = dwarf_attr!(str(dwarf,unit) origin_entry.DW_AT_name || None);

        let type_ = unit.entry(dwarf_attr!(unit_ref origin_entry.DW_AT_type || error))?;

        let value = if let Some(loc) = entry.attr(gimli::DW_AT_location)? {
            match loc.value() {
                gimli::AttributeValue::Exprloc(loc) => {
                    let pieces = super::dwarf_utils::evaluate_expression(unit, loc, eval_ctx)?;
                    LocalValue::Pieces(pieces)
                }
                gimli::AttributeValue::LocationListsRef(loc_list) => {
                    let mut loc_list = dwarf.locations(unit, loc_list)?;
                    let mut loc = None;
                    while let Some(entry) = loc_list.next()? {
                        if entry.range.begin <= addr && addr < entry.range.end {
                            loc = Some(entry.data);
                            break;
                        }
                    }
                    if let Some(loc) = loc {
                        let pieces = super::dwarf_utils::evaluate_expression(unit, loc, eval_ctx)?;
                        LocalValue::Pieces(pieces)
                    } else {
                        LocalValue::OptimizedOut
                    }
                }
                val => unreachable!("{:?}", val),
            }
        } else if let Some(const_val) = dwarf_attr!(udata entry.DW_AT_const_value || None) {
            LocalValue::Const(const_val)
        } else {
            LocalValue::Unknown
        };

        Ok(Local { name, type_, value })
    }

    pub fn name(&'a self) -> Result<Option<&'a str>, std::str::Utf8Error> {
        self.name
            .as_ref()
            .map(|name| std::str::from_utf8(name.bytes()))
            .transpose()
    }

    pub fn type_(&'a self) -> &'a gimli::DebuggingInformationEntry<'a, 'a, Reader<'ctx>> {
        &self.type_
    }

    pub fn value(&'a self) -> &'a LocalValue<'ctx> {
        &self.value
    }
}

pub struct FrameIter<'a> {
    pub(super) dwarf: &'a gimli::Dwarf<Reader<'a>>,
    pub(super) unit: Option<&'a gimli::Unit<Reader<'a>>>,
    pub(super) iter: addr2line::FrameIter<'a, Reader<'a>>,
}

impl<'a> FrameIter<'a> {
    pub fn next(&mut self) -> Result<Option<Frame<'a>>, gimli::Error> {
        Ok(self.iter.next()?.map(|frame| Frame {
            dwarf: self.dwarf,
            unit: self.unit,
            frame,
        }))
    }
}

impl<'a> std::ops::Deref for Frame<'a> {
    type Target = addr2line::Frame<'a, Reader<'a>>;

    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}
