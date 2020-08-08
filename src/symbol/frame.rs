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
                .map_err(|e: Box<dyn std::error::Error>| e)
                .unwrap();
        } else {
            println!("no dwarf entry for function");
        }
    }

    pub fn each_argument<
        E: From<gimli::Error> + From<String>,
        F: Fn(Local<'_, 'a>) -> Result<(), E>,
    >(
        &self,
        addr: u64,
        f: F,
    ) -> Result<(), E> {
        let (dwarf, unit, dw_die_offset) = self
            .function_debuginfo()
            .ok_or_else(|| "No dwarf debuginfo for function".to_owned())?;

        dwarf_utils::search_tree(unit, Some(dw_die_offset), |entry, _indent| {
            if entry.offset() == dw_die_offset {
                return Ok(SearchAction::VisitChildren);
            }

            if entry.tag() == gimli::DW_TAG_formal_parameter {
                f(Local::from_entry::<E>(dwarf, unit, entry, addr)?)?;
            }

            Ok(SearchAction::SkipChildren)
        })
        .map(|_: Option<()>| ())
    }

    pub fn each_local<
        E: From<gimli::Error> + From<String>,
        F: Fn(Local<'_, 'a>) -> Result<(), E>,
    >(
        &self,
        addr: u64,
        f: F,
    ) -> Result<(), E> {
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
                f(Local::from_entry::<E>(dwarf, unit, entry, addr)?)?;
            }

            Ok(SearchAction::VisitChildren)
        })
        .map(|_: Option<()>| ())
    }
}

pub struct Local<'a, 'ctx> {
    name: Option<Reader<'ctx>>,
    type_: Option<gimli::DebuggingInformationEntry<'a, 'a, Reader<'ctx>>>,
    value: LocalValue<'ctx>,
}

pub enum LocalValue<'ctx> {
    Expr(gimli::Expression<Reader<'ctx>>),
    Const(u64),
    OptimizedOut,
    Unknown,
}

impl<'a, 'ctx> Local<'a, 'ctx> {
    pub fn from_entry<E: From<gimli::Error> + From<String>>(
        dwarf: &'a gimli::Dwarf<Reader<'ctx>>,
        unit: &'a gimli::Unit<Reader<'ctx>>,
        entry: gimli::DebuggingInformationEntry<'a, 'a, Reader<'ctx>>,
        addr: u64,
    ) -> Result<Self, E> {
        let origin_entry = if let Some(origin) = entry.attr(gimli::DW_AT_abstract_origin)? {
            let origin = match origin.value() {
                gimli::AttributeValue::UnitRef(offset) => offset,
                _ => panic!("{:?}", origin.value()),
            };
            unit.entry(origin)?
        } else {
            entry.clone()
        };

        let name = origin_entry
            .attr(gimli::DW_AT_name)?
            .map(|name| {
                name.string_value(&dwarf.debug_str)
                    .ok_or_else(|| "Local name not a string".to_owned())
            })
            .transpose()?;

        let type_ = origin_entry
            .attr(gimli::DW_AT_type)?
            .map(|attr| match attr.value() {
                gimli::AttributeValue::UnitRef(type_) => Ok(type_),
                val => Err(format!(
                    "`{:?}` is not a valid value for a DW_AT_type attribute",
                    val
                )),
            })
            .transpose()?
            .map(|type_| unit.entry(type_))
            .transpose()?;

        let value = if let Some(loc) = entry.attr(gimli::DW_AT_location)? {
            match loc.value() {
                gimli::AttributeValue::Exprloc(loc) => LocalValue::Expr(loc),
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
                        LocalValue::Expr(loc)
                    } else {
                        LocalValue::OptimizedOut
                    }
                }
                val => unreachable!("{:?}", val),
            }
        } else if let Some(const_val) = entry.attr(gimli::DW_AT_const_value)? {
            LocalValue::Const(const_val.udata_value().unwrap())
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

    pub fn type_(&'a self) -> Option<&'a gimli::DebuggingInformationEntry<'a, 'a, Reader<'ctx>>> {
        self.type_.as_ref()
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
