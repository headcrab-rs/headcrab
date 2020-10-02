use gimli::{DebuggingInformationEntry, Dwarf, Unit, UnitOffset, ValueType};

use super::Reader;
use crate::CrabResult;

macro_rules! dwarf_attr {
    (str($dwarf:ident,$unit:ident) $entry:ident.$name:ident || $missing:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            dwarf_attr_exists_action_action!($missing, $dwarf.attr_string(&$unit, attr.value())?)
        } else {
            dwarf_attr_missing_action!($missing, $name)
        }
    };
    (unit_ref $entry:ident.$name:ident || $missing:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            match attr.value() {
                gimli::AttributeValue::UnitRef(unit_ref) => {
                    dwarf_attr_exists_action_action!($missing, unit_ref)
                }
                val => {
                    return Err(format!(
                        "`{:?}` is not a valid value for a {} attribute",
                        val,
                        gimli::$name,
                    )
                    .into())
                }
            }
        } else {
            dwarf_attr_missing_action!($missing, $name)
        }
    };
    (udata $entry:ident.$name:ident || $missing:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            dwarf_attr_exists_action_action!(
                $missing,
                attr.udata_value()
                    .ok_or(concat!("invalid value for", stringify!($name)))?
            )
        } else {
            dwarf_attr_missing_action!($missing, $name)
        }
    };
    (encoding $entry:ident.$name:ident || $missing:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            match attr.value() {
                gimli::AttributeValue::Encoding(encoding) => {
                    dwarf_attr_exists_action_action!($missing, encoding)
                }
                encoding => {
                    return Err(
                        format!("invalid value for {}: {:?}", gimli::$name, encoding).into(),
                    )
                }
            }
        } else {
            dwarf_attr_missing_action!($missing, $name)
        }
    };
    ($entry:ident.$name:ident || $missing:ident) => {
        if let Some(attr) = $entry.attr(gimli::$name)? {
            dwarf_attr_exists_action_action!($missing, attr)
        } else {
            dwarf_attr_missing_action!($missing, $name)
        }
    };
}

macro_rules! dwarf_attr_exists_action_action {
    (continue, $val:expr) => {
        $val
    };
    (error, $val:expr) => {
        $val
    };
    (None, $val:expr) => {
        Some($val)
    };
}

macro_rules! dwarf_attr_missing_action {
    (continue, $name:ident) => {
        continue;
    };
    (error, $name:ident) => {
        return Err(concat!("missing ", stringify!($name), " attribute").into());
    };
    (None, $name:ident) => {
        None
    };
}

pub fn in_range(
    dwarf: &Dwarf<Reader>,
    unit: &Unit<Reader>,
    entry: Option<&DebuggingInformationEntry<Reader>>,
    addr: u64,
) -> gimli::Result<bool> {
    if let Some(entry) = entry {
        let mut ranges = dwarf.die_ranges(unit, entry)?;
        while let Some(range) = ranges.next()? {
            if range.begin <= addr && range.end > addr {
                return Ok(true);
            }
        }
    } else {
        let mut ranges = dwarf.unit_ranges(unit)?;
        while let Some(range) = ranges.next()? {
            if range.begin <= addr && range.end > addr {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

pub enum SearchAction<T> {
    #[allow(dead_code)] // FIXME
    Found(T),
    VisitChildren,
    SkipChildren,
}

pub fn search_tree<'a, 'dwarf, 'unit: 'dwarf, T, E: From<gimli::Error>>(
    unit: &'unit Unit<Reader<'a>>,
    offset: Option<UnitOffset>,
    mut f: impl FnMut(
        DebuggingInformationEntry<'dwarf, 'unit, Reader<'a>>,
        usize,
    ) -> Result<SearchAction<T>, E>,
) -> Result<Option<T>, E> {
    fn process_tree<'a, 'dwarf, 'unit: 'dwarf, T, E: From<gimli::Error>>(
        unit: &Unit<Reader<'a>>,
        node: gimli::EntriesTreeNode<'dwarf, 'unit, '_, Reader<'a>>,
        indent: usize,
        f: &mut impl FnMut(
            DebuggingInformationEntry<'dwarf, 'unit, Reader<'a>>,
            usize,
        ) -> Result<SearchAction<T>, E>,
    ) -> Result<Option<T>, E> {
        let entry = node.entry().clone();

        match f(entry, indent)? {
            SearchAction::Found(val) => Ok(Some(val)),
            SearchAction::VisitChildren => {
                let mut children = node.children();
                while let Some(child) = children.next()? {
                    // Recursively process a child.
                    if let Some(val) = process_tree(unit, child, indent + 1, f)? {
                        return Ok(Some(val));
                    }
                }
                Ok(None)
            }
            SearchAction::SkipChildren => Ok(None),
        }
    }

    let mut entries_tree = unit.entries_tree(offset)?;
    process_tree(unit, entries_tree.root()?, 0, &mut f)
}

pub trait EvalContext {
    fn frame_base(&self) -> u64;
    fn register(&self, register: gimli::Register, base_type: ValueType) -> gimli::Value;
    fn memory(
        &self,
        address: u64,
        size: u8,
        address_space: Option<u64>,
        base_type: ValueType,
    ) -> gimli::Value;
}

fn value_type_from_base_type(
    unit: &Unit<Reader<'_>>,
    base_type: UnitOffset,
) -> CrabResult<ValueType> {
    if base_type.0 == 0 {
        Ok(ValueType::Generic)
    } else {
        let base_type_die = unit.entry(base_type)?;
        Ok(ValueType::from_entry(&base_type_die)?.ok_or_else(|| "not a base type".to_owned())?)
    }
}

pub fn evaluate_expression<'a>(
    unit: &gimli::Unit<Reader<'a>>,
    expr: gimli::Expression<Reader<'a>>,
    eval_ctx: &impl EvalContext,
) -> CrabResult<Vec<gimli::Piece<Reader<'a>>>> {
    let mut eval = expr.evaluation(unit.encoding());
    let mut res = eval.evaluate()?;
    loop {
        match res {
            gimli::EvaluationResult::Complete => {
                return Ok(eval.result());
            }
            gimli::EvaluationResult::RequiresFrameBase => {
                res = eval.resume_with_frame_base(eval_ctx.frame_base())?;
            }
            gimli::EvaluationResult::RequiresRegister {
                register,
                base_type,
            } => {
                let ty = value_type_from_base_type(unit, base_type)?;
                res = eval.resume_with_register(eval_ctx.register(register, ty))?;
            }
            gimli::EvaluationResult::RequiresMemory {
                address,
                size,
                space,
                base_type,
            } => {
                let ty = value_type_from_base_type(unit, base_type)?;
                res = eval.resume_with_memory(eval_ctx.memory(address, size, space, ty))?;
            }
            gimli::EvaluationResult::RequiresTls(_addr) => todo!("TLS"),
            gimli::EvaluationResult::RequiresCallFrameCfa => todo!("CFA"),
            gimli::EvaluationResult::RequiresAtLocation(_expr_ref) => todo!("at location"),
            gimli::EvaluationResult::RequiresEntryValue(_expr) => {
                // FIXME implement this
                // See https://github.com/llvm/llvm-project/blob/895337647896edefda244c7afc4b71eab41ff850/lldb/source/Expression/DWARFExpression.cpp#L645-L687
                todo!("entry value");
            }
            gimli::EvaluationResult::RequiresParameterRef(_param_ref) => todo!("parameter ref"),
            gimli::EvaluationResult::RequiresRelocatedAddress(_addr) => todo!("relocated address"),
            gimli::EvaluationResult::RequiresIndexedAddress {
                index: _,
                relocate: _,
            } => todo!("indexed address"),
            gimli::EvaluationResult::RequiresBaseType(_base_type) => todo!("base type"),
        }
    }
}
