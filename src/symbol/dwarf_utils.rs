use gimli::{DebuggingInformationEntry, Dwarf, Unit};

use super::Reader;

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
    offset: Option<gimli::UnitOffset>,
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

pub fn evaluate_expression<'a>(
    unit: &gimli::Unit<Reader<'a>>,
    expr: gimli::Expression<Reader<'a>>,
    frame_base: Option<u64>,
    get_reg: impl Fn(gimli::Register, gimli::ValueType) -> gimli::Value,
) -> Result<Vec<gimli::Piece<Reader<'a>>>, Box<dyn std::error::Error>> {
    let mut eval = expr.evaluation(unit.encoding());
    let mut res = eval.evaluate()?;
    loop {
        match res {
            gimli::EvaluationResult::Complete => {
                return Ok(eval.result());
            }
            gimli::EvaluationResult::RequiresFrameBase => {
                res = eval.resume_with_frame_base(
                    frame_base.ok_or_else(|| "No frame base".to_owned())?,
                )?;
            }
            gimli::EvaluationResult::RequiresRegister {
                register,
                base_type,
            } => {
                let ty = if base_type.0 == 0 {
                    gimli::ValueType::Generic
                } else {
                    let base_type_die = unit.entry(base_type)?;
                    gimli::ValueType::from_entry(&base_type_die)?
                        .ok_or_else(|| "not a base type".to_owned())?
                };

                let val = get_reg(register, ty);
                res = eval.resume_with_register(val)?;
            }
            res => unimplemented!("{:?}", res),
        }
    }
}
