/// This is a naive stack unwinder that returns all words that could be interpreted as return
/// address for a known function.
pub fn naive_unwinder<'a>(debuginfo: &'a super::RelocatedDwarf, stack: &'a [usize]) -> impl Iterator<Item = usize> + 'a {
    stack.iter().cloned().filter(move |addr| debuginfo.get_address_symbol_kind(*addr) == Some(object::SymbolKind::Text))
}
