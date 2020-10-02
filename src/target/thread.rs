pub trait Thread {
    type ThreadId;

    fn name(&self) -> crate::CrabResult<Option<String>>;
    fn thread_id(&self) -> Self::ThreadId;
}
