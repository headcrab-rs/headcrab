pub trait Thread {
    type ThreadId;

    fn name(&self) -> Option<String>;
    fn thread_id(&self) -> Self::ThreadId;
}
