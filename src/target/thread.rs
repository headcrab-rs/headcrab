pub trait Thread {
    type ThreadId;

    fn name(&self) -> Result<Option<String>, Box<dyn std::error::Error>>;
    fn thread_id(&self) -> Self::ThreadId;
}
