//! This is a simple test to running a syscall in a child process.

mod test_utils;

#[cfg(target_os = "linux")]
use headcrab::{target::UnixTarget, CrabResult};

static BIN_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees/hello");

// FIXME: Running this test just for linux because of privileges issue on macOS. Enable for everything after fixing.
#[cfg(target_os = "linux")]
#[test]
fn syscall() -> CrabResult<()> {
    test_utils::ensure_testees();

    let target = test_utils::launch(BIN_PATH);

    println!(
        "{}\n",
        std::fs::read_to_string(format!("/proc/{}/maps", target.pid()))?
    );

    let len = 1 << 20;
    let addr = target
        .mmap(
            0 as *mut _,
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
            0,
            0,
        )
        .unwrap();

    assert!(target.memory_maps()?.iter().any(|map| map.address.0 == addr));

    for line in std::fs::read_to_string(format!("/proc/{}/maps", target.pid()))?.lines() {
        if line.starts_with(&format!("{:08x}-", addr)) {
            // Found mapped addr
            test_utils::continue_to_end(&target);

            // unmap the previously mapped memory
            // and check that it is no longer in the mapped memory list.
            target.munmap(addr as *mut _, len)?;
            assert!(target.memory_maps()?.iter().all(|map| map.address.0 != addr));

            return Ok(());
        }
    }

    panic!(
        "\n{}\n",
        std::fs::read_to_string(format!("/proc/{}/maps", target.pid()))?
    );
}
