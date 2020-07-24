use std::sync::Once;

static TESTEES_BUILD: Once = Once::new();

/// Ensure that all testees are built.
pub fn ensure_testees() {
    TESTEES_BUILD.call_once(|| {
        let status = std::process::Command::new("make")
            .current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/testees"))
            .spawn()
            .unwrap()
            .wait()
            .unwrap();
        assert!(status.success());
    });
}
