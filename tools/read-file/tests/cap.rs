//! DESIGN: read-file copies at most 64 MiB per file. A 64 MiB + 7 byte file yields exactly 64 MiB.
use std::process::Command;
#[test]
fn caps_each_file_at_64_mib() {
    let cap = 64usize << 20;
    let dir = std::env::temp_dir().join(format!("read-file-cap-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (big, small) = (dir.join("big"), dir.join("small"));
    std::fs::write(&big, vec![b'a'; cap + 7]).unwrap();
    std::fs::write(&small, vec![b'b'; cap]).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_read-file")).arg(&big).output().unwrap();
    assert_eq!(out.stdout.len(), cap);
    let out = Command::new(env!("CARGO_BIN_EXE_read-file")).arg(&small).output().unwrap();
    assert_eq!(out.stdout.len(), cap);
    assert!(out.status.success());
    std::fs::remove_dir_all(&dir).unwrap();
}
