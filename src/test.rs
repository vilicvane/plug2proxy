use std::path::PathBuf;

pub fn test_dir() -> PathBuf {
  let test_dir = PathBuf::from(".test");

  std::fs::create_dir_all(&test_dir).unwrap();

  test_dir
}
