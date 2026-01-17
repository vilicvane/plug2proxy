use crate::out::OutExitTag;

pub enum Route {
  Direct,
  Tag(OutExitTag),
  Proxy,
  Any,
}

impl Route {
  /// Lower the number, higher the priority.
  pub fn priority(&self) -> u8 {
    match self {
      Route::Direct => 0,
      Route::Tag(_) => 1,
      Route::Proxy => 2,
      Route::Any => 3,
    }
  }
}
