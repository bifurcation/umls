// TODO(RLB): Replace with an enum
#[derive(Debug)]
pub struct Error(pub &'static str);

pub type Result<T> = core::result::Result<T, Error>;
