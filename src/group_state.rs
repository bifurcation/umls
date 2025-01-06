use crate::common::*;
use crate::io::*;
use crate::syntax::*;
use crate::{mls_struct, mls_struct_serialize};

mls_struct! {
    GroupState + GroupStateView,
    dummy: Nil + NilView,
}
