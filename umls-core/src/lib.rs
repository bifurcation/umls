#![no_std]
#![deny(warnings)] // We should be warnings-clear
#![warn(clippy::pedantic)] // Be pedantic by default
#![allow(clippy::missing_errors_doc)] // TODO
#![allow(clippy::missing_panics_doc)] // TODO
#![allow(clippy::cast_possible_truncation)] // TODO
#![allow(clippy::len_without_is_empty)] // N/A

pub mod common;
pub mod crypto;
pub mod io;
pub mod protocol;
pub mod stack;
pub mod syntax;
pub mod tree_math;
pub mod treekem;
