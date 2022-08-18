//! `ecc` implements constraints for ellictic curve operations

#![feature(trait_alias)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]

mod ecc;

/// Constraints for the SW curve that are used in the same proof system
mod base_field_ecc;
/// Constaints for any SW curve
mod general_ecc;

pub use crate::ecc::*;
pub use base_field_ecc::*;
pub use general_ecc::*;

pub use integer;
pub use integer::halo2;
pub use integer::maingate;

#[cfg(test)]
use halo2::halo2curves as curves;
