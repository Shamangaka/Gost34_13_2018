//! Regression checks for safe public APIs formerly using unchecked raw pointers.
//! Run after the safety patch, not against the original unsafe implementations.
#![allow(non_snake_case)]
use gost::qalqan::{AddRk, sBox, sBoxU};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn sboxu_agrees_with_safe_sbox() {
    let input: Vec<u8> = (0u8..=255).collect();
    let mut regular = [0u8; 256];
    let mut checked = [0u8; 256];
    sBox(&input, &mut regular, 256);
    sBoxU(&input, &mut checked, 256);
    assert_eq!(checked, regular);
}

#[test]
fn sboxu_short_input_panics_safely() {
    let input = [0u8; 1];
    let mut output = [0u8; 2];
    assert!(catch_unwind(AssertUnwindSafe(|| sBoxU(&input, &mut output, 2))).is_err());
}

#[test]
fn sboxu_short_output_panics_safely() {
    let input = [0u8; 2];
    let mut output = [0u8; 1];
    assert!(catch_unwind(AssertUnwindSafe(|| sBoxU(&input, &mut output, 2))).is_err());
}

#[test]
fn addrk_carry_matches_modular_addition() {
    let input = [255u8, 0, 0];
    let rk = [1u8, 0, 0];
    let mut output = [0u8; 3];
    AddRk(&input, &rk, 0, 3, &mut output);
    assert_eq!(output, [0, 1, 0]);
}

#[test]
fn addrk_short_input_panics_safely() {
    let input = [0u8; 1];
    let rk = [0u8; 2];
    let mut output = [0u8; 2];
    assert!(catch_unwind(AssertUnwindSafe(|| AddRk(&input, &rk, 0, 2, &mut output))).is_err());
}

#[test]
fn addrk_short_output_panics_safely() {
    let input = [0u8; 2];
    let rk = [0u8; 2];
    let mut output = [0u8; 1];
    assert!(catch_unwind(AssertUnwindSafe(|| AddRk(&input, &rk, 0, 2, &mut output))).is_err());
}

#[test]
fn addrk_short_round_key_panics_safely() {
    let input = [0u8; 2];
    let rk = [0u8; 1];
    let mut output = [0u8; 2];
    assert!(catch_unwind(AssertUnwindSafe(|| AddRk(&input, &rk, 0, 2, &mut output))).is_err());
}

#[test]
fn addrk_round_offset_overflow_panics_safely() {
    let input = [0u8; 2];
    let rk = [0u8; 2];
    let mut output = [0u8; 2];
    assert!(catch_unwind(AssertUnwindSafe(|| AddRk(&input, &rk, usize::MAX, 2, &mut output))).is_err());
}

#[test]
fn addrk_round_out_of_bounds_panics_safely() {
    let input = [0u8; 2];
    let rk = [0u8; 2];
    let mut output = [0u8; 2];
    assert!(catch_unwind(AssertUnwindSafe(|| AddRk(&input, &rk, 1, 2, &mut output))).is_err());
}
