//! Additional regression tests for total-block processing, checked offsets,
//! and failure-before-write behaviour of public low-level functions.
#![allow(non_snake_case)]
use gost::qalqan::{
    AddRk, AddRkX, InvAddRk, InvlinOp, InvsBox, Kexp, linOp, sBox,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn must_panic_unchanged<F>(mut output: Vec<u8>, work: F)
where F: FnOnce(&mut [u8]) {
    let before = output.clone();
    let err = catch_unwind(AssertUnwindSafe(|| work(&mut output)));
    assert!(err.is_err(), "expected controlled panic before partial processing");
    assert_eq!(output, before, "output was partially overwritten on failure");
}

#[test]
fn sbox_checks_input_and_does_not_modify_output() {
    must_panic_unchanged(vec![0xA5; 8], |out| sBox(&[1, 2, 3], out, 8));
}

#[test]
fn sbox_checks_output_and_does_not_modify_output() {
    must_panic_unchanged(vec![0xA5; 3], |out| sBox(&[1u8; 8], out, 8));
}

#[test]
fn inverse_sbox_checks_input_and_does_not_modify_output() {
    must_panic_unchanged(vec![0xA5; 8], |out| InvsBox(&[1u8; 7], out, 8));
}

#[test]
fn inverse_sbox_checks_output_and_does_not_modify_output() {
    must_panic_unchanged(vec![0xA5; 7], |out| InvsBox(&[1u8; 8], out, 8));
}

#[test]
fn direct_and_inverse_sbox_roundtrip_all_bytes() {
    let input: Vec<u8> = (0..=255).collect();
    let mut tmp = vec![0u8; 256];
    let mut back = vec![0u8; 256];
    sBox(&input, &mut tmp, 256);
    InvsBox(&tmp, &mut back, 256);
    assert_eq!(input, back);
}

#[test]
fn addrkx_properly_selects_nonzero_round() {
    let input = [0x11u8, 0x22, 0x33];
    let rounds = [0xFFu8, 0xFF, 0xFF, 0x10, 0x20, 0x30];
    let mut out = [0u8; 3];
    AddRkX(&input, &rounds, 1, 3, &mut out);
    assert_eq!(out, [0x01, 0x02, 0x03]);
}

#[test]
fn addrkx_short_input_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 3], |out| AddRkX(&[0u8; 2], &[0u8; 3], 0, 3, out));
}

#[test]
fn addrkx_short_output_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 2], |out| AddRkX(&[0u8; 3], &[0u8; 3], 0, 3, out));
}

#[test]
fn addrkx_short_round_key_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 3], |out| AddRkX(&[0u8; 3], &[0u8; 5], 1, 3, out));
}

#[test]
fn addrkx_overflow_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 3], |out| AddRkX(&[0u8; 3], &[0u8; 3], usize::MAX, 3, out));
}

#[test]
fn inverse_addrk_roundtrip_multi_byte_carries() {
    for blen in [1usize, 2, 16, 32, 64] {
        let block = vec![255u8; blen];
        let rk = vec![1u8; blen];
        let mut enc = vec![0u8; blen];
        let mut dec = vec![0u8; blen];
        AddRk(&block, &rk, 0, blen, &mut enc);
        InvAddRk(&enc, &rk, 0, blen, &mut dec);
        assert_eq!(dec, block);
    }
}

#[test]
fn inverse_addrk_short_input_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 8], |out| InvAddRk(&[0u8; 7], &[0u8; 8], 0, 8, out));
}

#[test]
fn inverse_addrk_short_output_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 7], |out| InvAddRk(&[0u8; 8], &[0u8; 8], 0, 8, out));
}

#[test]
fn inverse_addrk_short_round_key_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 8], |out| InvAddRk(&[0u8; 8], &[0u8; 15], 1, 8, out));
}

#[test]
fn inverse_addrk_overflow_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 8], |out| InvAddRk(&[0u8; 8], &[0u8; 8], usize::MAX, 8, out));
}

#[test]
fn linear_short_input_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 16], |out| linOp(&[0u8; 15], out, 16));
}

#[test]
fn linear_short_output_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 15], |out| linOp(&[0u8; 16], out, 16));
}

#[test]
fn inverse_linear_short_input_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 16], |out| InvlinOp(&[0u8; 15], out, 16));
}

#[test]
fn inverse_linear_short_output_panics_before_write() {
    must_panic_unchanged(vec![0xA5; 15], |out| InvlinOp(&[0u8; 16], out, 16));
}

#[test]
fn linear_valid_roundtrip_all_block_sizes() {
    for blen in [16usize, 32, 64] {
        let input: Vec<u8> = (0..blen).map(|x| x.wrapping_mul(7) as u8).collect();
        let mut temp = vec![0u8; blen];
        let mut back = vec![0u8; blen];
        linOp(&input, &mut temp, blen);
        InvlinOp(&temp, &mut back, blen);
        assert_eq!(back, input);
    }
}

#[test]
fn key_expansion_invalid_output_preserved() {
    let key = [0u8; 32];
    let mut out = vec![0xA5u8; 255]; // needs 16 * 16 = 256 bytes
    assert!(Kexp(&key, 32, 16, &mut out).is_err());
    assert!(out.iter().all(|&x| x == 0xA5));
}
