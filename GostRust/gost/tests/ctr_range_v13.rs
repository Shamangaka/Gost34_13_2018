use gost::modes::{ctr, ctr_no_wrap, CtrRangeError};
use gost::qalqan::Cipher;

fn cipher(b: usize) -> Cipher {
    Cipher::new(&[0x42u8; 32], b).expect("valid test parameters")
}

#[test]
fn v13_matches_legacy_for_valid_range_all_block_sizes() {
    for blen in [16, 32, 64] {
        let c = cipher(blen);
        let iv = vec![0x33u8; blen];
        for len in [0, 1, blen - 1, blen, blen + 1, 3 * blen] {
            let mut expected = vec![0x55u8; len];
            let mut actual = expected.clone();
            ctr(&c, &iv, &mut expected).unwrap();
            ctr_no_wrap(&c, &iv, &mut actual).unwrap();
            assert_eq!(actual, expected, "blen={blen} len={len}");
        }
    }
}

#[test]
fn v13_rejects_all_ff_iv_before_mutating_buffer() {
    for blen in [16, 32, 64] {
        let c = cipher(blen);
        let iv = vec![0xffu8; blen];
        let mut data = vec![0x65u8; 2 * blen];
        let before = data.clone();
        assert_eq!(ctr_no_wrap(&c, &iv, &mut data), Err(CtrRangeError::CounterExhausted));
        assert_eq!(data, before, "no partial output on rejected range");
    }
}

#[test]
fn v13_rejects_boundary_crossing_before_mutation() {
    for blen in [16, 32, 64] {
        let c = cipher(blen);
        let mut iv = vec![0xffu8; blen];
        iv[blen - 1] = 0xfe;
        let mut data = vec![0x61u8; 2 * blen];
        let before = data.clone();
        assert_eq!(ctr_no_wrap(&c, &iv, &mut data), Err(CtrRangeError::CounterExhausted));
        assert_eq!(data, before);
        // One block is permitted: last used counter is FF..FE,
        // then post-block increment yields FF..FF (not zero).
        let mut one = vec![0u8; blen];
        ctr_no_wrap(&c, &iv, &mut one).unwrap();
    }
}

#[test]
fn v13_accepts_last_available_two_blocks() {
    for blen in [16, 32, 64] {
        let c = cipher(blen);
        let mut iv = vec![0xffu8; blen];
        iv[blen - 1] = 0xfd;
        let mut expected = vec![7u8; 2 * blen];
        let mut actual = expected.clone();
        ctr(&c, &iv, &mut expected).unwrap();
        ctr_no_wrap(&c, &iv, &mut actual).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn v13_preserves_buffer_on_invalid_iv_length() {
    let c = cipher(16);
    let mut data = vec![0x33u8; 48];
    let before = data.clone();
    assert_eq!(ctr_no_wrap(&c, &[0u8; 15], &mut data), Err(CtrRangeError::IvLength));
    assert_eq!(data, before);
}

#[test]
fn v13_empty_message_is_no_op_even_at_boundary() {
    let c = cipher(16);
    let mut empty: [u8; 0] = [];
    ctr_no_wrap(&c, &[0xff; 16], &mut empty).unwrap();
}

#[test]
fn v13_remains_unauthenticated_and_allows_cross_call_overlap() {
    let c = cipher(16);
    let iv0 = [0u8; 16];
    let mut iv1 = [0u8; 16];
    iv1[15] = 1;
    let mut ct1 = [0x45u8; 32];
    let mut ct2 = [0x84u8; 16];
    ctr_no_wrap(&c, &iv0, &mut ct1).unwrap();
    ctr_no_wrap(&c, &iv1, &mut ct2).unwrap();
    // Guard is intentionally NOT advertised as IV-reuse protection.
    for j in 0..16 {
        assert_eq!(ct1[16+j] ^ ct2[j], 0x45 ^ 0x84);
    }
}
