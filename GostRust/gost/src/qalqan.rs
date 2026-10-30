#![allow(non_snake_case)]
#![allow(dead_code)]

use zeroize::Zeroizing;

pub const SHIFT: i32 = 17;
pub const MINBLOCKLEN: i32 = 16;
pub const MAXBLOCKLEN: i32 = 64;
pub const MINKEYLEN: i32 = 32;
pub const MAXKEYLEN: i32 = 128;
pub const KEYLENSTEP: i32 = 16;

// SB and ISB hold the correct S and S^-1. Tables 1 and 3 of СТ РК 4009-2025
// misprint three cells each ("de", "ce", "1e" for dc, cc, 1c).
pub const SB: [u8; 256] = [
    /* ded: OK, dif: 4, dip: 7, lin: 32, pow: 7, cor: 0, dst: 112, sac: 116..140, cyc: 256 */
    0xd1, 0xb5, 0xa6, 0x74, 0x2f, 0xb2, 0x03, 0x77, 0xae, 0xb3, 0x60, 0x95, 0xfd, 0xf8, 0xc7, 0xf0,
    0x2b, 0xce, 0xa5, 0x91, 0x4c, 0x6f, 0xf3, 0x4f, 0x82, 0x01, 0x45, 0x76, 0x9f, 0xed, 0x41, 0xfb,
    0xac, 0x4e, 0x5e, 0x04, 0xeb, 0xf9, 0xf1, 0x3a, 0x1f, 0xe2, 0x8e, 0xe7, 0x85, 0x35, 0xdb, 0x52,
    0x78, 0xa1, 0xfc, 0xa2, 0xde, 0x68, 0x02, 0x4d, 0xf6, 0xdd, 0xcf, 0xa3, 0xdc, 0x6b, 0x81, 0x44,
    0x2a, 0x5d, 0x1e, 0xe0, 0x53, 0x71, 0x3b, 0xc1, 0xcc, 0x9d, 0x80, 0xd5, 0x84, 0x00, 0x24, 0x4b,
    0xb6, 0x83, 0x0d, 0x87, 0x7e, 0x86, 0xca, 0x96, 0xbe, 0x5a, 0xe6, 0xd0, 0xd4, 0xd8, 0x55, 0xc0,
    0x05, 0xe5, 0xe9, 0x5b, 0x47, 0xe4, 0x2d, 0x34, 0x13, 0x88, 0x48, 0x32, 0x38, 0xb9, 0xda, 0xc9,
    0x42, 0x29, 0xd7, 0xf2, 0x9b, 0x6d, 0xe8, 0x8d, 0x12, 0x7c, 0x8c, 0x3f, 0xbc, 0x3c, 0x1b, 0xc5,
    0x69, 0x22, 0x97, 0xaa, 0x73, 0x0a, 0x0c, 0x8a, 0x90, 0x31, 0xc4, 0x33, 0xe1, 0x8b, 0x9c, 0x63,
    0x5f, 0xf5, 0xf7, 0xff, 0x79, 0x49, 0xd3, 0xc6, 0x7b, 0x1a, 0x39, 0xc8, 0x6e, 0x72, 0xd9, 0xc3,
    0x62, 0x28, 0xbd, 0xbb, 0xfa, 0x2e, 0xbf, 0x43, 0x06, 0x0b, 0x7a, 0x64, 0x5c, 0x92, 0x37, 0x3d,
    0x66, 0x26, 0x51, 0xef, 0x0f, 0xa9, 0x14, 0x70, 0x16, 0x17, 0x10, 0x19, 0x93, 0x09, 0x59, 0x15,
    0xfe, 0x4a, 0xcb, 0x2c, 0xcd, 0xb8, 0x94, 0xab, 0xdf, 0xa7, 0x0e, 0x30, 0xaf, 0x56, 0x23, 0xb1,
    0xb0, 0x58, 0x7d, 0xc2, 0x1d, 0x50, 0x20, 0x61, 0x25, 0x89, 0xa0, 0x6c, 0x11, 0x54, 0x98, 0xb7,
    0x18, 0x21, 0xad, 0x3e, 0xd2, 0xea, 0x40, 0xd6, 0xf4, 0xa4, 0x8f, 0xa8, 0x08, 0x57, 0xba, 0xee,
    0x75, 0x6a, 0x07, 0x99, 0x7f, 0x1c, 0xe3, 0x46, 0x67, 0xec, 0x27, 0x36, 0xb4, 0x65, 0x9e, 0x9a,
];

pub const ISB: [u8; 256] = [
    0x4d, 0x19, 0x36, 0x06, 0x23, 0x60, 0xa8, 0xf2, 0xec, 0xbd, 0x85, 0xa9, 0x86, 0x52, 0xca, 0xb4,
    0xba, 0xdc, 0x78, 0x68, 0xb6, 0xbf, 0xb8, 0xb9, 0xe0, 0xbb, 0x99, 0x7e, 0xf5, 0xd4, 0x42, 0x28,
    0xd6, 0xe1, 0x81, 0xce, 0x4e, 0xd8, 0xb1, 0xfa, 0xa1, 0x71, 0x40, 0x10, 0xc3, 0x66, 0xa5, 0x04,
    0xcb, 0x89, 0x6b, 0x8b, 0x67, 0x2d, 0xfb, 0xae, 0x6c, 0x9a, 0x27, 0x46, 0x7d, 0xaf, 0xe3, 0x7b,
    0xe6, 0x1e, 0x70, 0xa7, 0x3f, 0x1a, 0xf7, 0x64, 0x6a, 0x95, 0xc1, 0x4f, 0x14, 0x37, 0x21, 0x17,
    0xd5, 0xb2, 0x2f, 0x44, 0xdd, 0x5e, 0xcd, 0xed, 0xd1, 0xbe, 0x59, 0x63, 0xac, 0x41, 0x22, 0x90,
    0x0a, 0xd7, 0xa0, 0x8f, 0xab, 0xfd, 0xb0, 0xf8, 0x35, 0x80, 0xf1, 0x3d, 0xdb, 0x75, 0x9c, 0x15,
    0xb7, 0x45, 0x9d, 0x84, 0x03, 0xf0, 0x1b, 0x07, 0x30, 0x94, 0xaa, 0x98, 0x79, 0xd2, 0x54, 0xf4,
    0x4a, 0x3e, 0x18, 0x51, 0x4c, 0x2c, 0x55, 0x53, 0x69, 0xd9, 0x87, 0x8d, 0x7a, 0x77, 0x2a, 0xea,
    0x88, 0x13, 0xad, 0xbc, 0xc6, 0x0b, 0x57, 0x82, 0xde, 0xf3, 0xff, 0x74, 0x8e, 0x49, 0xfe, 0x1c,
    0xda, 0x31, 0x33, 0x3b, 0xe9, 0x12, 0x02, 0xc9, 0xeb, 0xb5, 0x83, 0xc7, 0x20, 0xe2, 0x08, 0xcc,
    0xd0, 0xcf, 0x05, 0x09, 0xfc, 0x01, 0x50, 0xdf, 0xc5, 0x6d, 0xee, 0xa3, 0x7c, 0xa2, 0x58, 0xa6,
    0x5f, 0x47, 0xd3, 0x9f, 0x8a, 0x7f, 0x97, 0x0e, 0x9b, 0x6f, 0x56, 0xc2, 0x48, 0xc4, 0x11, 0x3a,
    0x5b, 0x00, 0xe4, 0x96, 0x5c, 0x4b, 0xe7, 0x72, 0x5d, 0x9e, 0x6e, 0x2e, 0x3c, 0x39, 0x34, 0xc8,
    0x43, 0x8c, 0x29, 0xf6, 0x65, 0x61, 0x5a, 0x2b, 0x76, 0x62, 0xe5, 0x24, 0xf9, 0x1d, 0xef, 0xb3,
    0x0f, 0x26, 0x73, 0x16, 0xe8, 0x91, 0x38, 0x92, 0x0d, 0x25, 0xa4, 0x1f, 0x32, 0x0c, 0xc0, 0x93,
];

const C0: [u32; 3] = [1, 17, 14];
const C1: [u32; 7] = [3, 5, 11, 21, 16, 30, 19];
const C2: [u32; 7] = [4, 0, 22, 27, 47, 4, 61];

macro_rules! RNDS {
    ($x:expr) => {
        16 + ($x - 32) / 16
    };
}

pub(crate) use RNDS;

#[allow(non_snake_case)]
#[inline]
pub fn ROTL(x: u32, s: u32) -> u32 {
    x.rotate_left(s)
}

#[allow(non_snake_case)]
#[inline]
pub fn ROTL64(x: u64, s: u32) -> u64 {
    x.rotate_left(s)
}

/// Error for a key length other than 32..=128 bytes in steps of 16, a block
/// length other than 16, 32 or 64 bytes, or buffers that are too short.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParamError;

impl std::fmt::Display for ParamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("qalqan: key must be 32..128 bytes in steps of 16, block 16, 32 or 64 bytes")
    }
}

impl std::error::Error for ParamError {}

/// Key and block lengths in bytes allowed by section 5 of СТ РК 4009-2025.
pub fn valid_params(klen: usize, blen: usize) -> bool {
    (MINKEYLEN as usize..=MAXKEYLEN as usize).contains(&klen)
        && klen % KEYLENSTEP as usize == 0
        && matches!(blen, 16 | 32 | 64)
}

fn load32<const N: usize>(b: &[u8]) -> [u32; N] {
    std::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().unwrap()))
}

fn load64<const N: usize>(b: &[u8]) -> [u64; N] {
    std::array::from_fn(|i| u64::from_le_bytes(b[8 * i..8 * i + 8].try_into().unwrap()))
}

fn store32(b: &mut [u8], w: &[u32]) {
    for (i, x) in w.iter().enumerate() {
        b[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
}

fn store64(b: &mut [u8], w: &[u64]) {
    for (i, x) in w.iter().enumerate() {
        b[8 * i..8 * i + 8].copy_from_slice(&x.to_le_bytes());
    }
}

/// Formula (1): for i = 0..n-1 in order,
/// Word_i ^= XOR_{j=1}^{n-1} (Word_{(i+j) mod n} <<< C_{j-1}).
macro_rules! lin_fwd {
    ($w:expr, $c:expr) => {{
        let n = $w.len();
        for i in 0..n {
            let mut x = $w[i];
            for j in 1..n {
                x ^= $w[(i + j) % n].rotate_left($c[j - 1]);
            }
            $w[i] = x;
        }
    }};
}

/// Formula (2): the same updates for i = n-1, ..., 0.
macro_rules! lin_inv {
    ($w:expr, $c:expr) => {{
        let n = $w.len();
        for i in (0..n).rev() {
            let mut x = $w[i];
            for j in 1..n {
                x ^= $w[(i + j) % n].rotate_left($c[j - 1]);
            }
            $w[i] = x;
        }
    }};
}

fn lin334(din: &[u32; 4], dout: &mut [u32; 4]) {
    *dout = *din;
    lin_fwd!(dout, C0);
}

fn lin384(din: &[u32; 8], dout: &mut [u32; 8]) {
    *dout = *din;
    lin_fwd!(dout, C1);
}

fn lin388(din: &[u64; 8], dout: &mut [u64; 8]) {
    *dout = *din;
    lin_fwd!(dout, C2);
}

// The previous ilin334 used the shift constants in the wrong order for words
// 2 and 1, so L^-1 was not the inverse of L for 128-bit blocks.
fn ilin334(din: &[u32; 4], dout: &mut [u32; 4]) {
    *dout = *din;
    lin_inv!(dout, C0);
}

fn ilin384(din: &[u32; 8], dout: &mut [u32; 8]) {
    *dout = *din;
    lin_inv!(dout, C1);
}

fn ilin388(din: &[u64; 8], dout: &mut [u64; 8]) {
    *dout = *din;
    lin_inv!(dout, C2);
}

/// L (formula (1)) on little-endian words, as Appendix A requires. (The
/// previous version cast `&[u8]` to `&[u32]`/`&[u64]`, which is undefined
/// behaviour for unaligned buffers and depends on the host byte order.)
pub fn linOp(d: &[u8], r: &mut [u8], blocklen: usize) {
    assert!(matches!(blocklen, 16 | 32 | 64), "linOp: unsupported block length");
    assert!(d.len() >= blocklen, "linOp: input shorter than blocklen");
    assert!(r.len() >= blocklen, "linOp: output shorter than blocklen");
    match blocklen {
        16 => {
            let mut dout = [0u32; 4];
            lin334(&load32::<4>(d), &mut dout);
            store32(r, &dout);
        }
        32 => {
            let mut dout = [0u32; 8];
            lin384(&load32::<8>(d), &mut dout);
            store32(r, &dout);
        }
        64 => {
            let mut dout = [0u64; 8];
            lin388(&load64::<8>(d), &mut dout);
            store64(r, &dout);
        }
        _ => unreachable!(),
    }
}

#[allow(non_snake_case)]
/// Key expansion (section 8): writes RNDS(klen) * blen round-key bytes.
pub fn Kexp(key: &[u8], klen: usize, blen: usize, rkey: &mut [u8]) -> Result<(), ParamError> {
    if !valid_params(klen, blen) || key.len() < klen || rkey.len() < RNDS!(klen) * blen {
        return Err(ParamError);
    }
    let mut r0 = Zeroizing::new([0u8; 17]);
    let mut r1 = Zeroizing::new([0u8; 15]);
    for i in 0..15 {
        r0[i] = key[2 * i];
        r1[i] = key[2 * i + 1];
    }
    r0[15] = key[30];
    r0[16] = key[31];

    let addk = klen - 32;
    let mut step = 0usize;
    let mut prerun = SHIFT as usize;
    for round in 0..RNDS!(klen) {
        for k in 0..(blen + prerun) {
            let mut t0 = SB[r0[0] as usize]
                .wrapping_add(r0[1])
                .wrapping_add(SB[r0[3] as usize])
                .wrapping_add(r0[7])
                .wrapping_add(SB[r0[12] as usize])
                .wrapping_add(r0[16]);
            let mut t1 = SB[r1[0] as usize]
                .wrapping_add(r1[3])
                .wrapping_add(SB[r1[9] as usize])
                .wrapping_add(r1[12])
                .wrapping_add(SB[r1[14] as usize]);

            // Shift registers left by one byte: exactly the Appendix B operation.
            r0.copy_within(1..17, 0);
            r1.copy_within(1..15, 0);
            if k >= prerun {
                let idx = round * blen + k - prerun;
                rkey[idx] = t0.wrapping_add(r1[4]);
                if step < addk {
                    if step & 1 != 0 {
                        t0 = t0.wrapping_add(key[32 + step]);
                    } else {
                        t1 = t1.wrapping_add(key[32 + step]);
                    }
                    step += 1;
                }
            }
            r0[16] = t0;
            r1[14] = t1;
        }
        prerun = 0;
    }
    // r0/r1 are securely cleared on scope exit, including unwinding.
    Ok(())
}

pub fn sBox(data: &[u8], res: &mut [u8], blen: usize) {
    assert!(data.len() >= blen, "sBox: input shorter than blen");
    assert!(res.len() >= blen, "sBox: output shorter than blen");
    for i in 0..blen {
        res[i] = SB[data[i] as usize];
    }
}

pub fn sBoxU(data: &[u8], res: &mut [u8], blen: usize) {
    // Public safe API: never dereference raw pointers based on unchecked lengths.
    assert!(data.len() >= blen, "sBoxU: input shorter than blen");
    assert!(res.len() >= blen, "sBoxU: output shorter than blen");
    for i in 0..blen {
        res[i] = SB[data[i] as usize];
    }
}

fn sbox_in_place(b: &mut [u8]) {
    b.iter_mut().for_each(|x| *x = SB[*x as usize]);
}

fn inv_sbox_in_place(b: &mut [u8]) {
    b.iter_mut().for_each(|x| *x = ISB[*x as usize]);
}

pub fn AddRkX(block: &[u8], rkey: &[u8], nr: usize, blen: usize, res: &mut [u8]) {
    let start = nr.checked_mul(blen).expect("AddRkX: round offset overflow");
    let end = start.checked_add(blen).expect("AddRkX: round end overflow");
    assert!(block.len() >= blen, "AddRkX: input shorter than blen");
    assert!(res.len() >= blen, "AddRkX: output shorter than blen");
    assert!(rkey.len() >= end, "AddRkX: round key out of bounds");
    for i in 0..blen {
        res[i] = block[i] ^ rkey[start + i];
    }
}

pub fn AddRk(block: &[u8], rkey: &[u8], nr: usize, blen: usize, res: &mut [u8]) {
    // Checked arithmetic prevents index wraparound for untrusted round numbers.
    let start = nr.checked_mul(blen).expect("AddRk: round offset overflow");
    let end = start.checked_add(blen).expect("AddRk: round end overflow");
    assert!(block.len() >= blen, "AddRk: input shorter than blen");
    assert!(res.len() >= blen, "AddRk: output shorter than blen");
    assert!(rkey.len() >= end, "AddRk: round key out of bounds");

    let mut carry: u16 = 0;
    for i in 0..blen {
        let sum = (block[i] as u16) + (rkey[start + i] as u16) + carry;
        res[i] = sum as u8;
        carry = sum >> 8;
    }
}

/// Encryption (section 9.1) with N = RNDS(klen) round keys.
pub fn encrypt(data: &[u8], rkey: &[u8], klen: usize, blen: usize, res: &mut [u8]) -> Result<(), ParamError> {
    if !valid_params(klen, blen) || data.len() < blen || res.len() < blen || rkey.len() < RNDS!(klen) * blen {
        return Err(ParamError);
    }
    let mut block = Zeroizing::new([0u8; MAXBLOCKLEN as usize]);
    let mut block2 = Zeroizing::new([0u8; MAXBLOCKLEN as usize]);
    AddRk(data, rkey, 0, blen, &mut block[..]);
    sBox(&block[..], &mut block2[..], blen);
    linOp(&block2[..], &mut block[..], blen);
    for i in 1..RNDS!(klen) - 1 {
        AddRkX(&block[..], rkey, i, blen, &mut block2[..]);
        sbox_in_place(&mut block2[..blen]);
        linOp(&block2[..], &mut block[..], blen);
    }
    AddRk(&block[..], rkey, RNDS!(klen) - 1, blen, res);
    Ok(())
}

/// Subtraction of round key `nr` modulo 2^(8*blen), byte 0 least significant.
/// (The previous version underflowed a u16 — a panic in debug builds — and
/// lost the borrow after a logical shift in release builds.)
pub fn InvAddRk(block: &[u8], rkey: &[u8], nr: usize, blen: usize, res: &mut [u8]) {
    let start = nr.checked_mul(blen).expect("InvAddRk: round offset overflow");
    let end = start.checked_add(blen).expect("InvAddRk: round end overflow");
    assert!(block.len() >= blen, "InvAddRk: input shorter than blen");
    assert!(res.len() >= blen, "InvAddRk: output shorter than blen");
    assert!(rkey.len() >= end, "InvAddRk: round key out of bounds");

    let mut borrow = 0u16;
    for i in 0..blen {
        let subtrahend = (rkey[start + i] as u16) + borrow;
        let minuend = block[i] as u16;
        res[i] = minuend.wrapping_sub(subtrahend) as u8;
        borrow = if minuend < subtrahend { 1 } else { 0 };
    }
}

pub fn InvlinOp(d: &[u8], r: &mut [u8], blocklen: usize) {
    assert!(matches!(blocklen, 16 | 32 | 64), "InvlinOp: unsupported block length");
    assert!(d.len() >= blocklen, "InvlinOp: input shorter than blocklen");
    assert!(r.len() >= blocklen, "InvlinOp: output shorter than blocklen");
    match blocklen {
        16 => {
            let mut dout = [0u32; 4];
            ilin334(&load32::<4>(d), &mut dout);
            store32(r, &dout);
        }
        32 => {
            let mut dout = [0u32; 8];
            ilin384(&load32::<8>(d), &mut dout);
            store32(r, &dout);
        }
        64 => {
            let mut dout = [0u64; 8];
            ilin388(&load64::<8>(d), &mut dout);
            store64(r, &dout);
        }
        _ => unreachable!(),
    }
}

pub fn InvsBox(data: &[u8], res: &mut [u8], blen: usize) {
    assert!(data.len() >= blen, "InvsBox: input shorter than blen");
    assert!(res.len() >= blen, "InvsBox: output shorter than blen");
    for i in 0..blen {
        res[i] = ISB[data[i] as usize];
    }
}

/// Decryption (section 9.2). The middle rounds remove the round key with XOR
/// (the previous version used the modular addition AddRk there).
pub fn decrypt(data: &[u8], rkey: &[u8], klen: usize, blen: usize, res: &mut [u8]) -> Result<(), ParamError> {
    if !valid_params(klen, blen) || data.len() < blen || res.len() < blen || rkey.len() < RNDS!(klen) * blen {
        return Err(ParamError);
    }
    let mut block = Zeroizing::new([0u8; MAXBLOCKLEN as usize]);
    let mut block2 = Zeroizing::new([0u8; MAXBLOCKLEN as usize]);
    InvAddRk(data, rkey, RNDS!(klen) - 1, blen, &mut block[..]);
    for i in (1..RNDS!(klen) - 1).rev() {
        InvlinOp(&block[..], &mut block2[..], blen);
        inv_sbox_in_place(&mut block2[..blen]);
        AddRkX(&block2[..], rkey, i, blen, &mut block[..]);
    }
    InvlinOp(&block[..], &mut block2[..], blen);
    inv_sbox_in_place(&mut block2[..blen]);
    InvAddRk(&block2[..], rkey, 0, blen, res);
    Ok(())
}

/// An expanded key for one block length.
pub struct Cipher {
    klen: usize,
    blen: usize,
    rkey: Zeroizing<Vec<u8>>,
}

impl Cipher {
    /// `key`: 32..=128 bytes in steps of 16; `block_size`: 16, 32 or 64 bytes.
    pub fn new(key: &[u8], block_size: usize) -> Result<Self, ParamError> {
        if !valid_params(key.len(), block_size) {
            return Err(ParamError);
        }
        let mut rkey = Zeroizing::new(vec![0u8; RNDS!(key.len()) * block_size]);
        Kexp(key, key.len(), block_size, &mut rkey)?;
        Ok(Cipher { klen: key.len(), blen: block_size, rkey })
    }

    pub fn block_size(&self) -> usize {
        self.blen
    }

    /// Number of round keys N = 16 + (KLen - 256) / 128.
    pub fn rounds(&self) -> usize {
        RNDS!(self.klen)
    }

    /// Encrypts one block; panics if `input` or `output` is shorter than a block.
    pub fn encrypt_block(&self, input: &[u8], output: &mut [u8]) {
        encrypt(input, &self.rkey, self.klen, self.blen, output).expect("full block")
    }

    /// Decrypts one block; panics if `input` or `output` is shorter than a block.
    pub fn decrypt_block(&self, input: &[u8], output: &mut [u8]) {
        decrypt(input, &self.rkey, self.klen, self.blen, output).expect("full block")
    }

    /// Encrypts one block in place.
    pub fn encrypt_in_place(&self, block: &mut [u8]) {
        let mut tmp = Zeroizing::new([0u8; MAXBLOCKLEN as usize]);
        tmp[..self.blen].copy_from_slice(&block[..self.blen]);
        self.encrypt_block(&tmp[..self.blen], block);
    }

    /// Decrypts one block in place.
    pub fn decrypt_in_place(&self, block: &mut [u8]) {
        let mut tmp = Zeroizing::new([0u8; MAXBLOCKLEN as usize]);
        tmp[..self.blen].copy_from_slice(&block[..self.blen]);
        self.decrypt_block(&tmp[..self.blen], block);
    }
}

// Cipher.rkey is Zeroizing<Vec<u8>> and is wiped on Drop (including unwinding).
