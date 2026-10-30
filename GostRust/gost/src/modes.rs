//! Modes of operation of СТ РК ISO/IEC 10116-2019 for the СТ РК 4009-2025 cipher.
//!
//! | Mode | Parameters | Length |
//! |------|------------|--------|
//! | ECB  | –          | whole blocks |
//! | CBC  | m = 1      | whole blocks |
//! | CFB  | r = n, j = k = n | any (final partial block truncated) |
//! | OFB  | j = n      | any |
//! | CTR  | j = n; counter = whole block, +1 mod 2^n, last byte least significant | any |
//!
//! All functions work in place. None of the modes authenticates data.

use crate::qalqan::Cipher;

/// Wrong IV length, or ECB/CBC input that is not a whole number of blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModeError {
    IvLength,
    NotWholeBlocks,
}

impl std::fmt::Display for ModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModeError::IvLength => f.write_str("qalqan: IV length must equal the block size"),
            ModeError::NotWholeBlocks => f.write_str("qalqan: input is not a whole number of blocks"),
        }
    }
}

impl std::error::Error for ModeError {}

fn check_iv(c: &Cipher, iv: &[u8]) -> Result<(), ModeError> {
    if iv.len() == c.block_size() {
        Ok(())
    } else {
        Err(ModeError::IvLength)
    }
}

fn check_blocks(c: &Cipher, buf: &[u8]) -> Result<(), ModeError> {
    if buf.len() % c.block_size() == 0 {
        Ok(())
    } else {
        Err(ModeError::NotWholeBlocks)
    }
}

pub fn ecb_encrypt(c: &Cipher, buf: &mut [u8]) -> Result<(), ModeError> {
    check_blocks(c, buf)?;
    buf.chunks_exact_mut(c.block_size()).for_each(|b| c.encrypt_in_place(b));
    Ok(())
}

pub fn ecb_decrypt(c: &Cipher, buf: &mut [u8]) -> Result<(), ModeError> {
    check_blocks(c, buf)?;
    buf.chunks_exact_mut(c.block_size()).for_each(|b| c.decrypt_in_place(b));
    Ok(())
}

pub fn cbc_encrypt(c: &Cipher, iv: &[u8], buf: &mut [u8]) -> Result<(), ModeError> {
    check_iv(c, iv)?;
    check_blocks(c, buf)?;
    let mut prev = iv.to_vec();
    for b in buf.chunks_exact_mut(c.block_size()) {
        b.iter_mut().zip(&prev).for_each(|(x, p)| *x ^= p);
        c.encrypt_in_place(b);
        prev.copy_from_slice(b);
    }
    Ok(())
}

pub fn cbc_decrypt(c: &Cipher, iv: &[u8], buf: &mut [u8]) -> Result<(), ModeError> {
    check_iv(c, iv)?;
    check_blocks(c, buf)?;
    let mut prev = iv.to_vec();
    for b in buf.chunks_exact_mut(c.block_size()) {
        let cur = b.to_vec();
        c.decrypt_in_place(b);
        b.iter_mut().zip(&prev).for_each(|(x, p)| *x ^= p);
        prev = cur;
    }
    Ok(())
}

fn cfb(c: &Cipher, iv: &[u8], buf: &mut [u8], decrypt: bool) -> Result<(), ModeError> {
    check_iv(c, iv)?;
    let mut reg = iv.to_vec();
    let mut ks = vec![0u8; c.block_size()];
    for chunk in buf.chunks_mut(c.block_size()) {
        c.encrypt_block(&reg, &mut ks);
        for (k, x) in chunk.iter_mut().enumerate() {
            let input = *x;
            *x ^= ks[k];
            reg[k] = if decrypt { input } else { *x }; // ciphertext is fed back
        }
    }
    Ok(())
}

pub fn cfb_encrypt(c: &Cipher, iv: &[u8], buf: &mut [u8]) -> Result<(), ModeError> {
    cfb(c, iv, buf, false)
}

pub fn cfb_decrypt(c: &Cipher, iv: &[u8], buf: &mut [u8]) -> Result<(), ModeError> {
    cfb(c, iv, buf, true)
}

/// OFB encryption and decryption (the same operation).
pub fn ofb(c: &Cipher, iv: &[u8], buf: &mut [u8]) -> Result<(), ModeError> {
    check_iv(c, iv)?;
    let mut reg = iv.to_vec();
    for chunk in buf.chunks_mut(c.block_size()) {
        c.encrypt_in_place(&mut reg); // Y_i = e_K(Y_{i-1})
        chunk.iter_mut().zip(&reg).for_each(|(x, k)| *x ^= k);
    }
    Ok(())
}

/// CTR encryption and decryption (the same operation).
pub fn ctr(c: &Cipher, iv: &[u8], buf: &mut [u8]) -> Result<(), ModeError> {
    check_iv(c, iv)?;
    let mut counter = iv.to_vec();
    let mut ks = vec![0u8; c.block_size()];
    for chunk in buf.chunks_mut(c.block_size()) {
        c.encrypt_block(&counter, &mut ks);
        for b in counter.iter_mut().rev() {
            // CTR_{i+1} = CTR_i + 1 mod 2^n
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        chunk.iter_mut().zip(&ks).for_each(|(x, k)| *x ^= k);
    }
    Ok(())
}

/// ISO/IEC 9797-1 padding method 2 (0x80, then zeros to a whole block).
/// СТ РК 4009-2025 prescribes no padding; agree on one with the other party.
pub fn pad_method2(data: &[u8], block_size: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out.push(0x80);
    while out.len() % block_size != 0 {
        out.push(0);
    }
    out
}

/// Strips method-2 padding; `None` if it is invalid.
pub fn unpad_method2(data: &[u8], block_size: usize) -> Option<&[u8]> {
    if data.is_empty() || data.len() % block_size != 0 {
        return None;
    }
    let stop = data.len() - block_size;
    let mut i = data.len();
    while i > stop && data[i - 1] == 0 {
        i -= 1;
    }
    if i == stop || data[i - 1] != 0x80 {
        return None;
    }
    Some(&data[..i - 1])
}
