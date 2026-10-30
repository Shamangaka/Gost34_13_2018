//! Conformance tests for СТ РК 4009-2025 and the СТ РК ISO/IEC 10116 modes.
use gost::modes;
use gost::qalqan::{self, Cipher};
use std::path::PathBuf;

fn resource(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../resources").join(name)
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn records(name: &str) -> Vec<Vec<String>> {
    std::fs::read_to_string(resource(name))
        .unwrap()
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split_whitespace().map(String::from).collect())
        .collect()
}

/// The generator must reproduce the mandatory Appendix A byte for byte.
#[test]
fn appendix_a() {
    let mut src = std::fs::File::open(resource("input.bin")).unwrap();
    let mut out: Vec<u8> = Vec::new();
    gost::prng::init(0);
    gost::test_vectors::short_test_vectors(Some(&mut out), Some(&mut src));
    let got = String::from_utf8(out).unwrap();
    let want = std::fs::read_to_string(resource("gold.txt")).unwrap();
    assert!(got.trim_end_matches('\n') == want.trim_end_matches('\n'), "output differs from gold.txt");
}

/// 84 cases from the Appendix B reference code, all 21 key/block combinations.
#[test]
fn reference_known_answers() {
    let rows = records("reference_kat.txt");
    assert_eq!(rows.len(), 84);
    for f in rows {
        let (key, pt, ct) = (unhex(&f[2]), unhex(&f[3]), unhex(&f[4]));
        let c = Cipher::new(&key, pt.len()).unwrap();
        let mut out = vec![0u8; pt.len()];
        c.encrypt_block(&pt, &mut out);
        assert_eq!(out, ct, "{}/{}", f[0], f[1]);
        c.decrypt_block(&ct, &mut out);
        assert_eq!(out, pt, "{}/{}", f[0], f[1]);
    }
}

#[test]
fn mode_known_answers() {
    let rows = records("modes_kat.txt");
    assert_eq!(rows.len(), 54);
    for f in rows {
        let bits: usize = f[2].parse().unwrap();
        let (key, pt, ct) = (unhex(&f[3]), unhex(&f[5]), unhex(&f[6]));
        let iv = if f[4] == "-" { Vec::new() } else { unhex(&f[4]) };
        let c = Cipher::new(&key, bits / 8).unwrap();
        let (mut enc, mut dec) = (pt.clone(), ct.clone());
        match f[0].as_str() {
            "ECB" => {
                modes::ecb_encrypt(&c, &mut enc).unwrap();
                modes::ecb_decrypt(&c, &mut dec).unwrap();
            }
            "CBC" => {
                modes::cbc_encrypt(&c, &iv, &mut enc).unwrap();
                modes::cbc_decrypt(&c, &iv, &mut dec).unwrap();
            }
            "CFB" => {
                modes::cfb_encrypt(&c, &iv, &mut enc).unwrap();
                modes::cfb_decrypt(&c, &iv, &mut dec).unwrap();
            }
            "OFB" => {
                modes::ofb(&c, &iv, &mut enc).unwrap();
                modes::ofb(&c, &iv, &mut dec).unwrap();
            }
            "CTR" => {
                modes::ctr(&c, &iv, &mut enc).unwrap();
                modes::ctr(&c, &iv, &mut dec).unwrap();
            }
            m => panic!("unknown mode {m}"),
        }
        assert_eq!(enc, ct, "{} {}/{}", f[0], f[1], f[2]);
        assert_eq!(dec, pt, "{} {}/{}", f[0], f[1], f[2]);
    }
}

#[test]
fn round_trip_all_sizes() {
    let mut x: u64 = 1;
    let mut next = || {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (x >> 56) as u8
    };
    for blen in [16usize, 32, 64] {
        for klen in (32usize..=128).step_by(16) {
            for _ in 0..50 {
                let key: Vec<u8> = (0..klen).map(|_| next()).collect();
                let pt: Vec<u8> = (0..blen).map(|_| next()).collect();
                let c = Cipher::new(&key, blen).unwrap();
                assert_eq!(c.rounds(), 16 + (klen * 8 - 256) / 128);
                let mut buf = pt.clone();
                c.encrypt_in_place(&mut buf);
                c.decrypt_in_place(&mut buf);
                assert_eq!(buf, pt, "key {klen}, block {blen}");
            }
        }
    }
}

#[test]
fn rejects_invalid_parameters() {
    for klen in [0usize, 16, 31, 40, 144] {
        assert!(Cipher::new(&vec![0u8; klen], 16).is_err(), "key {klen}");
    }
    for blen in [0usize, 8, 24, 48, 128] {
        assert!(Cipher::new(&[0u8; 32], blen).is_err(), "block {blen}");
        let mut rk = vec![0u8; 22 * 128];
        assert!(qalqan::Kexp(&[0u8; 32], 32, blen, &mut rk).is_err());
    }
    let c = Cipher::new(&[0u8; 32], 16).unwrap();
    assert_eq!(modes::cbc_encrypt(&c, &[0u8; 15], &mut [0u8; 16]), Err(modes::ModeError::IvLength));
    assert_eq!(modes::ecb_encrypt(&c, &mut [0u8; 17]), Err(modes::ModeError::NotWholeBlocks));
}

#[test]
fn padding() {
    for bs in [16usize, 32, 64] {
        for n in 0..=2 * bs {
            let data = vec![0x80u8; n];
            let p = modes::pad_method2(&data, bs);
            assert_eq!(p.len() % bs, 0);
            assert_eq!(modes::unpad_method2(&p, bs), Some(&data[..]));
        }
        assert_eq!(modes::unpad_method2(&vec![0u8; bs], bs), None);
    }
}
