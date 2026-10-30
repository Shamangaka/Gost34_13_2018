# Conformance with СТ РК 4009-2025

This repository implements the block cipher of СТ РК 4009-2025 «Информационные
технологии. Криптографическая защита информации. Алгоритм блочного
симметричного шифрования» (Qalqan) and the modes of operation of
СТ РК ISO/IEC 10116-2019 that the standard's scope (1.1) refers to.

## What every implementation must do

| Requirement | Source |
|---|---|
| Block length 128, 256 or 512 bits; other lengths rejected | 5 |
| Key length 256…1024 bits in steps of 128; other lengths rejected | 5 |
| N = 16 + (KLen − 256)/128 round keys | 5, Appendix A |
| S and S⁻¹ (with the errata below) | 6.1, 9.2 |
| L / L⁻¹ on little-endian 32-bit words (128/256) or 64-bit words (512), shifts of Table 2 | 6.2, Appendix A |
| K^start and K^fin added/subtracted modulo 2^Blen, byte 0 least significant; middle keys XORed | 6.3, Appendix A |
| Key schedule: L0 = {K0, K2, …, K30, K31}, L1 = {K1, K3, …, K29}; 17 warm-up steps; round-key byte = L0 feedback ∔ L1₄; extra key bytes added to the L1 feedback on even steps and to the L0 feedback on odd steps, after the round-key byte is taken | 8, Appendix A |
| Appendix A reproduced byte for byte | Appendix A (mandatory) |
| ECB, CBC, CFB, OFB, CTR | СТ РК ISO/IEC 10116-2019 |

Mode parameters used here: CBC with m = 1; CFB with r = n and j = k = n;
OFB with j = n; CTR with j = n, the counter being the whole block incremented
modulo 2ⁿ with the last byte least significant. CFB, OFB and CTR accept a
final partial block. ISO/IEC 9797-1 padding method 2 is provided for ECB/CBC.

## Errata in the printed standard

The implementations follow Appendix A (mandatory), which agrees with the
reference code of Appendix B, wherever the text differs:

1. **Table 1 and Table 3 are not permutations.** S(0x3c), S(0x48), S(0xf5) are
   printed as `de`, `ce`, `1e`; the correct values are `dc`, `cc`, `1c`.
   S⁻¹(0x11), S⁻¹(0x9f), S⁻¹(0xaf) are printed as `de`, `1e`, `ce`; correct:
   `dc`, `1c`, `cc`. Several cells also contain Cyrillic `а`, `с`, `е` or the
   letter `l` in place of hex digits.
2. **Round count.** Formulas (5) and (9) iterate XSL₁…XSL_{N−1}, which would
   need N + 1 round keys. Section 7 and Appendix A use N: K⁰ (⊞), XSL rounds
   with K¹…K^{N−2}, K^{N−1} (⊞).
3. **Key schedule, keys longer than 256 bits.** The value written as
   L0₁₆ ∔ L1₄ uses the L0 feedback *before* the extra key byte is added. The
   "Output" lines that Appendix A prints on odd steps include the added byte
   and are not round-key bytes; the "Round N key" lines are authoritative.
4. **Register update.** The formula for L1 reads `L1₁..L1₁₃`; it must be
   `L1₁..L1₁₄` (L1 has 15 cells). Figure 3 draws the L1 taps at cells
   0, 7, 11, 13, 14; the formula, Appendix B and Appendix A use 0, 3, 9, 12, 14.
5. **Byte and word order** are not stated in the text; Appendix A fixes them as
   described in the table above.
6. **Appendix B code** shifts a 64-bit value by 64 in `ROTL64(x, 0)` (Table 2
   has a 0 rotation for 512-bit blocks) and casts byte arrays to
   `uint32_t*`/`uint64_t*`. Both are undefined behaviour; Clang at -O1 and above
   drops the 512-bit linear layer, and the casts make the result depend on the
   host byte order. The C++ here no longer does either.

## Not covered by the standard

- **MAC (имитовставка).** Section 1.1 mentions integrity protection "in
  accordance with СТ РК ISO/IEC 10116", but ISO/IEC 10116 defines no MAC and
  4009-2025 specifies none. No mode here authenticates data.
- **Interoperability choices** (CTR counter convention, padding, IV
  generation) must be agreed with the other party.
- **Certification.** Matching the test vectors is not certification. Use in
  state systems requires a certified cryptographic tool; СТ РК 1073-2025 sets
  the requirements for such tools.

## Shared test data (`resources/`)

| File | Content |
|---|---|
| `gold.txt` | Appendix A, as printed (all 28,768 hex digits of vector data checked against the standard's images). Generated from `input.bin`. |
| `reference_kat.txt` | 84 cases, all 21 key/block combinations, produced by the Appendix B code (Appendix A only encrypts with 256-bit keys). |
| `modes_kat.txt` | ECB/CBC/CFB/OFB/CTR cases for the three block sizes and 256/640/1024-bit keys, incl. partial blocks and counter wrap-around. |

## Status

C++, Go, Rust, C#, F# and Lean run the same checks against the shared data; the F* specification checks a selection of them by normalisation.

| Implementation | How to run | What is checked |
|---|---|---|
| C++ (`src/`) | `cmake -B build && cmake --build build && ctest --test-dir build` (needs GoogleTest) | Appendix A byte for byte, 84 reference KATs, mode KATs, round trips for all 21 size combinations, invalid parameters, padding. GCC, Clang, ASan/UBSan. |
| Go (`GostGolang/`) | `go test ./...` | Same, plus agreement with `crypto/cipher` CBC/CTR/OFB/CFB. |
| Rust (`GostRust/`) | `cargo test -p gost` | Same (debug and release builds). |
| C# (`GostCsharp/`) | `dotnet run -c Release -- --selftest` | Same. |
| F# (`GostFSharp/`) | `dotnet run -c Release -- --selftest` | Same. |
| Lean (`GostLean/`) | `lake build && lake exe gostlean --selftest` (Lean 4.12.0) | Same. |
| F* (`GostFStar/`) | `./verify.sh` (fstar.exe 2025.03.25; about 5 minutes) | By normalisation while type-checking: S-box, Appendix A linear-layer examples, round keys of a 1024-bit key, Appendix A ciphertexts for all three block lengths, decryption, the largest reference KAT, all five modes, padding. |

`.github/workflows/conformance.yml` runs all of the above.
