#pragma once
// СТ РК 4009-2025 block cipher (Qalqan), after the reference code of
// Appendix B, without its undefined behaviour and host byte-order dependence.
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <bit>

#define SHIFT 17
#define MINBLOCKLEN 16
#define MAXBLOCKLEN 64
#define MINKEYLEN 32
#define MAXKEYLEN 128
#define KEYLENSTEP 16
#define RNDS(x) (16 + ((x) - 32) / 16)

// std::rotl is defined for every shift count. The Appendix B macros computed
// x >> (64 - s), i.e. a shift by 64 for the 0 rotation of Table 2, which is
// undefined behaviour (Clang drops the 512-bit linear layer because of it).
inline uint32_t ROTL(uint32_t x, int s) { return std::rotl(x, s); }
inline uint64_t ROTL64(uint64_t x, int s) { return std::rotl(x, s); }

// True for klen = 32..128 bytes in steps of 16 and blen = 16, 32 or 64 bytes.
bool ValidParams(int klen, int blen);

// Key expansion: writes RNDS(klen) * blen bytes. Returns false, writing
// nothing, for an invalid key or block length.
bool Kexp(const uint8_t* key, int klen, int blen, uint8_t* rkey);

// Encrypting
void linOp(const uint8_t* d, uint8_t* r, int blocklen);
void sBox(const uint8_t* data, uint8_t* res, int blocklen);
void AddRkX(const uint8_t* block, const uint8_t* rkey, int nr, int blen, uint8_t* res);
void AddRk(const uint8_t* block, const uint8_t* rkey, int nr, int blen, uint8_t* res);
bool encrypt(const uint8_t* data, const uint8_t* rkey, int klen, int blen, uint8_t* res);

// Decrypting
void InvAddRk(const uint8_t* block, const uint8_t* rkey, int nr, int blen, uint8_t* res);
void InvlinOp(const uint8_t* d, uint8_t* r, int blocklen);
void InvsBox(const uint8_t* data, uint8_t* res, int blocklen);
bool decrypt(const uint8_t* data, const uint8_t* rkey, int klen, int blen, uint8_t* res);

// PRNG
void init(uint32_t ix);
uint8_t rnext(); // (1103515245 * x + 12345 mod 2**32)[23..16]

// Test vectors generators (Appendix A format)
void KexpV(const uint8_t* key, int klen, int blen, uint8_t* rkey, FILE* f);
void KexpVV(const uint8_t* key, int klen, int blen, uint8_t* rkey, FILE* f);
void ETestVectors(FILE* f);
void encryptV(const uint8_t* data, const uint8_t* rkey, int klen, int blen, uint8_t* res, FILE* f);
void ShortTestVectors(FILE* f, FILE* src);
