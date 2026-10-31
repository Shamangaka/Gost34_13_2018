#pragma once
// INTERNAL ONLY — NOT A SUPPORTED PUBLIC API.
// These pointer-only functions cannot validate actual buffer extents. Their
// preconditions must be enforced by their internal callers. User code must
// use QalqanCipher's std::span interface in Modes.h.
#include "Qalqan.h"

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
