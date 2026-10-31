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

// The raw key-schedule, round, and transform routines are intentionally NOT
// declared here. They are internal implementation details; see Modes.h for
// the bounds-checked public block-cipher API.
