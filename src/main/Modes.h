#pragma once
// Modes of operation of СТ РК ISO/IEC 10116-2019 for the СТ РК 4009-2025 cipher.
//
//   ECB, CBC (m = 1)                          whole blocks only
//   CFB (r = n, j = k = n), OFB (j = n),
//   CTR (j = n)                               any length; a final partial block is truncated
//
// CTR: the counter is the whole n-bit block, incremented modulo 2^n with the
// last byte least significant. None of the modes authenticates data.
// in and out may be the same buffer.
#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include "Qalqan.h"

class QalqanCipher
{
public:
    // Throws std::invalid_argument unless keyLen is 32..128 bytes in steps of
    // 16 and blockLen is 16, 32 or 64 bytes.
    // Bounds-checked public interface. Existing pointer-only constructor is
    // intentionally removed: its keyLen could lie about the allocation size.
    QalqanCipher(std::span<const uint8_t> key, size_t blockLen);
    ~QalqanCipher(); // wipes the round keys
    QalqanCipher(const QalqanCipher&) = delete;
    QalqanCipher& operator=(const QalqanCipher&) = delete;

    size_t BlockSize() const { return (size_t)blen_; }
    int Rounds() const { return RNDS(klen_); }
    // Exactly BlockSize() bytes required; buffers may be the same allocation
    // only if their starting addresses are equal (in-place); no partial overlap.
    void EncryptBlock(std::span<const uint8_t> in, std::span<uint8_t> out) const;
    void DecryptBlock(std::span<const uint8_t> in, std::span<uint8_t> out) const;

private:
    int klen_, blen_;
    uint8_t rkey_[RNDS(MAXKEYLEN) * MAXBLOCKLEN];
};

// This is a RESEARCH-ONLY, UNAUTHENTICATED confidentiality interface.
// All calls describe an entire message. CTR/CFB/OFB restart from IV on each
// call, unlike Go's stateful cipher.Stream. Reusing IV under one key is unsafe.
// Exact output length == input length, no partial overlap; in-place is allowed.
// IV must equal BlockSize() for CBC, CFB, OFB, CTR.
void EcbEncrypt(const QalqanCipher& c, std::span<const uint8_t> in, std::span<uint8_t> out);
void EcbDecrypt(const QalqanCipher& c, std::span<const uint8_t> in, std::span<uint8_t> out);
void CbcEncrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out);
void CbcDecrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out);
void CfbEncrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out);
void CfbDecrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
                std::span<const uint8_t> in, std::span<uint8_t> out);
void OfbCrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
              std::span<const uint8_t> in, std::span<uint8_t> out);
void CtrCrypt(const QalqanCipher& c, std::span<const uint8_t> iv,
              std::span<const uint8_t> in, std::span<uint8_t> out);

// ISO/IEC 9797-1 padding method 2 (0x80 then zeros to a whole block). The
// standard prescribes no padding; agree on one with the other party.
std::vector<uint8_t> PadMethod2(std::span<const uint8_t> data, size_t blockLen);
// Removes method-2 padding in place; false for bad padding; throws on bad blockLen.
bool UnpadMethod2(std::vector<uint8_t>& data, size_t blockLen);
