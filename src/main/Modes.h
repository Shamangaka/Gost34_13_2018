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
#include "Qalqan.h"

class QalqanCipher
{
public:
    // Throws std::invalid_argument unless keyLen is 32..128 bytes in steps of
    // 16 and blockLen is 16, 32 or 64 bytes.
    QalqanCipher(const uint8_t* key, size_t keyLen, size_t blockLen);
    ~QalqanCipher(); // wipes the round keys
    QalqanCipher(const QalqanCipher&) = delete;
    QalqanCipher& operator=(const QalqanCipher&) = delete;

    size_t BlockSize() const { return (size_t)blen_; }
    int Rounds() const { return RNDS(klen_); }
    void EncryptBlock(const uint8_t* in, uint8_t* out) const;
    void DecryptBlock(const uint8_t* in, uint8_t* out) const;

private:
    int klen_, blen_;
    uint8_t rkey_[RNDS(MAXKEYLEN) * MAXBLOCKLEN];
};

// len must be a multiple of the block size (std::invalid_argument otherwise).
void EcbEncrypt(const QalqanCipher& c, const uint8_t* in, uint8_t* out, size_t len);
void EcbDecrypt(const QalqanCipher& c, const uint8_t* in, uint8_t* out, size_t len);
void CbcEncrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len);
void CbcDecrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len);

// iv is one block. Any length.
void CfbEncrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len);
void CfbDecrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len);
void OfbCrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len);
void CtrCrypt(const QalqanCipher& c, const uint8_t* iv, const uint8_t* in, uint8_t* out, size_t len);

// ISO/IEC 9797-1 padding method 2 (0x80 then zeros to a whole block). The
// standard prescribes no padding; agree on one with the other party.
std::vector<uint8_t> PadMethod2(const uint8_t* data, size_t len, size_t blockLen);
// Removes method-2 padding in place; false if the padding is invalid.
bool UnpadMethod2(std::vector<uint8_t>& data, size_t blockLen);
