// Conformance tests for СТ РК 4009-2025 and the СТ РК ISO/IEC 10116 modes.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "Modes.h"
#include "Qalqan.h"

#ifndef QALQAN_RESOURCES
#define QALQAN_RESOURCES "resources"
#endif

extern uint8_t sb[256];

namespace
{
std::string ReadFile(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
        throw std::runtime_error("cannot open " + path);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string TrimNewlines(std::string s)
{
    while (!s.empty() && s.back() == '\n')
        s.pop_back();
    return s;
}

std::vector<uint8_t> Hex(const std::string& h)
{
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back((uint8_t)std::stoi(h.substr(i, 2), nullptr, 16));
    return out;
}

std::vector<std::vector<std::string>> Records(const std::string& file)
{
    std::vector<std::vector<std::string>> rows;
    std::istringstream in(ReadFile(std::string(QALQAN_RESOURCES) + "/" + file));
    std::string line;
    while (std::getline(in, line))
    {
        if (line.empty() || line[0] == '#')
            continue;
        std::istringstream ls(line);
        std::vector<std::string> f;
        std::string w;
        while (ls >> w)
            f.push_back(w);
        rows.push_back(f);
    }
    return rows;
}
} // namespace

// The generator must reproduce the mandatory Appendix A byte for byte.
TEST(Qalqan, AppendixA)
{
    const std::string res = QALQAN_RESOURCES;
    FILE* src = fopen((res + "/input.bin").c_str(), "rb");
    ASSERT_NE(src, nullptr);
    FILE* out = std::tmpfile();
    ASSERT_NE(out, nullptr);
    init(0);
    ShortTestVectors(out, src);
    fclose(src);
    std::string got;
    std::rewind(out);
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, out)) > 0)
        got.append(buf, n);
    fclose(out);
    got = TrimNewlines(got);
    std::string want = TrimNewlines(ReadFile(res + "/gold.txt"));
    ASSERT_EQ(got.size(), want.size());
    EXPECT_TRUE(got == want);
}

// 84 cases from the Appendix B reference code, all key/block combinations.
TEST(Qalqan, ReferenceKnownAnswers)
{
    int n = 0;
    for (const auto& f : Records("reference_kat.txt"))
    {
        auto key = Hex(f[2]), pt = Hex(f[3]), ct = Hex(f[4]);
        const int klen = (int)key.size(), blen = (int)pt.size();
        ASSERT_EQ(klen * 8, std::stoi(f[0]));
        ASSERT_EQ(blen * 8, std::stoi(f[1]));

        std::vector<uint8_t> rk(RNDS(klen) * blen), out(blen), back(blen);
        ASSERT_TRUE(Kexp(key.data(), klen, blen, rk.data()));
        ASSERT_TRUE(encrypt(pt.data(), rk.data(), klen, blen, out.data()));
        EXPECT_EQ(out, ct) << f[0] << "/" << f[1];
        ASSERT_TRUE(decrypt(ct.data(), rk.data(), klen, blen, back.data()));
        EXPECT_EQ(back, pt) << f[0] << "/" << f[1];

        QalqanCipher c(key.data(), key.size(), pt.size());
        c.EncryptBlock(pt.data(), out.data());
        EXPECT_EQ(out, ct);
        n++;
    }
    EXPECT_EQ(n, 84);
}

TEST(Qalqan, RoundTripAllSizes)
{
    std::mt19937 rng(7);
    for (int blen : {16, 32, 64})
        for (int klen = MINKEYLEN; klen <= MAXKEYLEN; klen += KEYLENSTEP)
            for (int t = 0; t < 50; t++)
            {
                std::vector<uint8_t> key(klen), pt(blen), ct(blen), back(blen);
                for (auto& b : key) b = (uint8_t)rng();
                for (auto& b : pt) b = (uint8_t)rng();
                QalqanCipher c(key.data(), key.size(), pt.size());
                EXPECT_EQ(c.Rounds(), 16 + (klen * 8 - 256) / 128);
                c.EncryptBlock(pt.data(), ct.data());
                c.DecryptBlock(ct.data(), back.data());
                ASSERT_EQ(back, pt) << klen << "/" << blen;
                std::vector<uint8_t> buf = pt; // in place
                c.EncryptBlock(buf.data(), buf.data());
                ASSERT_EQ(buf, ct);
            }
}

TEST(Qalqan, SBoxIsPermutation)
{
    std::vector<int> seen(256, 0);
    for (int i = 0; i < 256; i++)
        seen[sb[i]]++;
    EXPECT_EQ(std::count(seen.begin(), seen.end(), 1), 256);
    uint8_t in[64], out[64], back[64];
    for (int i = 0; i < 64; i++)
        in[i] = (uint8_t)(i * 4 + 1);
    sBox(in, out, 64);
    InvsBox(out, back, 64);
    EXPECT_EQ(0, memcmp(in, back, 64));
}

TEST(Qalqan, RejectsInvalidParameters)
{
    uint8_t key[MAXKEYLEN + 16] = {0}, rk[RNDS(MAXKEYLEN + 16) * 128] = {0}, blk[128] = {0};
    for (int klen : {0, 16, 31, 40, 144})
        EXPECT_FALSE(Kexp(key, klen, 16, rk)) << klen;
    for (int blen : {0, 8, 24, 48, 128})
    {
        EXPECT_FALSE(Kexp(key, 32, blen, rk)) << blen;
        EXPECT_FALSE(encrypt(blk, rk, 32, blen, blk)) << blen;
        EXPECT_FALSE(decrypt(blk, rk, 32, blen, blk)) << blen;
    }
    EXPECT_THROW(QalqanCipher(key, 33, 16), std::invalid_argument);
    EXPECT_THROW(QalqanCipher(key, 32, 24), std::invalid_argument);
}

TEST(Modes, KnownAnswers)
{
    int n = 0;
    for (const auto& f : Records("modes_kat.txt"))
    {
        const std::string& mode = f[0];
        auto key = Hex(f[3]), iv = Hex(f[4]), pt = Hex(f[5]), ct = Hex(f[6]);
        QalqanCipher c(key.data(), key.size(), (size_t)std::stoi(f[2]) / 8);
        std::vector<uint8_t> out(pt.size()), back(pt.size());
        if (mode == "ECB")
        {
            EcbEncrypt(c, pt.data(), out.data(), pt.size());
            EcbDecrypt(c, ct.data(), back.data(), ct.size());
        }
        else if (mode == "CBC")
        {
            CbcEncrypt(c, iv.data(), pt.data(), out.data(), pt.size());
            CbcDecrypt(c, iv.data(), ct.data(), back.data(), ct.size());
        }
        else if (mode == "CFB")
        {
            CfbEncrypt(c, iv.data(), pt.data(), out.data(), pt.size());
            CfbDecrypt(c, iv.data(), ct.data(), back.data(), ct.size());
        }
        else if (mode == "OFB")
        {
            OfbCrypt(c, iv.data(), pt.data(), out.data(), pt.size());
            OfbCrypt(c, iv.data(), ct.data(), back.data(), ct.size());
        }
        else if (mode == "CTR")
        {
            CtrCrypt(c, iv.data(), pt.data(), out.data(), pt.size());
            CtrCrypt(c, iv.data(), ct.data(), back.data(), ct.size());
        }
        else
            FAIL() << "unknown mode " << mode;
        EXPECT_EQ(out, ct) << mode << " " << f[1] << "/" << f[2];
        EXPECT_EQ(back, pt) << mode << " " << f[1] << "/" << f[2];
        n++;
    }
    EXPECT_EQ(n, 54);
}

TEST(Modes, InPlaceAndPartialBlocks)
{
    std::mt19937 rng(11);
    for (size_t bs : {16, 32, 64})
    {
        std::vector<uint8_t> key(48), iv(bs);
        for (auto& b : key) b = (uint8_t)rng();
        for (auto& b : iv) b = (uint8_t)rng();
        QalqanCipher c(key.data(), key.size(), bs);
        for (size_t len : {size_t(0), size_t(1), bs - 1, bs, bs + 1, 5 * bs + 3})
        {
            std::vector<uint8_t> pt(len), sep(len), buf;
            for (auto& b : pt) b = (uint8_t)rng();
            CfbEncrypt(c, iv.data(), pt.data(), sep.data(), len);
            buf = pt;
            CfbEncrypt(c, iv.data(), buf.data(), buf.data(), len);
            EXPECT_EQ(buf, sep);
            CfbDecrypt(c, iv.data(), buf.data(), buf.data(), len);
            EXPECT_EQ(buf, pt);
            buf = pt;
            CtrCrypt(c, iv.data(), buf.data(), buf.data(), len);
            CtrCrypt(c, iv.data(), buf.data(), buf.data(), len);
            EXPECT_EQ(buf, pt);
            buf = pt;
            OfbCrypt(c, iv.data(), buf.data(), buf.data(), len);
            OfbCrypt(c, iv.data(), buf.data(), buf.data(), len);
            EXPECT_EQ(buf, pt);
        }
        std::vector<uint8_t> blocks(3 * bs), buf;
        for (auto& b : blocks) b = (uint8_t)rng();
        buf = blocks;
        CbcEncrypt(c, iv.data(), buf.data(), buf.data(), buf.size());
        CbcDecrypt(c, iv.data(), buf.data(), buf.data(), buf.size());
        EXPECT_EQ(buf, blocks);
        EXPECT_THROW(CbcEncrypt(c, iv.data(), blocks.data(), buf.data(), bs + 1), std::invalid_argument);
    }
}

TEST(Modes, Padding)
{
    for (size_t bs : {16, 32, 64})
        for (size_t n = 0; n <= 2 * bs; n++)
        {
            std::vector<uint8_t> data(n, 0x80);
            auto p = PadMethod2(data.data(), data.size(), bs);
            EXPECT_EQ(p.size() % bs, 0u);
            EXPECT_GT(p.size(), n);
            ASSERT_TRUE(UnpadMethod2(p, bs));
            EXPECT_EQ(p, data);
        }
    std::vector<uint8_t> bad(16, 0);
    EXPECT_FALSE(UnpadMethod2(bad, 16));
    bad[15] = 1;
    EXPECT_FALSE(UnpadMethod2(bad, 16));
}
