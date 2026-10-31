#include "Modes.h"
#include "QalqanInternal.h" // only for controlled low-level invalid-argument probes
#include <array>
#include <vector>
#include <stdexcept>
#include <climits>
#include <cstdio>
#include <algorithm>
#include <string>
#include <sstream>
#include <fstream>
#include <cstdlib>

#ifndef QALQAN_RESOURCES
#define QALQAN_RESOURCES "resources"
#endif
static std::vector<uint8_t> parseHex(const std::string& src)
{
    std::vector<uint8_t> v;
    if (src == "-") return v;
    if (src.size() % 2 != 0) throw std::runtime_error("hex uneven length");
    for (size_t i=0; i<src.size(); i+=2)
    {
        v.push_back(static_cast<uint8_t>(std::stoul(src.substr(i,2),nullptr,16)));
    }
    return v;
}

template<typename F> static void mustThrow(F f, const char* name)
{
    bool caught = false;
    try { f(); } catch (const std::invalid_argument&) { caught = true; }
    if (!caught) { std::fprintf(stderr, "FAIL expected invalid_argument: %s\n", name); std::abort(); }
}
static void require(bool cond, const char* name)
{
    if (!cond) { std::fprintf(stderr, "FAIL: %s\n", name); std::abort(); }
}
int main()
{
    std::array<uint8_t, MAXKEYLEN> key{};
    std::array<uint8_t, MAXBLOCKLEN> in{}, out{};
    std::array<uint8_t, MAXBLOCKLEN+1> shared{};
    std::array<uint8_t, RNDS(MAXKEYLEN)*MAXBLOCKLEN> rk{};
    for (size_t j = 0; j < key.size(); j++) key[j] = static_cast<uint8_t>(j+1);
    for (size_t j = 0; j < in.size(); j++) in[j] = static_cast<uint8_t>(j*7+2);
    // Invalid key lengths and wrong block sizes reject BEFORE touching key.
    mustThrow([&]{ QalqanCipher c(std::span<const uint8_t>(key.data(), 31), 16); }, "bad key span");
    mustThrow([&]{ QalqanCipher c(std::span<const uint8_t>(key.data(), 32), 24); }, "bad block size");
    require(!Kexp(nullptr, 32, 16, rk.data()), "null raw key safely rejected");
    for (size_t bs : {size_t(16), size_t(32), size_t(64)})
        for (size_t kl = 32; kl <= MAXKEYLEN; kl += 16)
        {
            QalqanCipher c(std::span<const uint8_t>(key.data(),kl), bs);
            std::fill(out.begin(),out.end(),0x5a);
            mustThrow([&]{ c.EncryptBlock({in.data(),bs-1},{out.data(),bs}); }, "short input");
            require(std::all_of(out.begin(),out.end(),[](uint8_t x){return x==0x5a;}), "no output mutation on bad input");
            mustThrow([&]{ c.EncryptBlock({in.data(),bs},{out.data(),bs-1}); }, "short output");
            mustThrow([&]{ c.EncryptBlock({shared.data(),bs},{shared.data()+1,bs}); }, "partial overlap");
            c.EncryptBlock({in.data(),bs},{out.data(),bs});
            auto actual = out;
            c.DecryptBlock({out.data(),bs},{out.data(),bs});
            require(std::equal(in.begin(),in.begin()+bs,out.begin()), "encrypt/decrypt roundtrip");
            c.EncryptBlock({in.data(),bs},{in.data(),bs});
            require(std::equal(actual.begin(),actual.begin()+bs,in.begin()), "in-place encrypt matches");
            // Reset plaintext for next iteration
            c.DecryptBlock({in.data(),bs},{in.data(),bs});
        }
    {
        QalqanCipher c(std::span<const uint8_t>(key.data(),32),16);
        std::array<uint8_t,16> iv{};
        std::array<uint8_t,32> b{};
        mustThrow([&]{ CtrCrypt(c,{iv.data(),15},{b.data(),16},{b.data(),16}); }, "short CTR IV");
        mustThrow([&]{ CbcEncrypt(c,iv,{b.data(),16},{b.data(),15}); }, "short CBC output");
        mustThrow([&]{ EcbEncrypt(c,{b.data(),17},{b.data(),17}); }, "ECB nonwhole");
        mustThrow([&]{ OfbCrypt(c,iv,{b.data(),16},{b.data()+1,16}); }, "mode partial overlap");
        CtrCrypt(c,iv,{b.data(),17},{b.data(),17}); // in-place is permitted
    }
    mustThrow([&]{ AddRkX(in.data(),rk.data(), INT_MAX, 2,out.data()); }, "reject round offset overflow");
    mustThrow([&]{ AddRk(in.data(),rk.data(), INT_MAX,16,out.data()); }, "reject add round overflow");
    mustThrow([&]{ InvAddRk(in.data(),rk.data(), -1,16,out.data()); }, "reject negative round");
    mustThrow([&]{ linOp(in.data(),out.data(),24); }, "invalid linear block size");
    mustThrow([&]{ InvlinOp(in.data(),out.data(),24); }, "invalid inverse linear block size");
    mustThrow([&]{ PadMethod2(std::span<const uint8_t>{},0); }, "zero pad size");
    std::vector<uint8_t> padded(16,0);
    mustThrow([&]{ UnpadMethod2(padded,0); }, "zero unpad size");
    for (size_t bs : {size_t(16),size_t(32),size_t(64)})
    {
        std::vector<uint8_t> empty;
        auto p = PadMethod2(empty, bs);
        require(p.size()==bs && p.front()==0x80, "pad empty");
        require(UnpadMethod2(p,bs) && p.empty(), "unpad empty");
    }
    size_t referenceKats = 0;
    {
        std::ifstream fin(std::string(QALQAN_RESOURCES) + "/reference_kat.txt");
        require(fin.good(), "reference KAT file readable");
        std::string line;
        while (std::getline(fin,line))
        {
            if (line.empty() || line[0] == '#') continue;
            std::istringstream ls(line);
            int keybits=0,blockbits=0;
            std::string kh,ph,ch;
            require(static_cast<bool>(ls>>keybits>>blockbits>>kh>>ph>>ch), "reference KAT parses");
            auto k=parseHex(kh), pt=parseHex(ph), expected=parseHex(ch);
            require(k.size()*8==static_cast<size_t>(keybits) &&
                    pt.size()*8==static_cast<size_t>(blockbits), "reference KAT lengths");
            QalqanCipher c(k,pt.size());
            std::vector<uint8_t> ct(pt.size()),back(pt.size());
            c.EncryptBlock(pt,ct);
            require(ct==expected, "reference KAT ciphertext");
            c.DecryptBlock(ct,back);
            require(back==pt, "reference KAT decrypted text");
            referenceKats++;
        }
        require(referenceKats==84, "84 reference KATs");
    }
    size_t modesKats = 0;
    {
        std::ifstream fin(std::string(QALQAN_RESOURCES) + "/modes_kat.txt");
        require(fin.good(), "mode KAT file readable");
        std::string line;
        while (std::getline(fin,line))
        {
            if (line.empty() || line[0]=='#') continue;
            std::istringstream ls(line);
            std::string mode,keybits,blockbits,kh,ih,ph,ch;
            require(static_cast<bool>(ls>>mode>>keybits>>blockbits>>kh>>ih>>ph>>ch), "mode KAT parses");
            auto k=parseHex(kh),iv=parseHex(ih),pt=parseHex(ph),expected=parseHex(ch);
            QalqanCipher c(k,static_cast<size_t>(std::stoul(blockbits))/8);
            std::vector<uint8_t> ct(pt.size()),back(pt.size());
            if (mode=="ECB") { EcbEncrypt(c,pt,ct); EcbDecrypt(c,expected,back); }
            else if (mode=="CBC") { CbcEncrypt(c,iv,pt,ct); CbcDecrypt(c,iv,expected,back); }
            else if (mode=="CFB") { CfbEncrypt(c,iv,pt,ct); CfbDecrypt(c,iv,expected,back); }
            else if (mode=="OFB") { OfbCrypt(c,iv,pt,ct); OfbCrypt(c,iv,expected,back); }
            else if (mode=="CTR") { CtrCrypt(c,iv,pt,ct); CtrCrypt(c,iv,expected,back); }
            else require(false, "known mode name");
            require(ct==expected, "mode KAT ciphertext");
            require(back==pt, "mode KAT plaintext");
            modesKats++;
        }
        require(modesKats==54, "54 mode KATs");
    }
    std::printf("PASS: Qalqan v20 C++ safety gate; %zu reference KAT; %zu mode KAT\n", referenceKats,modesKats);
    // End safety gate
}
