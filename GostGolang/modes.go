package main

// Modes of operation of СТ РК ISO/IEC 10116-2019 (the Kazakh adoption of
// ISO/IEC 10116), to which СТ РК 4009-2025, 1.1 refers. They work with any
// cipher.Block, so with all three Qalqan block sizes.
//
// Implemented parameter choices:
//
//	ECB  -
//	CBC  m = 1 (one starting variable)
//	CFB  r = n, j = k = n (full-block feedback; a final partial block is allowed)
//	OFB  j = n
//	CTR  j = n; the counter is the whole n-bit block, incremented modulo 2^n
//	     with the last byte least significant (ISO bit-string convention,
//	     leftmost bit most significant)
//
// The counter convention is not fixed by СТ РК 4009-2025; agree on it with
// the other party (see CONFORMANCE.md). None of these modes authenticates data.
//
// As with crypto/cipher, dst and src must overlap entirely or not at all.

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

type ecb struct {
	b       cipher.Block
	bs      int
	decrypt bool
}

// NewECBEncrypter returns a BlockMode that encrypts in electronic codebook mode.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode { return &ecb{b: b, bs: b.BlockSize()} }

// NewECBDecrypter returns a BlockMode that decrypts in electronic codebook mode.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return &ecb{b: b, bs: b.BlockSize(), decrypt: true}
}

func (x *ecb) BlockSize() int { return x.bs }

func (x *ecb) CryptBlocks(dst, src []byte) {
	checkBlocks(x.bs, dst, src)
	for len(src) > 0 {
		if x.decrypt {
			x.b.Decrypt(dst[:x.bs], src[:x.bs])
		} else {
			x.b.Encrypt(dst[:x.bs], src[:x.bs])
		}
		src, dst = src[x.bs:], dst[x.bs:]
	}
}

type cbc struct {
	b       cipher.Block
	bs      int
	iv, tmp []byte
	decrypt bool
}

func newCBC(b cipher.Block, iv []byte, decrypt bool) *cbc {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("qalqan: IV length must equal block size")
	}
	return &cbc{b: b, bs: bs, iv: append([]byte(nil), iv...), tmp: make([]byte, bs), decrypt: decrypt}
}

// NewCBCEncrypter returns a BlockMode that encrypts in cipher block chaining
// mode with starting variable iv (len(iv) == block size).
func NewCBCEncrypter(b cipher.Block, iv []byte) cipher.BlockMode { return newCBC(b, iv, false) }

// NewCBCDecrypter returns a BlockMode that decrypts in cipher block chaining mode.
func NewCBCDecrypter(b cipher.Block, iv []byte) cipher.BlockMode { return newCBC(b, iv, true) }

func (x *cbc) BlockSize() int { return x.bs }

func (x *cbc) CryptBlocks(dst, src []byte) {
	checkBlocks(x.bs, dst, src)
	bs := x.bs
	for len(src) > 0 {
		if x.decrypt {
			copy(x.tmp, src[:bs]) // keep C_i: dst may be src
			x.b.Decrypt(dst[:bs], src[:bs])
			subtle.XORBytes(dst[:bs], dst[:bs], x.iv)
			x.iv, x.tmp = x.tmp, x.iv
		} else {
			subtle.XORBytes(dst[:bs], src[:bs], x.iv)
			x.b.Encrypt(dst[:bs], dst[:bs])
			copy(x.iv, dst[:bs])
		}
		src, dst = src[bs:], dst[bs:]
	}
}

func checkBlocks(bs int, dst, src []byte) {
	if len(src)%bs != 0 {
		panic("qalqan: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("qalqan: output smaller than input")
	}
}

type ctr struct {
	b       cipher.Block
	ctr     []byte
	out     []byte
	outUsed int
}

// NewCTR returns a Stream for counter mode with initial counter iv
// (len(iv) == block size). Encryption and decryption are the same operation.
// Never reuse a (key, iv) pair, and never let two messages' counter ranges overlap.
func NewCTR(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("qalqan: IV length must equal block size")
	}
	return &ctr{b: b, ctr: append([]byte(nil), iv...), out: make([]byte, bs), outUsed: bs}
}

func (x *ctr) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("qalqan: output smaller than input")
	}
	for len(src) > 0 {
		if x.outUsed == len(x.out) {
			x.b.Encrypt(x.out, x.ctr)
			for i := len(x.ctr) - 1; i >= 0; i-- { // CTR_{i+1} = CTR_i + 1 mod 2^n
				x.ctr[i]++
				if x.ctr[i] != 0 {
					break
				}
			}
			x.outUsed = 0
		}
		n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
		dst, src = dst[n:], src[n:]
		x.outUsed += n
	}
}

type ofb struct {
	b       cipher.Block
	reg     []byte
	outUsed int
}

// NewOFB returns a Stream for output feedback mode with starting variable iv.
// Encryption and decryption are the same operation.
func NewOFB(b cipher.Block, iv []byte) cipher.Stream {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("qalqan: IV length must equal block size")
	}
	return &ofb{b: b, reg: append([]byte(nil), iv...), outUsed: bs}
}

func (x *ofb) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("qalqan: output smaller than input")
	}
	for len(src) > 0 {
		if x.outUsed == len(x.reg) {
			x.b.Encrypt(x.reg, x.reg) // Y_i = e_K(Y_{i-1})
			x.outUsed = 0
		}
		n := subtle.XORBytes(dst, src, x.reg[x.outUsed:])
		dst, src = dst[n:], src[n:]
		x.outUsed += n
	}
}

type cfb struct {
	b         cipher.Block
	next, out []byte
	outUsed   int
	decrypt   bool
}

func newCFB(b cipher.Block, iv []byte, decrypt bool) *cfb {
	bs := b.BlockSize()
	if len(iv) != bs {
		panic("qalqan: IV length must equal block size")
	}
	return &cfb{b: b, next: append([]byte(nil), iv...), out: make([]byte, bs), outUsed: bs, decrypt: decrypt}
}

// NewCFBEncrypter returns a Stream that encrypts in full-block cipher feedback mode.
func NewCFBEncrypter(b cipher.Block, iv []byte) cipher.Stream { return newCFB(b, iv, false) }

// NewCFBDecrypter returns a Stream that decrypts in full-block cipher feedback mode.
func NewCFBDecrypter(b cipher.Block, iv []byte) cipher.Stream { return newCFB(b, iv, true) }

func (x *cfb) XORKeyStream(dst, src []byte) {
	if len(dst) < len(src) {
		panic("qalqan: output smaller than input")
	}
	for len(src) > 0 {
		if x.outUsed == len(x.out) {
			x.b.Encrypt(x.out, x.next)
			x.outUsed = 0
		}
		if x.decrypt {
			copy(x.next[x.outUsed:], src) // ciphertext is the feedback; save it before dst overwrites src
		}
		n := subtle.XORBytes(dst, src, x.out[x.outUsed:])
		if !x.decrypt {
			copy(x.next[x.outUsed:], dst[:n])
		}
		dst, src = dst[n:], src[n:]
		x.outUsed += n
	}
}

// ErrPadding is returned by Unpad for input that is not correctly padded.
var ErrPadding = errors.New("qalqan: invalid padding")

// Pad appends ISO/IEC 9797-1 padding method 2 (a 0x80 byte, then zero bytes
// up to a multiple of blockSize) for use with ECB or CBC. СТ РК 4009-2025 does
// not prescribe a padding method; agree on one with the other party.
func Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+n)
	copy(out, data)
	out[len(data)] = 0x80
	return out
}

// Unpad removes padding added by Pad. The scan over the last block does not
// branch on its contents, but a padding error is still an oracle unless the
// ciphertext is authenticated before decryption.
func Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, ErrPadding
	}
	last := data[len(data)-blockSize:]
	pos := -1  // index of the 0x80 marker within the last block
	found := 0 // 1 once the marker has been seen (scanning from the end)
	valid := 1 // stays 1 while only zero bytes precede the marker
	for i := len(last) - 1; i >= 0; i-- {
		b := int(last[i])
		isZero := subtle.ConstantTimeByteEq(byte(b), 0)
		isMark := subtle.ConstantTimeByteEq(byte(b), 0x80)
		notFound := 1 - found
		// before the marker every byte must be zero or be the marker itself
		valid &= subtle.ConstantTimeSelect(notFound, isZero|isMark, 1)
		take := notFound & isMark
		pos = subtle.ConstantTimeSelect(take, i, pos)
		found |= take
	}
	if valid&found != 1 {
		return nil, ErrPadding
	}
	return data[:len(data)-blockSize+pos], nil
}
