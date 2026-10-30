package main

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

// The sb/isb arrays hold the correct S and S^-1. Tables 1 and 3 of
// СТ РК 4009-2025 misprint three cells each (de, ce, 1e for dc, cc, 1c).

var sb = [256]uint8{ /* ded: OK, dif: 4, dip: 7, lin: 32, pow: 7, cor: 0, dst: 112, sac: 116..140, cyc: 256 */
	0xd1, 0xb5, 0xa6, 0x74, 0x2f, 0xb2, 0x03, 0x77, 0xae, 0xb3, 0x60, 0x95, 0xfd, 0xf8, 0xc7, 0xf0,
	0x2b, 0xce, 0xa5, 0x91, 0x4c, 0x6f, 0xf3, 0x4f, 0x82, 0x01, 0x45, 0x76, 0x9f, 0xed, 0x41, 0xfb,
	0xac, 0x4e, 0x5e, 0x04, 0xeb, 0xf9, 0xf1, 0x3a, 0x1f, 0xe2, 0x8e, 0xe7, 0x85, 0x35, 0xdb, 0x52,
	0x78, 0xa1, 0xfc, 0xa2, 0xde, 0x68, 0x02, 0x4d, 0xf6, 0xdd, 0xcf, 0xa3, 0xdc, 0x6b, 0x81, 0x44,
	0x2a, 0x5d, 0x1e, 0xe0, 0x53, 0x71, 0x3b, 0xc1, 0xcc, 0x9d, 0x80, 0xd5, 0x84, 0x00, 0x24, 0x4b,
	0xb6, 0x83, 0x0d, 0x87, 0x7e, 0x86, 0xca, 0x96, 0xbe, 0x5a, 0xe6, 0xd0, 0xd4, 0xd8, 0x55, 0xc0,
	0x05, 0xe5, 0xe9, 0x5b, 0x47, 0xe4, 0x2d, 0x34, 0x13, 0x88, 0x48, 0x32, 0x38, 0xb9, 0xda, 0xc9,
	0x42, 0x29, 0xd7, 0xf2, 0x9b, 0x6d, 0xe8, 0x8d, 0x12, 0x7c, 0x8c, 0x3f, 0xbc, 0x3c, 0x1b, 0xc5,
	0x69, 0x22, 0x97, 0xaa, 0x73, 0x0a, 0x0c, 0x8a, 0x90, 0x31, 0xc4, 0x33, 0xe1, 0x8b, 0x9c, 0x63,
	0x5f, 0xf5, 0xf7, 0xff, 0x79, 0x49, 0xd3, 0xc6, 0x7b, 0x1a, 0x39, 0xc8, 0x6e, 0x72, 0xd9, 0xc3,
	0x62, 0x28, 0xbd, 0xbb, 0xfa, 0x2e, 0xbf, 0x43, 0x06, 0x0b, 0x7a, 0x64, 0x5c, 0x92, 0x37, 0x3d,
	0x66, 0x26, 0x51, 0xef, 0x0f, 0xa9, 0x14, 0x70, 0x16, 0x17, 0x10, 0x19, 0x93, 0x09, 0x59, 0x15,
	0xfe, 0x4a, 0xcb, 0x2c, 0xcd, 0xb8, 0x94, 0xab, 0xdf, 0xa7, 0x0e, 0x30, 0xaf, 0x56, 0x23, 0xb1,
	0xb0, 0x58, 0x7d, 0xc2, 0x1d, 0x50, 0x20, 0x61, 0x25, 0x89, 0xa0, 0x6c, 0x11, 0x54, 0x98, 0xb7,
	0x18, 0x21, 0xad, 0x3e, 0xd2, 0xea, 0x40, 0xd6, 0xf4, 0xa4, 0x8f, 0xa8, 0x08, 0x57, 0xba, 0xee,
	0x75, 0x6a, 0x07, 0x99, 0x7f, 0x1c, 0xe3, 0x46, 0x67, 0xec, 0x27, 0x36, 0xb4, 0x65, 0x9e, 0x9a}
var isb = [256]uint8{
	0x4d, 0x19, 0x36, 0x06, 0x23, 0x60, 0xa8, 0xf2, 0xec, 0xbd, 0x85, 0xa9, 0x86, 0x52, 0xca, 0xb4,
	0xba, 0xdc, 0x78, 0x68, 0xb6, 0xbf, 0xb8, 0xb9, 0xe0, 0xbb, 0x99, 0x7e, 0xf5, 0xd4, 0x42, 0x28,
	0xd6, 0xe1, 0x81, 0xce, 0x4e, 0xd8, 0xb1, 0xfa, 0xa1, 0x71, 0x40, 0x10, 0xc3, 0x66, 0xa5, 0x04,
	0xcb, 0x89, 0x6b, 0x8b, 0x67, 0x2d, 0xfb, 0xae, 0x6c, 0x9a, 0x27, 0x46, 0x7d, 0xaf, 0xe3, 0x7b,
	0xe6, 0x1e, 0x70, 0xa7, 0x3f, 0x1a, 0xf7, 0x64, 0x6a, 0x95, 0xc1, 0x4f, 0x14, 0x37, 0x21, 0x17,
	0xd5, 0xb2, 0x2f, 0x44, 0xdd, 0x5e, 0xcd, 0xed, 0xd1, 0xbe, 0x59, 0x63, 0xac, 0x41, 0x22, 0x90,
	0x0a, 0xd7, 0xa0, 0x8f, 0xab, 0xfd, 0xb0, 0xf8, 0x35, 0x80, 0xf1, 0x3d, 0xdb, 0x75, 0x9c, 0x15,
	0xb7, 0x45, 0x9d, 0x84, 0x03, 0xf0, 0x1b, 0x07, 0x30, 0x94, 0xaa, 0x98, 0x79, 0xd2, 0x54, 0xf4,
	0x4a, 0x3e, 0x18, 0x51, 0x4c, 0x2c, 0x55, 0x53, 0x69, 0xd9, 0x87, 0x8d, 0x7a, 0x77, 0x2a, 0xea,
	0x88, 0x13, 0xad, 0xbc, 0xc6, 0x0b, 0x57, 0x82, 0xde, 0xf3, 0xff, 0x74, 0x8e, 0x49, 0xfe, 0x1c,
	0xda, 0x31, 0x33, 0x3b, 0xe9, 0x12, 0x02, 0xc9, 0xeb, 0xb5, 0x83, 0xc7, 0x20, 0xe2, 0x08, 0xcc,
	0xd0, 0xcf, 0x05, 0x09, 0xfc, 0x01, 0x50, 0xdf, 0xc5, 0x6d, 0xee, 0xa3, 0x7c, 0xa2, 0x58, 0xa6,
	0x5f, 0x47, 0xd3, 0x9f, 0x8a, 0x7f, 0x97, 0x0e, 0x9b, 0x6f, 0x56, 0xc2, 0x48, 0xc4, 0x11, 0x3a,
	0x5b, 0x00, 0xe4, 0x96, 0x5c, 0x4b, 0xe7, 0x72, 0x5d, 0x9e, 0x6e, 0x2e, 0x3c, 0x39, 0x34, 0xc8,
	0x43, 0x8c, 0x29, 0xf6, 0x65, 0x61, 0x5a, 0x2b, 0x76, 0x62, 0xe5, 0x24, 0xf9, 0x1d, 0xef, 0xb3,
	0x0f, 0x26, 0x73, 0x16, 0xe8, 0x91, 0x38, 0x92, 0x0d, 0x25, 0xa4, 0x1f, 0x32, 0x0c, 0xc0, 0x93}

var c0 = [3]int{1, 17, 14}
var c1 = [7]int{3, 5, 11, 21, 16, 30, 19}
var c2 = [7]int{4, 0, 22, 27, 47, 4, 61}

const SHIFT = 17
const MINBLOCKLEN = 16
const MAXBLOCKLEN = 64
const MINKEYLEN = 32
const MAXKEYLEN = 128
const KEYLENSTEP = 16

func RNDS(x int) int {
	return (16 + (x-32)/16)
}
func ROTL(x uint32, s int) uint32 {
	return bits.RotateLeft32(x, s)
}
func ROTL64(x uint64, s int) uint64 {
	return bits.RotateLeft64(x, s)
}

var errParams = errors.New("qalqan: key must be 32..128 bytes in steps of 16, block 16, 32 or 64 bytes")

// validParams checks the key and block lengths (in bytes) of section 5.
func validParams(klen, blen int) bool {
	return klen >= MINKEYLEN && klen <= MAXKEYLEN && klen%KEYLENSTEP == 0 &&
		(blen == 16 || blen == 32 || blen == 64)
}

// Kexp expands key into RNDS(klen) round keys of blen bytes (section 8).
func Kexp(key []uint8, klen int, blen int, rkey []uint8) error {
	if !validParams(klen, blen) || len(key) < klen || len(rkey) < RNDS(klen)*blen {
		return errParams
	}
	var r0 [17]uint8
	var r1 [15]uint8
	var addk = klen - 32
	var step = 0
	var s = SHIFT
	for i := 0; i < 15; i++ {
		r0[i] = key[2*i]
		r1[i] = key[2*i+1]
	}
	r0[15] = key[30]
	r0[16] = key[31]
	for r := 0; r < RNDS(klen); r++ {
		for k := 0; k < blen+s; k++ {
			var t0 = (byte)(sb[r0[0]] + r0[1] + sb[r0[3]] + r0[7] + sb[r0[12]] + r0[16])
			var t1 = (byte)(sb[r1[0]] + r1[3] + sb[r1[9]] + r1[12] + sb[r1[14]])
			for i := 0; i < 14; i++ {
				r0[i] = r0[i+1]
				r1[i] = r1[i+1]
			}
			r0[14] = r0[15]
			r0[15] = r0[16]
			if k >= s {
				rkey[r*blen+k-s] = (byte)(t0 + r1[4])
				if step < addk {
					if (step & 1) != 0 {
						t0 += key[32+step]

					} else {
						t1 += key[32+step]
					}
					step++
				}
			}
			r0[16] = t0
			r1[14] = t1
		}
		s = 0
	}
	clear(r0[:])
	clear(r1[:])
	return nil
}

func lin344(din []uint32, dout []uint32) {
	dout[0] = din[0] ^ ROTL(din[1], c0[0]) ^ ROTL(din[2], c0[1]) ^ ROTL(din[3], c0[2])
	dout[1] = din[1] ^ ROTL(din[2], c0[0]) ^ ROTL(din[3], c0[1]) ^ ROTL(dout[0], c0[2])
	dout[2] = din[2] ^ ROTL(din[3], c0[0]) ^ ROTL(dout[0], c0[1]) ^ ROTL(dout[1], c0[2])
	dout[3] = din[3] ^ ROTL(dout[0], c0[0]) ^ ROTL(dout[1], c0[1]) ^ ROTL(dout[2], c0[2])
}

func lin384(din []uint32, dout []uint32) {
	dout[0] = din[0] ^ ROTL(din[1], c1[0]) ^ ROTL(din[2], c1[1]) ^ ROTL(din[3], c1[2]) ^ ROTL(din[4], c1[3]) ^ ROTL(din[5], c1[4]) ^ ROTL(din[6], c1[5]) ^ ROTL(din[7], c1[6])
	dout[1] = din[1] ^ ROTL(din[2], c1[0]) ^ ROTL(din[3], c1[1]) ^ ROTL(din[4], c1[2]) ^ ROTL(din[5], c1[3]) ^ ROTL(din[6], c1[4]) ^ ROTL(din[7], c1[5]) ^ ROTL(dout[0], c1[6])
	dout[2] = din[2] ^ ROTL(din[3], c1[0]) ^ ROTL(din[4], c1[1]) ^ ROTL(din[5], c1[2]) ^ ROTL(din[6], c1[3]) ^ ROTL(din[7], c1[4]) ^ ROTL(dout[0], c1[5]) ^ ROTL(dout[1], c1[6])
	dout[3] = din[3] ^ ROTL(din[4], c1[0]) ^ ROTL(din[5], c1[1]) ^ ROTL(din[6], c1[2]) ^ ROTL(din[7], c1[3]) ^ ROTL(dout[0], c1[4]) ^ ROTL(dout[1], c1[5]) ^ ROTL(dout[2], c1[6])
	dout[4] = din[4] ^ ROTL(din[5], c1[0]) ^ ROTL(din[6], c1[1]) ^ ROTL(din[7], c1[2]) ^ ROTL(dout[0], c1[3]) ^ ROTL(dout[1], c1[4]) ^ ROTL(dout[2], c1[5]) ^ ROTL(dout[3], c1[6])
	dout[5] = din[5] ^ ROTL(din[6], c1[0]) ^ ROTL(din[7], c1[1]) ^ ROTL(dout[0], c1[2]) ^ ROTL(dout[1], c1[3]) ^ ROTL(dout[2], c1[4]) ^ ROTL(dout[3], c1[5]) ^ ROTL(dout[4], c1[6])
	dout[6] = din[6] ^ ROTL(din[7], c1[0]) ^ ROTL(dout[0], c1[1]) ^ ROTL(dout[1], c1[2]) ^ ROTL(dout[2], c1[3]) ^ ROTL(dout[3], c1[4]) ^ ROTL(dout[4], c1[5]) ^ ROTL(dout[5], c1[6])
	dout[7] = din[7] ^ ROTL(dout[0], c1[0]) ^ ROTL(dout[1], c1[1]) ^ ROTL(dout[2], c1[2]) ^ ROTL(dout[3], c1[3]) ^ ROTL(dout[4], c1[4]) ^ ROTL(dout[5], c1[5]) ^ ROTL(dout[6], c1[6])
}

func lin388(din []uint64, dout []uint64) {
	dout[0] = din[0] ^ ROTL64(din[1], c2[0]) ^ ROTL64(din[2], c2[1]) ^ ROTL64(din[3], c2[2]) ^ ROTL64(din[4], c2[3]) ^ ROTL64(din[5], c2[4]) ^ ROTL64(din[6], c2[5]) ^ ROTL64(din[7], c2[6])
	dout[1] = din[1] ^ ROTL64(din[2], c2[0]) ^ ROTL64(din[3], c2[1]) ^ ROTL64(din[4], c2[2]) ^ ROTL64(din[5], c2[3]) ^ ROTL64(din[6], c2[4]) ^ ROTL64(din[7], c2[5]) ^ ROTL64(dout[0], c2[6])
	dout[2] = din[2] ^ ROTL64(din[3], c2[0]) ^ ROTL64(din[4], c2[1]) ^ ROTL64(din[5], c2[2]) ^ ROTL64(din[6], c2[3]) ^ ROTL64(din[7], c2[4]) ^ ROTL64(dout[0], c2[5]) ^ ROTL64(dout[1], c2[6])
	dout[3] = din[3] ^ ROTL64(din[4], c2[0]) ^ ROTL64(din[5], c2[1]) ^ ROTL64(din[6], c2[2]) ^ ROTL64(din[7], c2[3]) ^ ROTL64(dout[0], c2[4]) ^ ROTL64(dout[1], c2[5]) ^ ROTL64(dout[2], c2[6])
	dout[4] = din[4] ^ ROTL64(din[5], c2[0]) ^ ROTL64(din[6], c2[1]) ^ ROTL64(din[7], c2[2]) ^ ROTL64(dout[0], c2[3]) ^ ROTL64(dout[1], c2[4]) ^ ROTL64(dout[2], c2[5]) ^ ROTL64(dout[3], c2[6])
	dout[5] = din[5] ^ ROTL64(din[6], c2[0]) ^ ROTL64(din[7], c2[1]) ^ ROTL64(dout[0], c2[2]) ^ ROTL64(dout[1], c2[3]) ^ ROTL64(dout[2], c2[4]) ^ ROTL64(dout[3], c2[5]) ^ ROTL64(dout[4], c2[6])
	dout[6] = din[6] ^ ROTL64(din[7], c2[0]) ^ ROTL64(dout[0], c2[1]) ^ ROTL64(dout[1], c2[2]) ^ ROTL64(dout[2], c2[3]) ^ ROTL64(dout[3], c2[4]) ^ ROTL64(dout[4], c2[5]) ^ ROTL64(dout[5], c2[6])
	dout[7] = din[7] ^ ROTL64(dout[0], c2[0]) ^ ROTL64(dout[1], c2[1]) ^ ROTL64(dout[2], c2[2]) ^ ROTL64(dout[3], c2[3]) ^ ROTL64(dout[4], c2[4]) ^ ROTL64(dout[5], c2[5]) ^ ROTL64(dout[6], c2[6])
}

// linOp applies L (formula (1)) to little-endian words, as Appendix A
// requires; the result does not depend on the host byte order.
func linOp(d []uint8, r []uint8, blocklen int) {
	switch blocklen {
	case 16:
		var din, dout [4]uint32
		load32(din[:], d)
		lin344(din[:], dout[:])
		store32(r, dout[:])
	case 32:
		var din, dout [8]uint32
		load32(din[:], d)
		lin384(din[:], dout[:])
		store32(r, dout[:])
	case 64:
		var din, dout [8]uint64
		load64(din[:], d)
		lin388(din[:], dout[:])
		store64(r, dout[:])
	default:
		panic("qalqan: bad block length")
	}
}

func load32(w []uint32, b []uint8) {
	for i := range w {
		w[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
}

func store32(b []uint8, w []uint32) {
	for i := range w {
		binary.LittleEndian.PutUint32(b[4*i:], w[i])
	}
}

func load64(w []uint64, b []uint8) {
	for i := range w {
		w[i] = binary.LittleEndian.Uint64(b[8*i:])
	}
}

func store64(b []uint8, w []uint64) {
	for i := range w {
		binary.LittleEndian.PutUint64(b[8*i:], w[i])
	}
}

func sBox(data []uint8, res []uint8, blen int) {
	for i := 0; i < blen; i++ {
		res[i] = sb[data[i]]
	}
}

func AddRkX(block []uint8, rkey []uint8, nr int, blen int, res []uint8) {
	for i := 0; i < blen; i++ {
		res[i] = (block[i] ^ rkey[nr*blen+i])
	}
}

func AddRk(block []uint8, rkey []uint8, nr int, blen int, res []uint8) {
	tmp := uint16(block[0]) + uint16(rkey[blen*nr])
	res[0] = uint8(tmp)
	tmp >>= 8
	for i := 1; i < blen; i++ {
		tmp += uint16(block[i]) + uint16(rkey[blen*nr+i])
		res[i] = uint8(tmp)
		tmp >>= 8
	}
}

// encrypt implements section 9.1 with N = RNDS(klen) round keys.
func encrypt(data []uint8, rkey []uint8, klen int, blen int, res []uint8) error {
	if !validParams(klen, blen) || len(data) < blen || len(res) < blen || len(rkey) < RNDS(klen)*blen {
		return errParams
	}
	var b1, b2 [MAXBLOCKLEN]uint8
	block, block2 := b1[:blen], b2[:blen]
	AddRk(data, rkey, 0, blen, block)
	sBox(block, block2, blen)
	linOp(block2, block, blen)
	for i := 1; i < RNDS(klen)-1; i++ {
		AddRkX(block, rkey, i, blen, block2)
		sBox(block2, block2, blen)
		linOp(block2, block, blen)
	}
	AddRk(block, rkey, RNDS(klen)-1, blen, res)
	return nil
}

// InvAddRk subtracts round key nr modulo 2^(8*blen), byte 0 least
// significant. (The previous version kept the borrow as 0x00FF after a
// logical shift of a uint16, so every decryption came out wrong.)
func InvAddRk(block []uint8, rkey []uint8, nr int, blen int, res []uint8) {
	var borrow uint16
	for i := 0; i < blen; i++ {
		d := uint16(block[i]) - uint16(rkey[blen*nr+i]) - borrow
		res[i] = uint8(d)
		borrow = (d >> 8) & 1
	}
}

func ilin344(din []uint32, dout []uint32) {
	dout[3] = din[3] ^ ROTL(din[0], c0[0]) ^ ROTL(din[1], c0[1]) ^ ROTL(din[2], c0[2])
	dout[2] = din[2] ^ ROTL(dout[3], c0[0]) ^ ROTL(din[0], c0[1]) ^ ROTL(din[1], c0[2])
	dout[1] = din[1] ^ ROTL(dout[2], c0[0]) ^ ROTL(dout[3], c0[1]) ^ ROTL(din[0], c0[2])
	dout[0] = din[0] ^ ROTL(dout[1], c0[0]) ^ ROTL(dout[2], c0[1]) ^ ROTL(dout[3], c0[2])
}

func ilin384(din []uint32, dout []uint32) {
	dout[7] = din[7] ^ ROTL(din[0], c1[0]) ^ ROTL(din[1], c1[1]) ^ ROTL(din[2], c1[2]) ^ ROTL(din[3], c1[3]) ^ ROTL(din[4], c1[4]) ^ ROTL(din[5], c1[5]) ^ ROTL(din[6], c1[6])
	dout[6] = din[6] ^ ROTL(dout[7], c1[0]) ^ ROTL(din[0], c1[1]) ^ ROTL(din[1], c1[2]) ^ ROTL(din[2], c1[3]) ^ ROTL(din[3], c1[4]) ^ ROTL(din[4], c1[5]) ^ ROTL(din[5], c1[6])
	dout[5] = din[5] ^ ROTL(dout[6], c1[0]) ^ ROTL(dout[7], c1[1]) ^ ROTL(din[0], c1[2]) ^ ROTL(din[1], c1[3]) ^ ROTL(din[2], c1[4]) ^ ROTL(din[3], c1[5]) ^ ROTL(din[4], c1[6])
	dout[4] = din[4] ^ ROTL(dout[5], c1[0]) ^ ROTL(dout[6], c1[1]) ^ ROTL(dout[7], c1[2]) ^ ROTL(din[0], c1[3]) ^ ROTL(din[1], c1[4]) ^ ROTL(din[2], c1[5]) ^ ROTL(din[3], c1[6])
	dout[3] = din[3] ^ ROTL(dout[4], c1[0]) ^ ROTL(dout[5], c1[1]) ^ ROTL(dout[6], c1[2]) ^ ROTL(dout[7], c1[3]) ^ ROTL(din[0], c1[4]) ^ ROTL(din[1], c1[5]) ^ ROTL(din[2], c1[6])
	dout[2] = din[2] ^ ROTL(dout[3], c1[0]) ^ ROTL(dout[4], c1[1]) ^ ROTL(dout[5], c1[2]) ^ ROTL(dout[6], c1[3]) ^ ROTL(dout[7], c1[4]) ^ ROTL(din[0], c1[5]) ^ ROTL(din[1], c1[6])
	dout[1] = din[1] ^ ROTL(dout[2], c1[0]) ^ ROTL(dout[3], c1[1]) ^ ROTL(dout[4], c1[2]) ^ ROTL(dout[5], c1[3]) ^ ROTL(dout[6], c1[4]) ^ ROTL(dout[7], c1[5]) ^ ROTL(din[0], c1[6])
	dout[0] = din[0] ^ ROTL(dout[1], c1[0]) ^ ROTL(dout[2], c1[1]) ^ ROTL(dout[3], c1[2]) ^ ROTL(dout[4], c1[3]) ^ ROTL(dout[5], c1[4]) ^ ROTL(dout[6], c1[5]) ^ ROTL(dout[7], c1[6])
}

func ilin388(din []uint64, dout []uint64) {
	dout[7] = din[7] ^ ROTL64(din[0], c2[0]) ^ ROTL64(din[1], c2[1]) ^ ROTL64(din[2], c2[2]) ^ ROTL64(din[3], c2[3]) ^ ROTL64(din[4], c2[4]) ^ ROTL64(din[5], c2[5]) ^ ROTL64(din[6], c2[6])
	dout[6] = din[6] ^ ROTL64(dout[7], c2[0]) ^ ROTL64(din[0], c2[1]) ^ ROTL64(din[1], c2[2]) ^ ROTL64(din[2], c2[3]) ^ ROTL64(din[3], c2[4]) ^ ROTL64(din[4], c2[5]) ^ ROTL64(din[5], c2[6])
	dout[5] = din[5] ^ ROTL64(dout[6], c2[0]) ^ ROTL64(dout[7], c2[1]) ^ ROTL64(din[0], c2[2]) ^ ROTL64(din[1], c2[3]) ^ ROTL64(din[2], c2[4]) ^ ROTL64(din[3], c2[5]) ^ ROTL64(din[4], c2[6])
	dout[4] = din[4] ^ ROTL64(dout[5], c2[0]) ^ ROTL64(dout[6], c2[1]) ^ ROTL64(dout[7], c2[2]) ^ ROTL64(din[0], c2[3]) ^ ROTL64(din[1], c2[4]) ^ ROTL64(din[2], c2[5]) ^ ROTL64(din[3], c2[6])
	dout[3] = din[3] ^ ROTL64(dout[4], c2[0]) ^ ROTL64(dout[5], c2[1]) ^ ROTL64(dout[6], c2[2]) ^ ROTL64(dout[7], c2[3]) ^ ROTL64(din[0], c2[4]) ^ ROTL64(din[1], c2[5]) ^ ROTL64(din[2], c2[6])
	dout[2] = din[2] ^ ROTL64(dout[3], c2[0]) ^ ROTL64(dout[4], c2[1]) ^ ROTL64(dout[5], c2[2]) ^ ROTL64(dout[6], c2[3]) ^ ROTL64(dout[7], c2[4]) ^ ROTL64(din[0], c2[5]) ^ ROTL64(din[1], c2[6])
	dout[1] = din[1] ^ ROTL64(dout[2], c2[0]) ^ ROTL64(dout[3], c2[1]) ^ ROTL64(dout[4], c2[2]) ^ ROTL64(dout[5], c2[3]) ^ ROTL64(dout[6], c2[4]) ^ ROTL64(dout[7], c2[5]) ^ ROTL64(din[0], c2[6])
	dout[0] = din[0] ^ ROTL64(dout[1], c2[0]) ^ ROTL64(dout[2], c2[1]) ^ ROTL64(dout[3], c2[2]) ^ ROTL64(dout[4], c2[3]) ^ ROTL64(dout[5], c2[4]) ^ ROTL64(dout[6], c2[5]) ^ ROTL64(dout[7], c2[6])
}

func InvlinOp(d []uint8, r []uint8, blocklen int) {
	switch blocklen {
	case 16:
		var din, dout [4]uint32
		load32(din[:], d)
		ilin344(din[:], dout[:])
		store32(r, dout[:])
	case 32:
		var din, dout [8]uint32
		load32(din[:], d)
		ilin384(din[:], dout[:])
		store32(r, dout[:])
	case 64:
		var din, dout [8]uint64
		load64(din[:], d)
		ilin388(din[:], dout[:])
		store64(r, dout[:])
	default:
		panic("qalqan: bad block length")
	}
}

func InvsBox(data []uint8, res []uint8, blen int) {
	for i := 0; i < blen; i++ {
		res[i] = isb[data[i]]
	}
}

// decrypt implements section 9.2.
func decrypt(data []uint8, rkey []uint8, klen int, blen int, res []uint8) error {
	if !validParams(klen, blen) || len(data) < blen || len(res) < blen || len(rkey) < RNDS(klen)*blen {
		return errParams
	}
	var b1, b2 [MAXBLOCKLEN]uint8
	block, block2 := b1[:blen], b2[:blen]
	InvAddRk(data, rkey, RNDS(klen)-1, blen, block)
	for i := RNDS(klen) - 2; i > 0; i-- {
		InvlinOp(block, block2, blen)
		InvsBox(block2, block2, blen)
		AddRkX(block2, rkey, i, blen, block)
	}
	InvlinOp(block, block2, blen)
	InvsBox(block2, block2, blen)
	InvAddRk(block2, rkey, 0, blen, res)
	return nil
}

// Cipher is an expanded key for one block length. It implements
// crypto/cipher.Block, so the modes in modes.go (and those of crypto/cipher)
// can use it.
type Cipher struct {
	klen, blen int
	rkey       []uint8
}

// NewCipher expands key (32..128 bytes, step 16) for a 16-, 32- or 64-byte block.
func NewCipher(key []uint8, blockSize int) (*Cipher, error) {
	if !validParams(len(key), blockSize) {
		return nil, errParams
	}
	c := &Cipher{klen: len(key), blen: blockSize, rkey: make([]uint8, RNDS(len(key))*blockSize)}
	if err := Kexp(key, c.klen, c.blen, c.rkey); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Cipher) BlockSize() int { return c.blen }

// Encrypt encrypts one block; dst and src may be the same slice.
func (c *Cipher) Encrypt(dst, src []byte) {
	if err := encrypt(src, c.rkey, c.klen, c.blen, dst); err != nil {
		panic("qalqan: input or output not a full block")
	}
}

// Decrypt decrypts one block; dst and src may be the same slice.
func (c *Cipher) Decrypt(dst, src []byte) {
	if err := decrypt(src, c.rkey, c.klen, c.blen, dst); err != nil {
		panic("qalqan: input or output not a full block")
	}
}

// Reset wipes the round keys (best effort: the Go runtime may hold copies).
func (c *Cipher) Reset() { clear(c.rkey) }
