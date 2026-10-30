-- СТ РК 4009-2025 block cipher (Qalqan): key schedule, rounds, encryption
-- and decryption for 128/256/512-bit blocks and 256..1024-bit keys.
-- Byte 0 of a block is least significant for the modulo-2^n key additions
-- and the linear transform works on little-endian words (Appendix A).

-- S (Table 1) and S^-1 (Table 3) with the correct values; the printed tables
-- misprint three cells each ("de", "ce", "1e" for dc, cc, 1c).
def sb : Array UInt8 :=
    #[ -- ded: OK, dif: 4, dip: 7, lin: 32, pow: 7, cor: 0, dst: 112, sac: 116..140, cyc: 256
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
        0x75, 0x6a, 0x07, 0x99, 0x7f, 0x1c, 0xe3, 0x46, 0x67, 0xec, 0x27, 0x36, 0xb4, 0x65, 0x9e, 0x9a
    ]
def isb : Array UInt8 :=
    #[
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
        0x0f, 0x26, 0x73, 0x16, 0xe8, 0x91, 0x38, 0x92, 0x0d, 0x25, 0xa4, 0x1f, 0x32, 0x0c, 0xc0, 0x93
    ]
-- Shift constants of Table 2.
def c0 : Array Nat := #[ 1, 17, 14 ]
def c1 : Array Nat := #[ 3, 5, 11, 21, 16, 30, 19 ]
def c2 : Array Nat := #[ 4, 0, 22, 27, 47, 4, 61 ]

def SHIFT := 17
def MINBLOCKLEN := 16
def MAXBLOCKLEN := 64
def MINKEYLEN := 32
def MAXKEYLEN := 128
def KEYLENSTEP := 16

/-- Number of round keys N = 16 + (KLen - 256) / 128 (key length in bytes). -/
def RNDS (x : Nat) : Nat := 16 + (x - 32) / 16

/-- Key length 32..128 bytes in steps of 16, block length 16, 32 or 64 bytes (section 5). -/
def validParams (klen blen : Nat) : Bool :=
  MINKEYLEN ≤ klen && klen ≤ MAXKEYLEN && klen % KEYLENSTEP == 0 && (blen == 16 || blen == 32 || blen == 64)

def rotl32 (x : UInt32) (s : Nat) : UInt32 :=
  if s % 32 == 0 then x else (x <<< UInt32.ofNat s) ||| (x >>> UInt32.ofNat (32 - s))

def rotl64 (x : UInt64) (s : Nat) : UInt64 :=
  if s % 64 == 0 then x else (x <<< UInt64.ofNat s) ||| (x >>> UInt64.ofNat (64 - s))

def sbox (x : UInt8) : UInt8 := sb[x.toNat]!
def invSbox (x : UInt8) : UInt8 := isb[x.toNat]!

/-! ### Key schedule (section 8) -/

/-- The byte shift registers L0 (17 cells) and L1 (15 cells). -/
structure KeyRegs where
  l0 : Array UInt8
  l1 : Array UInt8

/-- L0 = {K0, K2, ..., K28, K30, K31}, L1 = {K1, K3, ..., K29}. -/
def KeyRegs.load (key : Array UInt8) : KeyRegs :=
  { l0 := (List.range 15).toArray.map (fun i => key[2 * i]!) ++ #[key[30]!, key[31]!]
    l1 := (List.range 15).toArray.map (fun i => key[2 * i + 1]!) }

/-- Feedback bytes (sums modulo 256):
    t0 = S(L0_0) + L0_1 + S(L0_3) + L0_7 + S(L0_12) + L0_16,
    t1 = S(L1_0) + L1_3 + S(L1_9) + L1_12 + S(L1_14). -/
def KeyRegs.feedback (r : KeyRegs) : UInt8 × UInt8 :=
  (sbox r.l0[0]! + r.l0[1]! + sbox r.l0[3]! + r.l0[7]! + sbox r.l0[12]! + r.l0[16]!,
   sbox r.l1[0]! + r.l1[3]! + sbox r.l1[9]! + r.l1[12]! + sbox r.l1[14]!)

/-- Moves both registers one cell towards index 0; the last cells keep their
    old value until `store` writes the new feedback bytes. -/
def KeyRegs.shift (r : KeyRegs) : KeyRegs :=
  { l0 := r.l0.extract 1 17 ++ #[r.l0[16]!], l1 := r.l1.extract 1 15 ++ #[r.l1[14]!] }

def KeyRegs.store (r : KeyRegs) (t0 t1 : UInt8) : KeyRegs :=
  { l0 := r.l0.set! 16 t0, l1 := r.l1.set! 14 t1 }

/-- Round keys: RNDS(klen) * blen bytes. After 17 warm-up steps each step
    yields the L0 feedback ∔ L1_4; key bytes beyond 256 bits are added to the
    L1 feedback on even steps and to the L0 feedback on odd steps, after the
    round-key byte is taken. -/
def kexp (key : Array UInt8) (blen : Nat) : Array UInt8 := Id.run do
  let extra := key.size - 32
  let mut r := KeyRegs.load key
  for _ in [0:SHIFT] do
    let (t0, t1) := r.feedback
    r := r.shift.store t0 t1
  let n := RNDS key.size * blen
  let mut rk : Array UInt8 := Array.mkEmpty n
  for j in [0:n] do
    let (t0, t1) := r.feedback
    let s := r.shift
    rk := rk.push (t0 + s.l1[4]!)
    let (t0, t1) :=
      if j < extra then
        if j % 2 == 0 then (t0, t1 + key[32 + j]!) else (t0 + key[32 + j]!, t1)
      else (t0, t1)
    r := s.store t0 t1
  return rk

/-! ### Round operations -/

def load32 (b : Array UInt8) (i : Nat) : UInt32 :=
  (b[4 * i]!).toUInt32 ||| ((b[4 * i + 1]!).toUInt32 <<< 8) |||
  ((b[4 * i + 2]!).toUInt32 <<< 16) ||| ((b[4 * i + 3]!).toUInt32 <<< 24)

def load64 (b : Array UInt8) (i : Nat) : UInt64 :=
  (load32 b (2 * i)).toUInt64 ||| ((load32 b (2 * i + 1)).toUInt64 <<< 32)

def bytes32 (w : Array UInt32) : Array UInt8 :=
  w.concatMap fun (x : UInt32) => #[x.toUInt8, (x >>> 8).toUInt8, (x >>> 16).toUInt8, (x >>> 24).toUInt8]

def bytes64 (w : Array UInt64) : Array UInt8 :=
  bytes32 (w.concatMap fun (x : UInt64) => #[x.toUInt32, (x >>> 32).toUInt32])

/-- Formula (1) (or (2) when `inverse`): for i = 0..n-1 (n-1..0),
    Word_i ^= XOR_{j=1}^{n-1} (Word_{(i+j) mod n} <<< C_{j-1}). -/
def mixWords {α : Type} [Xor α] [Inhabited α] (rot : α → Nat → α) (w : Array α) (c : Array Nat) (inverse : Bool) : Array α := Id.run do
  let n := w.size
  let mut w := w
  for k in [0:n] do
    let i := if inverse then n - 1 - k else k
    let mut x := w[i]!
    for j in [1:n] do
      x := x ^^^ rot w[(i + j) % n]! c[j - 1]!
    w := w.set! i x
  return w

/-- The linear transform L (or L^-1) on a block of 16, 32 or 64 bytes. -/
def linear (b : Array UInt8) (inverse : Bool := false) : Array UInt8 :=
  match b.size with
  | 16 => bytes32 (mixWords rotl32 ((List.range 4).toArray.map (load32 b)) c0 inverse)
  | 32 => bytes32 (mixWords rotl32 ((List.range 8).toArray.map (load32 b)) c1 inverse)
  | 64 => bytes64 (mixWords rotl64 ((List.range 8).toArray.map (load64 b)) c2 inverse)
  | _ => b

def subBytes (b : Array UInt8) : Array UInt8 := b.map sbox
def invSubBytes (b : Array UInt8) : Array UInt8 := b.map invSbox

def xorBytes (a b : Array UInt8) : Array UInt8 :=
  (List.range a.size).toArray.map fun i => a[i]! ^^^ b[i]!

/-- a + k modulo 2^(8*size), byte 0 least significant (K^start, K^fin). -/
def addMod (a k : Array UInt8) : Array UInt8 := Id.run do
  let mut out : Array UInt8 := Array.mkEmpty a.size
  let mut carry := 0
  for i in [0:a.size] do
    let s := a[i]!.toNat + k[i]!.toNat + carry
    out := out.push (UInt8.ofNat s)
    carry := s / 256
  return out

/-- a - k modulo 2^(8*size), byte 0 least significant. -/
def subMod (a k : Array UInt8) : Array UInt8 := Id.run do
  let mut out : Array UInt8 := Array.mkEmpty a.size
  let mut borrow := 0
  for i in [0:a.size] do
    let d := a[i]!.toNat + 256 - k[i]!.toNat - borrow
    out := out.push (UInt8.ofNat d)
    borrow := if d < 256 then 1 else 0
  return out

def roundKey (rk : Array UInt8) (blen i : Nat) : Array UInt8 := rk.extract (i * blen) ((i + 1) * blen)

/-! ### Cipher (section 9) -/

structure Cipher where
  klen : Nat
  blen : Nat
  rk : Array UInt8

/-- `none` unless the key is 32..128 bytes (step 16) and the block 16, 32 or 64 bytes. -/
def Cipher.new? (key : Array UInt8) (blen : Nat) : Option Cipher :=
  if validParams key.size blen then some { klen := key.size, blen, rk := kexp key blen } else none

def Cipher.rounds (c : Cipher) : Nat := RNDS c.klen

/-- Encryption: K^start ⊞, S, L; XSL with K_1..K_{N-2}; K^fin ⊞. -/
def Cipher.encrypt (c : Cipher) (pt : Array UInt8) : Array UInt8 := Id.run do
  let n := c.rounds
  let mut s := linear (subBytes (addMod pt (roundKey c.rk c.blen 0)))
  for i in [1:n - 1] do
    s := linear (subBytes (xorBytes s (roundKey c.rk c.blen i)))
  return addMod s (roundKey c.rk c.blen (n - 1))

def Cipher.decrypt (c : Cipher) (ct : Array UInt8) : Array UInt8 := Id.run do
  let n := c.rounds
  let mut s := subMod ct (roundKey c.rk c.blen (n - 1))
  for k in [1:n - 1] do
    let i := n - 1 - k -- N-2 down to 1
    s := xorBytes (invSubBytes (linear s (inverse := true))) (roundKey c.rk c.blen i)
  return subMod (invSubBytes (linear s (inverse := true))) (roundKey c.rk c.blen 0)
