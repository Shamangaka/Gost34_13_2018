module Qalqan
open Prims

(* СТ РК 4009-2025 block cipher (Qalqan) as a total, executable specification:
   key schedule, L / L^-1, encryption and decryption for 128/256/512-bit blocks
   and 256..1024-bit keys, plus the ISO/IEC 10116 modes (Qalqan.Modes).
   Qalqan.Test checks Appendix A values by normalisation (assert_norm).
   Byte 0 is least significant for the modulo-2^n key additions and the
   linear transform uses little-endian words (Appendix A). *)

module U8 = FStar.UInt8
module U32 = FStar.UInt32
module U64 = FStar.UInt64
module L = FStar.List.Tot
open FStar.List.Tot
open FStar.Mul

(* S (Table 1) and S^-1 (Table 3) with the correct values; the printed tables
   misprint three cells each ("de", "ce", "1e" for dc, cc, 1c). *)
//[@@extract_as (`(fun (x: nat) -> "not a number"))]
[@@"opaque_to_smt"]
let sb : list UInt8.t  = [
  (* ded: OK, dif: 4, dip: 7, lin: 32, pow: 7, cor: 0, dst: 112, sac: 116..140, cyc: 256 *)
      0xd1uy; 0xb5uy; 0xa6uy; 0x74uy; 0x2fuy; 0xb2uy; 0x03uy; 0x77uy; 0xaeuy; 0xb3uy; 0x60uy; 0x95uy; 0xfduy; 0xf8uy; 0xc7uy; 0xf0uy;
      0x2buy; 0xceuy; 0xa5uy; 0x91uy; 0x4cuy; 0x6fuy; 0xf3uy; 0x4fuy; 0x82uy; 0x01uy; 0x45uy; 0x76uy; 0x9fuy; 0xeduy; 0x41uy; 0xfbuy;
      0xacuy; 0x4euy; 0x5euy; 0x04uy; 0xebuy; 0xf9uy; 0xf1uy; 0x3auy; 0x1fuy; 0xe2uy; 0x8euy; 0xe7uy; 0x85uy; 0x35uy; 0xdbuy; 0x52uy;
      0x78uy; 0xa1uy; 0xfcuy; 0xa2uy; 0xdeuy; 0x68uy; 0x02uy; 0x4duy; 0xf6uy; 0xdduy; 0xcfuy; 0xa3uy; 0xdcuy; 0x6buy; 0x81uy; 0x44uy;
      0x2auy; 0x5duy; 0x1euy; 0xe0uy; 0x53uy; 0x71uy; 0x3buy; 0xc1uy; 0xccuy; 0x9duy; 0x80uy; 0xd5uy; 0x84uy; 0x00uy; 0x24uy; 0x4buy;
      0xb6uy; 0x83uy; 0x0duy; 0x87uy; 0x7euy; 0x86uy; 0xcauy; 0x96uy; 0xbeuy; 0x5auy; 0xe6uy; 0xd0uy; 0xd4uy; 0xd8uy; 0x55uy; 0xc0uy;
      0x05uy; 0xe5uy; 0xe9uy; 0x5buy; 0x47uy; 0xe4uy; 0x2duy; 0x34uy; 0x13uy; 0x88uy; 0x48uy; 0x32uy; 0x38uy; 0xb9uy; 0xdauy; 0xc9uy;
      0x42uy; 0x29uy; 0xd7uy; 0xf2uy; 0x9buy; 0x6duy; 0xe8uy; 0x8duy; 0x12uy; 0x7cuy; 0x8cuy; 0x3fuy; 0xbcuy; 0x3cuy; 0x1buy; 0xc5uy;
      0x69uy; 0x22uy; 0x97uy; 0xaauy; 0x73uy; 0x0auy; 0x0cuy; 0x8auy; 0x90uy; 0x31uy; 0xc4uy; 0x33uy; 0xe1uy; 0x8buy; 0x9cuy; 0x63uy;
      0x5fuy; 0xf5uy; 0xf7uy; 0xffuy; 0x79uy; 0x49uy; 0xd3uy; 0xc6uy; 0x7buy; 0x1auy; 0x39uy; 0xc8uy; 0x6euy; 0x72uy; 0xd9uy; 0xc3uy;
      0x62uy; 0x28uy; 0xbduy; 0xbbuy; 0xfauy; 0x2euy; 0xbfuy; 0x43uy; 0x06uy; 0x0buy; 0x7auy; 0x64uy; 0x5cuy; 0x92uy; 0x37uy; 0x3duy;
      0x66uy; 0x26uy; 0x51uy; 0xefuy; 0x0fuy; 0xa9uy; 0x14uy; 0x70uy; 0x16uy; 0x17uy; 0x10uy; 0x19uy; 0x93uy; 0x09uy; 0x59uy; 0x15uy;
      0xfeuy; 0x4auy; 0xcbuy; 0x2cuy; 0xcduy; 0xb8uy; 0x94uy; 0xabuy; 0xdfuy; 0xa7uy; 0x0euy; 0x30uy; 0xafuy; 0x56uy; 0x23uy; 0xb1uy;
      0xb0uy; 0x58uy; 0x7duy; 0xc2uy; 0x1duy; 0x50uy; 0x20uy; 0x61uy; 0x25uy; 0x89uy; 0xa0uy; 0x6cuy; 0x11uy; 0x54uy; 0x98uy; 0xb7uy;
      0x18uy; 0x21uy; 0xaduy; 0x3euy; 0xd2uy; 0xeauy; 0x40uy; 0xd6uy; 0xf4uy; 0xa4uy; 0x8fuy; 0xa8uy; 0x08uy; 0x57uy; 0xbauy; 0xeeuy;
      0x75uy; 0x6auy; 0x07uy; 0x99uy; 0x7fuy; 0x1cuy; 0xe3uy; 0x46uy; 0x67uy; 0xecuy; 0x27uy; 0x36uy; 0xb4uy; 0x65uy; 0x9euy; 0x9auy
]

[@@"opaque_to_smt"]
let isb : list UInt8.t = [
        0x4duy; 0x19uy; 0x36uy; 0x06uy; 0x23uy; 0x60uy; 0xa8uy; 0xf2uy; 0xecuy; 0xbduy; 0x85uy; 0xa9uy; 0x86uy; 0x52uy; 0xcauy; 0xb4uy;
        0xbauy; 0xdcuy; 0x78uy; 0x68uy; 0xb6uy; 0xbfuy; 0xb8uy; 0xb9uy; 0xe0uy; 0xbbuy; 0x99uy; 0x7euy; 0xf5uy; 0xd4uy; 0x42uy; 0x28uy;
        0xd6uy; 0xe1uy; 0x81uy; 0xceuy; 0x4euy; 0xd8uy; 0xb1uy; 0xfauy; 0xa1uy; 0x71uy; 0x40uy; 0x10uy; 0xc3uy; 0x66uy; 0xa5uy; 0x04uy;
        0xcbuy; 0x89uy; 0x6buy; 0x8buy; 0x67uy; 0x2duy; 0xfbuy; 0xaeuy; 0x6cuy; 0x9auy; 0x27uy; 0x46uy; 0x7duy; 0xafuy; 0xe3uy; 0x7buy;
        0xe6uy; 0x1euy; 0x70uy; 0xa7uy; 0x3fuy; 0x1auy; 0xf7uy; 0x64uy; 0x6auy; 0x95uy; 0xc1uy; 0x4fuy; 0x14uy; 0x37uy; 0x21uy; 0x17uy;
        0xd5uy; 0xb2uy; 0x2fuy; 0x44uy; 0xdduy; 0x5euy; 0xcduy; 0xeduy; 0xd1uy; 0xbeuy; 0x59uy; 0x63uy; 0xacuy; 0x41uy; 0x22uy; 0x90uy;
        0x0auy; 0xd7uy; 0xa0uy; 0x8fuy; 0xabuy; 0xfduy; 0xb0uy; 0xf8uy; 0x35uy; 0x80uy; 0xf1uy; 0x3duy; 0xdbuy; 0x75uy; 0x9cuy; 0x15uy;
        0xb7uy; 0x45uy; 0x9duy; 0x84uy; 0x03uy; 0xf0uy; 0x1buy; 0x07uy; 0x30uy; 0x94uy; 0xaauy; 0x98uy; 0x79uy; 0xd2uy; 0x54uy; 0xf4uy;
        0x4auy; 0x3euy; 0x18uy; 0x51uy; 0x4cuy; 0x2cuy; 0x55uy; 0x53uy; 0x69uy; 0xd9uy; 0x87uy; 0x8duy; 0x7auy; 0x77uy; 0x2auy; 0xeauy;
        0x88uy; 0x13uy; 0xaduy; 0xbcuy; 0xc6uy; 0x0buy; 0x57uy; 0x82uy; 0xdeuy; 0xf3uy; 0xffuy; 0x74uy; 0x8euy; 0x49uy; 0xfeuy; 0x1cuy;
        0xdauy; 0x31uy; 0x33uy; 0x3buy; 0xe9uy; 0x12uy; 0x02uy; 0xc9uy; 0xebuy; 0xb5uy; 0x83uy; 0xc7uy; 0x20uy; 0xe2uy; 0x08uy; 0xccuy;
        0xd0uy; 0xcfuy; 0x05uy; 0x09uy; 0xfcuy; 0x01uy; 0x50uy; 0xdfuy; 0xc5uy; 0x6duy; 0xeeuy; 0xa3uy; 0x7cuy; 0xa2uy; 0x58uy; 0xa6uy;
        0x5fuy; 0x47uy; 0xd3uy; 0x9fuy; 0x8auy; 0x7fuy; 0x97uy; 0x0euy; 0x9buy; 0x6fuy; 0x56uy; 0xc2uy; 0x48uy; 0xc4uy; 0x11uy; 0x3auy;
        0x5buy; 0x00uy; 0xe4uy; 0x96uy; 0x5cuy; 0x4buy; 0xe7uy; 0x72uy; 0x5duy; 0x9euy; 0x6euy; 0x2euy; 0x3cuy; 0x39uy; 0x34uy; 0xc8uy;
        0x43uy; 0x8cuy; 0x29uy; 0xf6uy; 0x65uy; 0x61uy; 0x5auy; 0x2buy; 0x76uy; 0x62uy; 0xe5uy; 0x24uy; 0xf9uy; 0x1duy; 0xefuy; 0xb3uy;
        0x0fuy; 0x26uy; 0x73uy; 0x16uy; 0xe8uy; 0x91uy; 0x38uy; 0x92uy; 0x0duy; 0x25uy; 0xa4uy; 0x1fuy; 0x32uy; 0x0cuy; 0xc0uy; 0x93uy;
    ]

let c0 : list nat = [ 1; 17; 14 ]
let c1 : list nat = [ 3; 5; 11; 21; 16; 30; 19 ]
let c2 : list nat = [ 4; 0; 22; 27; 47; 4; 61 ]

let _SHIFT = 17
let _MINBLOCKLEN = 16
let _MAXBLOCKLEN = 64
let _MINKEYLEN = 32
let _MAXKEYLEN = 128
let _KEYLENSTEP = 16

(* Number of round keys N = 16 + (KLen - 256) / 128, key length in bytes. *)
let _RNDS (x: nat) : r:nat{r >= 16} = if x >= 32 then 16 + (x - 32) / 16 else 16

(* Key length 32..128 bytes in steps of 16, block length 16, 32 or 64 bytes. *)
let valid_params (klen blen: nat) : bool =
  klen >= 32 && klen <= 128 && klen % 16 = 0 && (blen = 16 || blen = 32 || blen = 64)

let _ROTL (x: UInt32.t) (s: UInt32.t{UInt32.v s < 32 && UInt32.v s > 0}) = 
    UInt32.logor (UInt32.shift_left x s) (UInt32.shift_right x (UInt32.sub 32ul s))

(* Rotation counts of Table 2 for 512-bit blocks are 0..61: the previous
   refinement (0 < s < 32) could not be applied to 0, 47 or 61. *)
let _ROTL64 (x: UInt64.t) (s: UInt32.t{UInt32.v s < 64}) =
    if s = 0ul then x
    else UInt64.logor (UInt64.shift_left x s) (UInt64.shift_right x (UInt32.sub 64ul s))

(* Total list helpers *)
let rec nth (#a: Type) (l: list a) (i: nat) (d: a) : a =
  match l with
  | [] -> d
  | h :: t -> if i = 0 then h else nth t (i - 1) d

let rec update (#a: Type) (l: list a) (i: nat) (v: a) : list a =
  match l with
  | [] -> []
  | h :: t -> if i = 0 then v :: t else h :: update t (i - 1) v

let rec take (#a: Type) (n: nat) (l: list a) : list a =
  match l with
  | [] -> []
  | h :: t -> if n = 0 then [] else h :: take (n - 1) t

let rec drop (#a: Type) (n: nat) (l: list a) : list a =
  match l with
  | [] -> []
  | _ :: t -> if n = 0 then l else drop (n - 1) t

let tail (#a: Type) (l: list a) : list a = match l with | [] -> [] | _ :: t -> t

let rec range (n: nat) : list nat = if n = 0 then [] else range (n - 1) @ [n - 1]

let sbox (x: U8.t) : U8.t = nth sb (U8.v x) 0uy
let inv_sbox (x: U8.t) : U8.t = nth isb (U8.v x) 0uy

let ( +! ) (a b: U8.t) : U8.t = U8.add_mod a b

let rotl32 (x: U32.t) (s: nat) : U32.t =
  let s = s % 32 in
  if s = 0 then x
  else U32.logor (U32.shift_left x (U32.uint_to_t s)) (U32.shift_right x (U32.uint_to_t (32 - s)))

let rotl64 (x: U64.t) (s: nat) : U64.t =
  let s = s % 64 in
  if s = 0 then x
  else U64.logor (U64.shift_left x (U32.uint_to_t s)) (U64.shift_right x (U32.uint_to_t (64 - s)))

(* ---- Key schedule (section 8) ---- *)

type regs = { l0: list U8.t; l1: list U8.t }

(* L0 = {K0, K2, ..., K28, K30, K31}, L1 = {K1, K3, ..., K29} *)
let load_key (key: list U8.t) : regs =
  { l0 = L.map (fun (i: nat) -> nth key (2 * i) 0uy) (range 15) @ [nth key 30 0uy; nth key 31 0uy];
    l1 = L.map (fun (i: nat) -> nth key (2 * i + 1) 0uy) (range 15) }

(* t0 = S(L0_0) + L0_1 + S(L0_3) + L0_7 + S(L0_12) + L0_16,
   t1 = S(L1_0) + L1_3 + S(L1_9) + L1_12 + S(L1_14)  (mod 256) *)
let feedback (r: regs) : U8.t & U8.t =
  (sbox (nth r.l0 0 0uy) +! nth r.l0 1 0uy +! sbox (nth r.l0 3 0uy) +! nth r.l0 7 0uy
     +! sbox (nth r.l0 12 0uy) +! nth r.l0 16 0uy,
   sbox (nth r.l1 0 0uy) +! nth r.l1 3 0uy +! sbox (nth r.l1 9 0uy) +! nth r.l1 12 0uy
     +! sbox (nth r.l1 14 0uy))

(* Shift towards index 0; the last cells keep their old value until [store]. *)
let shift (r: regs) : regs =
  { l0 = tail r.l0 @ [nth r.l0 16 0uy]; l1 = tail r.l1 @ [nth r.l1 14 0uy] }

let store (r: regs) (t0 t1: U8.t) : regs = { l0 = update r.l0 16 t0; l1 = update r.l1 14 t1 }

let rec warmup (n: nat) (r: regs) : Tot regs (decreases n) =
  if n = 0 then r
  else let (t0, t1) = feedback r in warmup (n - 1) (store (shift r) t0 t1)

(* After warm-up each step outputs L0 feedback + L1_4; key bytes beyond 256
   bits go into the L1 feedback on even steps and the L0 feedback on odd
   steps, after the round-key byte is taken. *)
let rec gen (key: list U8.t) (extra j: nat) (n: nat) (r: regs) : Tot (list U8.t) (decreases n) =
  if n = 0 then []
  else
    let (t0, t1) = feedback r in
    let s = shift r in
    let b = t0 +! nth s.l1 4 0uy in
    let k = nth key (32 + j) 0uy in
    let (t0', t1') =
      if j < extra then (if j % 2 = 0 then (t0, t1 +! k) else (t0 +! k, t1)) else (t0, t1)
    in
    b :: gen key extra (j + 1) (n - 1) (store s t0' t1')

let kexp (key: list U8.t) (blen: nat) : list U8.t =
  let klen = L.length key in
  gen key (if klen >= 32 then klen - 32 else 0) 0 (_RNDS klen * blen) (warmup _SHIFT (load_key key))

(* ---- Linear transform (section 6.2) ---- *)

let load32 (b: list U8.t) (i: nat) : U32.t =
  let byte (k: nat) = FStar.Int.Cast.uint8_to_uint32 (nth b (4 * i + k) 0uy) in
  U32.logor (byte 0)
    (U32.logor (U32.shift_left (byte 1) 8ul)
      (U32.logor (U32.shift_left (byte 2) 16ul) (U32.shift_left (byte 3) 24ul)))

let load64 (b: list U8.t) (i: nat) : U64.t =
  U64.logor (FStar.Int.Cast.uint32_to_uint64 (load32 b (2 * i)))
    (U64.shift_left (FStar.Int.Cast.uint32_to_uint64 (load32 b (2 * i + 1))) 32ul)

let to_u8 (x: U32.t) : U8.t = FStar.Int.Cast.uint32_to_uint8 x
let to_u32 (x: U64.t) : U32.t = FStar.Int.Cast.uint64_to_uint32 x

let word_bytes (x: U32.t) : list U8.t =
  [to_u8 x; to_u8 (U32.shift_right x 8ul); to_u8 (U32.shift_right x 16ul); to_u8 (U32.shift_right x 24ul)]

let bytes32 (w: list U32.t) : list U8.t = L.flatten (L.map word_bytes w)

let dword_words (x: U64.t) : list U32.t = [to_u32 x; to_u32 (U64.shift_right x 32ul)]

let bytes64 (w: list U64.t) : list U8.t = bytes32 (L.flatten (L.map dword_words w))

(* XOR_{j=1}^{n-1} (Word_{(i+j) mod n} <<< C_{j-1}) into x *)
let rec terms32 (w: list U32.t) (c: list nat) (n: pos) (i: nat) (j: pos) (fuel: nat) (x: U32.t)
  : Tot U32.t (decreases fuel) =
  if fuel = 0 then x
  else terms32 w c n i (j + 1) (fuel - 1) (U32.logxor x (rotl32 (nth w ((i + j) % n) 0ul) (nth c (j - 1) 0)))

let rec terms64 (w: list U64.t) (c: list nat) (n: pos) (i: nat) (j: pos) (fuel: nat) (x: U64.t)
  : Tot U64.t (decreases fuel) =
  if fuel = 0 then x
  else terms64 w c n i (j + 1) (fuel - 1) (U64.logxor x (rotl64 (nth w ((i + j) % n) 0uL) (nth c (j - 1) 0)))

(* Formula (1) (i = 0..n-1) or, when [inverse], formula (2) (i = n-1..0);
   each update uses the words already updated. *)
let rec mix32 (w: list U32.t) (c: list nat) (n: pos) (inverse: bool) (k: nat) (fuel: nat)
  : Tot (list U32.t) (decreases fuel) =
  if fuel = 0 then w
  else
    let i = if inverse && k < n then n - 1 - k else k in
    mix32 (update w i (terms32 w c n i 1 (n - 1) (nth w i 0ul))) c n inverse (k + 1) (fuel - 1)

let rec mix64 (w: list U64.t) (c: list nat) (n: pos) (inverse: bool) (k: nat) (fuel: nat)
  : Tot (list U64.t) (decreases fuel) =
  if fuel = 0 then w
  else
    let i = if inverse && k < n then n - 1 - k else k in
    mix64 (update w i (terms64 w c n i 1 (n - 1) (nth w i 0uL))) c n inverse (k + 1) (fuel - 1)

let linear (b: list U8.t) (inverse: bool) : list U8.t =
  match L.length b with
  | 16 -> bytes32 (mix32 (L.map (load32 b) (range 4)) c0 4 inverse 0 4)
  | 32 -> bytes32 (mix32 (L.map (load32 b) (range 8)) c1 8 inverse 0 8)
  | 64 -> bytes64 (mix64 (L.map (load64 b) (range 8)) c2 8 inverse 0 8)
  | _ -> b

(* ---- Round-key addition (section 6.3) ---- *)

let rec xor_bytes (a k: list U8.t) : list U8.t =
  match a, k with
  | x :: xs, y :: ys -> U8.logxor x y :: xor_bytes xs ys
  | _ -> []

(* a + k mod 2^(8 len), byte 0 least significant *)
let rec add_mod (a k: list U8.t) (carry: nat{carry <= 1}) : list U8.t =
  match a, k with
  | x :: xs, y :: ys ->
    let s = U8.v x + U8.v y + carry in
    U8.uint_to_t (s % 256) :: add_mod xs ys (s / 256)
  | _ -> []

(* a - k mod 2^(8 len) *)
let rec sub_mod (a k: list U8.t) (borrow: nat{borrow <= 1}) : list U8.t =
  match a, k with
  | x :: xs, y :: ys ->
    let d = U8.v x + 256 - U8.v y - borrow in
    U8.uint_to_t (d % 256) :: sub_mod xs ys (if d < 256 then 1 else 0)
  | _ -> []

let round_key (rk: list U8.t) (blen i: nat) : list U8.t = take blen (drop (i * blen) rk)

(* ---- Encryption and decryption (section 9) with N round keys ---- *)

let rec xsl (rk: list U8.t) (blen i: nat) (fuel: nat) (s: list U8.t) : Tot (list U8.t) (decreases fuel) =
  if fuel = 0 then s
  else xsl rk blen (i + 1) (fuel - 1) (linear (L.map sbox (xor_bytes s (round_key rk blen i))) false)

let rec xls (rk: list U8.t) (blen i: nat) (fuel: nat) (s: list U8.t) : Tot (list U8.t) (decreases fuel) =
  if fuel = 0 then s
  else
    let s' = xor_bytes (L.map inv_sbox (linear s true)) (round_key rk blen i) in
    xls rk blen (if i > 0 then i - 1 else 0) (fuel - 1) s'

(* Encryption with expanded round keys [rk] for a key of [klen] bytes. *)
let encrypt_rk (rk: list U8.t) (klen: nat) (pt: list U8.t) : list U8.t =
  let blen = L.length pt in
  let n = _RNDS klen in
  let s = linear (L.map sbox (add_mod pt (round_key rk blen 0) 0)) false in
  add_mod (xsl rk blen 1 (n - 2) s) (round_key rk blen (n - 1)) 0

let decrypt_rk (rk: list U8.t) (klen: nat) (ct: list U8.t) : list U8.t =
  let blen = L.length ct in
  let n = _RNDS klen in
  let s = xls rk blen (n - 2) (n - 2) (sub_mod ct (round_key rk blen (n - 1)) 0) in
  sub_mod (L.map inv_sbox (linear s true)) (round_key rk blen 0) 0

(* None for an invalid key or block length. *)
let encrypt (key pt: list U8.t) : option (list U8.t) =
  if valid_params (L.length key) (L.length pt)
  then Some (encrypt_rk (kexp key (L.length pt)) (L.length key) pt) else None

let decrypt (key ct: list U8.t) : option (list U8.t) =
  if valid_params (L.length key) (L.length ct)
  then Some (decrypt_rk (kexp key (L.length ct)) (L.length key) ct) else None
