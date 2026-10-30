module Qalqan.Modes

(* Modes of operation of СТ РК ISO/IEC 10116-2019 for the СТ РК 4009-2025
   cipher: ECB, CBC (m = 1), CFB (r = n, j = k = n), OFB (j = n), CTR (j = n;
   the counter is the whole block, incremented modulo 2^n with the last byte
   least significant). CFB/OFB/CTR accept a final partial block. None for a
   wrong IV length, or ECB/CBC input that is not a whole number of blocks.
   None of the modes authenticates data. *)

open FStar.Mul
open FStar.List.Tot
open Qalqan
module U8 = FStar.UInt8
module L = FStar.List.Tot

type cipher = { klen: nat; blen: pos; rk: list U8.t }

(* None for an invalid key or block length. *)
let make (key: list U8.t) (blen: nat) : option cipher =
  if valid_params (L.length key) blen
  then Some ({ klen = L.length key; blen = blen; rk = kexp key blen })
  else None

let enc (c: cipher) (b: list U8.t) : list U8.t = encrypt_rk c.rk c.klen b
let dec (c: cipher) (b: list U8.t) : list U8.t = decrypt_rk c.rk c.klen b

(* Split into blocks; the last one may be shorter. *)
let rec chunks_f (bs: pos) (l: list U8.t) (fuel: nat) : Tot (list (list U8.t)) (decreases fuel) =
  if fuel = 0 then []
  else match l with
       | [] -> []
       | _ -> take bs l :: chunks_f bs (drop bs l) (fuel - 1)

let chunks (bs: pos) (l: list U8.t) : list (list U8.t) = chunks_f bs l (L.length l)

let ecb_encrypt (c: cipher) (data: list U8.t) : option (list U8.t) =
  if L.length data % c.blen <> 0 then None
  else Some (L.flatten (L.map (enc c) (chunks c.blen data)))

let ecb_decrypt (c: cipher) (data: list U8.t) : option (list U8.t) =
  if L.length data % c.blen <> 0 then None
  else Some (L.flatten (L.map (dec c) (chunks c.blen data)))

let rec cbc_enc (c: cipher) (prev: list U8.t) (bl: list (list U8.t))
  : Tot (list U8.t) (decreases bl) =
  match bl with
  | [] -> []
  | b :: t -> let ct = enc c (xor_bytes b prev) in ct @ cbc_enc c ct t

let rec cbc_dec (c: cipher) (prev: list U8.t) (bl: list (list U8.t))
  : Tot (list U8.t) (decreases bl) =
  match bl with
  | [] -> []
  | b :: t -> xor_bytes (dec c b) prev @ cbc_dec c b t

let cbc_encrypt (c: cipher) (iv data: list U8.t) : option (list U8.t) =
  if L.length iv <> c.blen || L.length data % c.blen <> 0 then None
  else Some (cbc_enc c iv (chunks c.blen data))

let cbc_decrypt (c: cipher) (iv data: list U8.t) : option (list U8.t) =
  if L.length iv <> c.blen || L.length data % c.blen <> 0 then None
  else Some (cbc_dec c iv (chunks c.blen data))

(* the ciphertext is fed back *)
let rec cfb_f (c: cipher) (decrypting: bool) (reg: list U8.t) (bl: list (list U8.t))
  : Tot (list U8.t) (decreases bl) =
  match bl with
  | [] -> []
  | b :: t ->
    let o = xor_bytes b (enc c reg) in
    o @ cfb_f c decrypting (if decrypting then b else o) t

let cfb_encrypt (c: cipher) (iv data: list U8.t) : option (list U8.t) =
  if L.length iv <> c.blen then None else Some (cfb_f c false iv (chunks c.blen data))

let cfb_decrypt (c: cipher) (iv data: list U8.t) : option (list U8.t) =
  if L.length iv <> c.blen then None else Some (cfb_f c true iv (chunks c.blen data))

(* Y_i = e_K(Y_{i-1}) *)
let rec ofb_f (c: cipher) (reg: list U8.t) (bl: list (list U8.t))
  : Tot (list U8.t) (decreases bl) =
  match bl with
  | [] -> []
  | b :: t -> let y = enc c reg in xor_bytes b y @ ofb_f c y t

(* OFB; encryption and decryption are the same operation. *)
let ofb (c: cipher) (iv data: list U8.t) : option (list U8.t) =
  if L.length iv <> c.blen then None else Some (ofb_f c iv (chunks c.blen data))

let rec incr_le (l: list U8.t) : list U8.t =
  match l with
  | [] -> []
  | x :: t -> if x = 255uy then 0uy :: incr_le t else U8.add_mod x 1uy :: t

(* CTR_{i+1} = CTR_i + 1 mod 2^n, last byte least significant *)
let incr_counter (l: list U8.t) : list U8.t = L.rev (incr_le (L.rev l))

let rec ctr_f (c: cipher) (counter: list U8.t) (bl: list (list U8.t))
  : Tot (list U8.t) (decreases bl) =
  match bl with
  | [] -> []
  | b :: t -> xor_bytes b (enc c counter) @ ctr_f c (incr_counter counter) t

(* CTR; encryption and decryption are the same operation. *)
let ctr (c: cipher) (iv data: list U8.t) : option (list U8.t) =
  if L.length iv <> c.blen then None else Some (ctr_f c iv (chunks c.blen data))

let rec zeros (n: nat) : list U8.t = if n = 0 then [] else 0uy :: zeros (n - 1)

(* ISO/IEC 9797-1 padding method 2 (0x80, then zeros to a whole block). *)
let pad_method2 (data: list U8.t) (bs: pos) : list U8.t =
  data @ (0x80uy :: zeros (bs - 1 - L.length data % bs))

let rec drop_zeros (l: list U8.t) (k: nat) : Tot (list U8.t) (decreases l) =
  match l with
  | x :: t -> if k > 0 && x = 0uy then drop_zeros t (k - 1) else l
  | [] -> []

(* Removes method-2 padding; None if it is invalid. *)
let unpad_method2 (data: list U8.t) (bs: pos) : option (list U8.t) =
  if L.length data = 0 || L.length data % bs <> 0 then None
  else match drop_zeros (L.rev data) (bs - 1) with
       | x :: rest -> if x = 0x80uy then Some (L.rev rest) else None
       | [] -> None
