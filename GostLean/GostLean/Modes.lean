import GostLean.Qalqan

/-!
Modes of operation of СТ РК ISO/IEC 10116-2019: ECB, CBC (m = 1),
CFB (r = n, j = k = n), OFB (j = n), CTR (j = n; the counter is the whole
block, incremented modulo 2^n with the last byte least significant).
CFB/OFB/CTR accept a final partial block. The functions return `none` for a
wrong IV length, or for ECB/CBC input that is not a whole number of blocks.
None of the modes authenticates data.
-/

/-- Splits data into blocks; the last one may be shorter. -/
def blocksOf (bs : Nat) (data : Array UInt8) : List (Array UInt8) :=
  (List.range ((data.size + bs - 1) / bs)).map fun i => data.extract (i * bs) (min ((i + 1) * bs) data.size)

def ecbEncrypt (c : Cipher) (data : Array UInt8) : Option (Array UInt8) :=
  if data.size % c.blen != 0 then none
  else some ((blocksOf c.blen data).foldl (fun acc b => acc ++ c.encrypt b) #[])

def ecbDecrypt (c : Cipher) (data : Array UInt8) : Option (Array UInt8) :=
  if data.size % c.blen != 0 then none
  else some ((blocksOf c.blen data).foldl (fun acc b => acc ++ c.decrypt b) #[])

def cbcEncrypt (c : Cipher) (iv data : Array UInt8) : Option (Array UInt8) :=
  if iv.size != c.blen || data.size % c.blen != 0 then none
  else some <| Id.run do
    let mut prev := iv
    let mut out : Array UInt8 := #[]
    for b in blocksOf c.blen data do
      prev := c.encrypt (xorBytes b prev)
      out := out ++ prev
    return out

def cbcDecrypt (c : Cipher) (iv data : Array UInt8) : Option (Array UInt8) :=
  if iv.size != c.blen || data.size % c.blen != 0 then none
  else some <| Id.run do
    let mut prev := iv
    let mut out : Array UInt8 := #[]
    for b in blocksOf c.blen data do
      out := out ++ xorBytes (c.decrypt b) prev
      prev := b
    return out

def cfb (c : Cipher) (iv data : Array UInt8) (decrypt : Bool) : Option (Array UInt8) :=
  if iv.size != c.blen then none
  else some <| Id.run do
    let mut reg := iv
    let mut out : Array UInt8 := #[]
    for b in blocksOf c.blen data do
      let o := xorBytes b (c.encrypt reg)
      out := out ++ o
      reg := if decrypt then b else o -- the ciphertext is fed back
    return out

def cfbEncrypt (c : Cipher) (iv data : Array UInt8) := cfb c iv data false
def cfbDecrypt (c : Cipher) (iv data : Array UInt8) := cfb c iv data true

/-- OFB; encryption and decryption are the same operation. -/
def ofb (c : Cipher) (iv data : Array UInt8) : Option (Array UInt8) :=
  if iv.size != c.blen then none
  else some <| Id.run do
    let mut reg := iv
    let mut out : Array UInt8 := #[]
    for b in blocksOf c.blen data do
      reg := c.encrypt reg -- Y_i = e_K(Y_{i-1})
      out := out ++ xorBytes b reg
    return out

/-- CTR_{i+1} = CTR_i + 1 mod 2^n, last byte least significant. -/
def incrCounter (ctr : Array UInt8) : Array UInt8 := Id.run do
  let mut c := ctr
  let mut carry := true
  for k in [0:c.size] do
    if carry then
      let i := c.size - 1 - k
      let v := c[i]! + 1
      c := c.set! i v
      carry := v == 0
  return c

/-- CTR; encryption and decryption are the same operation. -/
def ctr (c : Cipher) (iv data : Array UInt8) : Option (Array UInt8) :=
  if iv.size != c.blen then none
  else some <| Id.run do
    let mut counter := iv
    let mut out : Array UInt8 := #[]
    for b in blocksOf c.blen data do
      out := out ++ xorBytes b (c.encrypt counter)
      counter := incrCounter counter
    return out

/-- ISO/IEC 9797-1 padding method 2 (0x80, then zeros to a whole block). -/
def padMethod2 (data : Array UInt8) (bs : Nat) : Array UInt8 :=
  let n := (data.size / bs + 1) * bs
  data.push 0x80 ++ mkArray (n - data.size - 1) 0

/-- Removes method-2 padding; `none` if it is invalid. -/
def unpadMethod2 (data : Array UInt8) (bs : Nat) : Option (Array UInt8) :=
  if data.size == 0 || data.size % bs != 0 then none
  else Id.run do
    let stop := data.size - bs
    let mut i := data.size
    let mut scanning := true
    for _ in [0:bs] do
      if scanning && data[i - 1]! == 0 then i := i - 1 else scanning := false
    if i == stop || data[i - 1]! != 0x80 then return none
    return some (data.extract 0 (i - 1))
