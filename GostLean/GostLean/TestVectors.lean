import GostLean.Qalqan

/-! Generator of the СТ РК 4009-2025 Appendix A test vectors, in the format of
the Appendix B reference code (`ShortTestVectors`). -/

def hexByte (x : UInt8) : String :=
  let d := "0123456789abcdef".toList
  String.mk [d[x.toNat / 16]!, d[x.toNat % 16]!]

def hex (b : Array UInt8) : String := String.join (b.toList.map hexByte)

def pr (label : String) (b : Array UInt8) : String := s!"{label}:\n{hex b}\n"

def pad2 (n : Nat) : String := if n < 10 then s!" {n}" else toString n

def shortTestLin (din : Array UInt8) : String := Id.run do
  let mut out := "Linear operation:\n"
  for bl in [16, 32, 64] do
    let x := din.extract 0 bl
    out := out ++ s!"Input ({bl * 8} bits):  {hex x}\nOutput ({bl * 8} bits): {hex (linear x)}\n"
  return out ++ "\n"

def shortTestSBox (din : Array UInt8) : String :=
  s!"Nonlinear operation:\nInput ({din.size * 8} bits):  {hex din}\nOutput ({din.size * 8} bits): {hex (subBytes din)}\n\n"

/-- Mirrors KexpV (`verbose = false`) and KexpVV (`verbose = true`). -/
def kexpTrace (key : Array UInt8) (blen : Nat) (verbose : Bool) : String := Id.run do
  let klen := key.size
  let n := RNDS klen
  let addk := klen - 32
  let mut r := KeyRegs.load key
  let mut out := pr "Initial key" key ++ pr "Register L0" r.l0 ++ pr "Register L1" r.l1
  let mut rk : Array UInt8 := mkArray (n * blen) 0
  let mut step := 0
  let mut s := SHIFT
  for rnd in [0:n] do
    for k in [0:blen + s] do
      let (f0, f1) := r.feedback
      r := r.shift
      let mut t0 := f0
      let mut t1 := f1
      if k >= s then
        rk := rk.set! (rnd * blen + k - s) (t0 + r.l1[4]!)
        if step < addk then
          if step % 2 == 1 then
            if verbose && step < 32 then
              out := out ++ s!"Additional key byte to L0: {hexByte key[32 + step]!}\n"
            t0 := t0 + key[32 + step]!
          else
            if verbose && step < 32 then
              out := out ++ s!"Additional key byte to L1: {hexByte key[32 + step]!}\n"
            t1 := t1 + key[32 + step]!
          if verbose && step < 32 then
            out := out ++ pr "Register L0" r.l0 ++ pr "Register L1" r.l1
          step := step + 1
        if verbose && step < 8 then
          out := out ++ s!"Output {hexByte (t0 + r.l1[4]!)} (L0: {hexByte t0}, L1: {hexByte r.l1[4]!})\n"
      r := r.store t0 t1
      if verbose && step < 16 then
        out := out ++ s!"Step {k}\nFeedback L0: {hexByte t0}, L1: {hexByte t1}\n" ++ pr "Register L0" r.l0 ++ pr "Register L1" r.l1
    if !verbose && s != 0 then
      out := out ++ "After prerun:\n" ++ pr "Register L0" r.l0 ++ pr "Register L1" r.l1
    s := 0
  for i in [0:n] do
    out := out ++ s!"Round {pad2 i} key: {hex (roundKey rk blen i)}\n"
  return out

/-- Mirrors encryptV: every intermediate value of one encryption. -/
def encTrace (c : Cipher) (data : Array UInt8) : String := Id.run do
  let n := c.rounds
  let bl := c.blen
  let mut out := pr "Clear text" data ++ pr "Key 0" (roundKey c.rk bl 0)
  let mut b := addMod data (roundKey c.rk bl 0)
  out := out ++ pr "After add K0" b
  b := subBytes b
  out := out ++ pr "After Sub" b
  b := linear b
  out := out ++ pr "After linear" b
  for i in [1:n - 1] do
    out := out ++ s!"Round {i}.\nKey{i}:\n{hex (roundKey c.rk bl i)}\n"
    b := xorBytes b (roundKey c.rk bl i)
    out := out ++ pr "After addkey" b
    b := subBytes b
    out := out ++ pr "After Sub" b
    b := linear b
    out := out ++ pr "After linear" b
  out := out ++ pr "Final key" (roundKey c.rk bl (n - 1))
  return out ++ pr "Ciphertext" (addMod b (roundKey c.rk bl (n - 1)))

def shortTestKExp (key : Array UInt8) : String :=
  s!"\nKey expansion for {key.size * 8} bit key and {MAXBLOCKLEN * 8} bit block:\n" ++ kexpTrace key MAXBLOCKLEN true ++ "\n"

def shortTestEnc (key : Array UInt8) : String := Id.run do
  let mut out := ""
  for klen in [32, 48, 64, 80, 96, 112, 128] do
    out := out ++ s!"\n***** Key expansion, key length = {klen * 8}, block length = {MINBLOCKLEN * 8} *****\n"
      ++ kexpTrace (key.extract 0 klen) MINBLOCKLEN false ++ "\n"
  for blen in [16, 32, 64] do
    match Cipher.new? (key.extract 0 MINKEYLEN) blen with
    | some c =>
      out := out ++ s!"\n***** Encryption, key length = {MINKEYLEN * 8}, block len = {blen * 8} *****\n"
        ++ encTrace c (mkArray blen 0) ++ "\n"
    | none => pure ()
  return out

/-- The whole Appendix A output for the bytes of resources/input.bin, read in
    the same order as the reference code reads them. -/
def shortTestVectors (input : Array UInt8) : String :=
  let part (a b : Nat) := input.extract a b
  shortTestLin (part 0 64) ++ shortTestLin (part 64 128) ++ shortTestSBox (part 128 192)
    ++ shortTestKExp (part 192 320) ++ shortTestEnc (part 384 512)
