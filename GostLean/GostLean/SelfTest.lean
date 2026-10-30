import GostLean.Qalqan
import GostLean.Modes
import GostLean.TestVectors

/-! Conformance self-test (`lake exe gostlean --selftest`): Appendix A byte for
byte, the reference and mode known answers, round trips, invalid parameters,
padding. -/

def hexVal (c : Char) : Nat :=
  if c.isDigit then c.toNat - '0'.toNat else c.toLower.toNat - 'a'.toNat + 10

def unhex (s : String) : Array UInt8 := Id.run do
  let cs := s.toList.toArray
  let mut out : Array UInt8 := #[]
  for i in [0:cs.size / 2] do
    out := out.push (UInt8.ofNat (hexVal cs[2 * i]! * 16 + hexVal cs[2 * i + 1]!))
  return out

def records (text : String) : List (List String) :=
  (text.splitOn "\n").filter (fun l => !l.isEmpty && !l.startsWith "#")
    |>.map fun l => (l.splitOn " ").filter (· ≠ "")

def trimNewlines (s : String) : String := s.dropRightWhile (· == '\n')

def selfTest (resources : System.FilePath) : IO UInt32 := do
  let failures ← IO.mkRef 0
  let check (ok : Bool) (what : String) : IO Unit := do
    unless ok do
      failures.modify (· + 1)
      IO.println s!"FAIL: {what}"
  -- Appendix A
  let input ← IO.FS.readBinFile (resources / "input.bin")
  let gold ← IO.FS.readFile (resources / "gold.txt")
  check (trimNewlines (shortTestVectors input.data) == trimNewlines gold) "Appendix A output differs from gold.txt"
  -- Reference known answers (Appendix B code, all 21 size combinations)
  let refs := records (← IO.FS.readFile (resources / "reference_kat.txt"))
  for f in refs do
    let key := unhex f[2]!
    let pt := unhex f[3]!
    let ct := unhex f[4]!
    match Cipher.new? key pt.size with
    | some c =>
      check (c.encrypt pt == ct) s!"reference KAT encrypt {f[0]!}/{f[1]!}"
      check (c.decrypt ct == pt) s!"reference KAT decrypt {f[0]!}/{f[1]!}"
    | none => check false s!"valid key rejected {f[0]!}/{f[1]!}"
  check (refs.length == 84) s!"expected 84 reference cases, found {refs.length}"
  -- Mode known answers
  let modeRows := records (← IO.FS.readFile (resources / "modes_kat.txt"))
  for f in modeRows do
    let key := unhex f[3]!
    let iv := if f[4]! == "-" then #[] else unhex f[4]!
    let pt := unhex f[5]!
    let ct := unhex f[6]!
    match Cipher.new? key (f[2]!.toNat! / 8) with
    | some c =>
      let (enc, dec) := match f[0]! with
        | "ECB" => (ecbEncrypt c pt, ecbDecrypt c ct)
        | "CBC" => (cbcEncrypt c iv pt, cbcDecrypt c iv ct)
        | "CFB" => (cfbEncrypt c iv pt, cfbDecrypt c iv ct)
        | "OFB" => (ofb c iv pt, ofb c iv ct)
        | _ => (ctr c iv pt, ctr c iv ct)
      check (enc == some ct) s!"{f[0]!} encrypt {f[1]!}/{f[2]!}"
      check (dec == some pt) s!"{f[0]!} decrypt {f[1]!}/{f[2]!}"
    | none => check false s!"valid key rejected {f[1]!}/{f[2]!}"
  check (modeRows.length == 54) s!"expected 54 mode cases, found {modeRows.length}"
  -- Round trips for all 21 key/block combinations
  let mut x : UInt64 := 1
  for blen in [16, 32, 64] do
    for klen in [32, 48, 64, 80, 96, 112, 128] do
      for _ in [0:20] do
        let mut key : Array UInt8 := #[]
        for _ in [0:klen] do
          x := x * 6364136223846793005 + 1442695040888963407
          key := key.push (x >>> 56).toUInt8
        let mut pt : Array UInt8 := #[]
        for _ in [0:blen] do
          x := x * 6364136223846793005 + 1442695040888963407
          pt := pt.push (x >>> 56).toUInt8
        match Cipher.new? key blen with
        | some c =>
          check (c.rounds == 16 + (klen * 8 - 256) / 128) "round count"
          check (c.decrypt (c.encrypt pt) == pt) s!"round trip key {klen * 8}, block {blen * 8}"
        | none => check false "valid key rejected"
  -- Invalid parameters
  for klen in [0, 16, 31, 40, 144] do
    check (Cipher.new? (mkArray klen 0) 16).isNone s!"{klen}-byte key accepted"
  for blen in [0, 8, 24, 48, 128] do
    check (Cipher.new? (mkArray 32 0) blen).isNone s!"{blen}-byte block accepted"
  if let some c := Cipher.new? (mkArray 32 0) 16 then
    check (cbcEncrypt c (mkArray 15 0) (mkArray 16 0)).isNone "short IV accepted"
    check (ecbEncrypt c (mkArray 17 0)).isNone "partial ECB block accepted"
  -- Padding
  for bs in [16, 32, 64] do
    for n in [0:2 * bs + 1] do
      let data : Array UInt8 := mkArray n 0x80
      let p := padMethod2 data bs
      check (p.size % bs == 0 && unpadMethod2 p bs == some data) s!"padding n={n}"
    check (unpadMethod2 (mkArray bs 0) bs).isNone "missing padding marker accepted"
  let n ← failures.get
  IO.println (if n == 0 then "selftest: all checks passed" else s!"selftest: {n} failure(s)")
  return if n == 0 then 0 else 1
