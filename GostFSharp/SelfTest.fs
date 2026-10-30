module SelfTest

// Conformance self-test (run with "--selftest"): Appendix A byte for byte,
// the reference and mode known answers, round trips, invalid parameters, padding.

open System
open System.IO
open System.Text
open Modes

let mutable private failures = 0

let private check ok (what: string) =
    if not ok then
        failures <- failures + 1
        printfn "FAIL: %s" what

let private records (resources: string) (name: string) =
    File.ReadLines(Path.Combine(resources, name))
    |> Seq.filter (fun l -> l.Length > 0 && l.[0] <> '#')
    |> Seq.map (fun l -> l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
    |> Seq.toList

let private appendixA (resources: string) =
    let tmp = Path.GetTempFileName()
    try
        PRNG.init 0
        do
            use src = File.OpenRead(Path.Combine(resources, "input.bin"))
            use f = new StreamWriter(tmp, false, UTF8Encoding(false))
            TestVectors.ShortTestVectors(f, src)
        let got = File.ReadAllText(tmp).TrimEnd('\n')
        let want = File.ReadAllText(Path.Combine(resources, "gold.txt")).TrimEnd('\n')
        check (got = want) "Appendix A output differs from gold.txt"
    finally
        File.Delete tmp

let private referenceKat resources =
    let rows = records resources "reference_kat.txt"
    for f in rows do
        let key, pt, ct = Convert.FromHexString f.[2], Convert.FromHexString f.[3], Convert.FromHexString f.[4]
        use c = new QalqanCipher(key, pt.Length)
        check (c.EncryptBlock pt = ct) (sprintf "reference KAT encrypt %s/%s" f.[0] f.[1])
        check (c.DecryptBlock ct = pt) (sprintf "reference KAT decrypt %s/%s" f.[0] f.[1])
    check (rows.Length = 84) (sprintf "expected 84 reference cases, found %d" rows.Length)

let private modesKat resources =
    let rows = records resources "modes_kat.txt"
    for f in rows do
        let key, pt, ct = Convert.FromHexString f.[3], Convert.FromHexString f.[5], Convert.FromHexString f.[6]
        let iv = if f.[4] = "-" then [||] else Convert.FromHexString f.[4]
        use c = new QalqanCipher(key, int f.[2] / 8)
        let enc, dec =
            match f.[0] with
            | "ECB" -> ecbEncrypt c pt, ecbDecrypt c ct
            | "CBC" -> cbcEncrypt c iv pt, cbcDecrypt c iv ct
            | "CFB" -> cfbEncrypt c iv pt, cfbDecrypt c iv ct
            | "OFB" -> ofb c iv pt, ofb c iv ct
            | "CTR" -> ctr c iv pt, ctr c iv ct
            | m -> failwithf "unknown mode %s" m
        check (enc = ct) (sprintf "%s encrypt %s/%s" f.[0] f.[1] f.[2])
        check (dec = pt) (sprintf "%s decrypt %s/%s" f.[0] f.[1] f.[2])
    check (rows.Length = 54) (sprintf "expected 54 mode cases, found %d" rows.Length)

let private roundTrip () =
    let rng = Random(7)
    for blen in [ 16; 32; 64 ] do
        for klen in Qalqan.MINKEYLEN .. Qalqan.KEYLENSTEP .. Qalqan.MAXKEYLEN do
            for _ in 1 .. 50 do
                let key = Array.zeroCreate<byte> klen
                let pt = Array.zeroCreate<byte> blen
                rng.NextBytes key
                rng.NextBytes pt
                use c = new QalqanCipher(key, blen)
                check (c.Rounds = 16 + (klen * 8 - 256) / 128) "round count"
                check (c.DecryptBlock(c.EncryptBlock pt) = pt) (sprintf "round trip key %d, block %d" (klen * 8) (blen * 8))

let private throws f =
    try
        f () |> ignore
        false
    with :? ArgumentException -> true

let private invalidParameters () =
    for klen in [ 0; 16; 31; 40; 144 ] do
        check (throws (fun () -> new QalqanCipher(Array.zeroCreate klen, 16))) (sprintf "%d-byte key accepted" klen)
    for blen in [ 0; 8; 24; 48; 128 ] do
        check (throws (fun () -> new QalqanCipher(Array.zeroCreate 32, blen))) (sprintf "%d-byte block accepted" blen)
    use c = new QalqanCipher(Array.zeroCreate 32, 16)
    check (throws (fun () -> cbcEncrypt c (Array.zeroCreate 15) (Array.zeroCreate 16))) "short IV accepted"
    check (throws (fun () -> ecbEncrypt c (Array.zeroCreate 17))) "partial ECB block accepted"

let private padding () =
    for bs in [ 16; 32; 64 ] do
        for n in 0 .. 2 * bs do
            let data = Array.create n 0x80uy
            let p = padMethod2 data bs
            check (p.Length % bs = 0 && unpadMethod2 p bs = Some data) (sprintf "padding n=%d" n)
        check (unpadMethod2 (Array.zeroCreate bs) bs = None) "missing padding marker accepted"

let run (resources: string) =
    failures <- 0
    appendixA resources
    referenceKat resources
    modesKat resources
    roundTrip ()
    invalidParameters ()
    padding ()
    printfn "%s" (if failures = 0 then "selftest: all checks passed" else sprintf "selftest: %d failure(s)" failures)
    if failures = 0 then 0 else 1
