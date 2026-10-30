module Modes

// Modes of operation of СТ РК ISO/IEC 10116-2019: ECB, CBC (m = 1),
// CFB (r = n, j = k = n), OFB (j = n), CTR (j = n; the counter is the whole
// block, incremented modulo 2^n with the last byte least significant).
// CFB/OFB/CTR accept a final partial block. Functions return new arrays.
// None of the modes authenticates data.

open System
open System.Security.Cryptography
open Microsoft.FSharp.NativeInterop
open Qalqan

#nowarn "9"

let private expandKey (key: byte[]) (blockSize: int) =
    let rkey = Array.zeroCreate<byte> (RNDS(key.Length) * blockSize)
    use k = fixed key
    use rk = fixed rkey
    Kexp(k, key.Length, blockSize, rk) |> ignore
    rkey

let private cryptBlock (forward: bool) (rkey: byte[]) (klen: int) (blockSize: int) (input: byte[]) =
    let output = Array.zeroCreate<byte> blockSize
    use i = fixed input
    use o = fixed output
    use rk = fixed rkey
    (if forward then encrypt(i, rk, klen, blockSize, o) else decrypt(i, rk, klen, blockSize, o)) |> ignore
    output

/// An expanded СТ РК 4009-2025 key for one block length.
type QalqanCipher(key: byte[], blockSize: int) =
    do
        if not (ValidParams(key.Length, blockSize)) then
            invalidArg "key" "key must be 32..128 bytes in steps of 16, block 16, 32 or 64 bytes"
    let klen = key.Length
    let rkey = expandKey key blockSize

    member _.BlockSize = blockSize
    /// Number of round keys N = 16 + (KLen - 256) / 128.
    member _.Rounds = RNDS(klen)

    member _.EncryptBlock(input: byte[]) : byte[] =
        if input.Length <> blockSize then invalidArg "input" "input must be one block"
        cryptBlock true rkey klen blockSize input

    member _.DecryptBlock(input: byte[]) : byte[] =
        if input.Length <> blockSize then invalidArg "input" "input must be one block"
        cryptBlock false rkey klen blockSize input

    interface IDisposable with
        member _.Dispose() = CryptographicOperations.ZeroMemory(Span<byte>(rkey))

let private checkIv (c: QalqanCipher) (iv: byte[]) =
    if iv.Length <> c.BlockSize then invalidArg "iv" "IV length must equal the block size"

let private checkBlocks (c: QalqanCipher) (data: byte[]) =
    if data.Length % c.BlockSize <> 0 then invalidArg "data" "input is not a whole number of blocks"

/// Splits data into blocks; the last one may be shorter.
let private blocks (c: QalqanCipher) (data: byte[]) =
    Array.chunkBySize c.BlockSize data

let private xorInto (a: byte[]) (b: byte[]) = Array.init a.Length (fun k -> a.[k] ^^^ b.[k])

let ecbEncrypt (c: QalqanCipher) (data: byte[]) =
    checkBlocks c data
    blocks c data |> Array.collect c.EncryptBlock

let ecbDecrypt (c: QalqanCipher) (data: byte[]) =
    checkBlocks c data
    blocks c data |> Array.collect c.DecryptBlock

let cbcEncrypt (c: QalqanCipher) (iv: byte[]) (data: byte[]) =
    checkIv c iv
    checkBlocks c data
    let out = ResizeArray<byte>(data.Length)
    let mutable prev = iv
    for b in blocks c data do
        prev <- c.EncryptBlock(xorInto b prev)
        out.AddRange prev
    out.ToArray()

let cbcDecrypt (c: QalqanCipher) (iv: byte[]) (data: byte[]) =
    checkIv c iv
    checkBlocks c data
    let out = ResizeArray<byte>(data.Length)
    let mutable prev = iv
    for b in blocks c data do
        out.AddRange(xorInto (c.DecryptBlock b) prev)
        prev <- b
    out.ToArray()

let private cfb (c: QalqanCipher) (iv: byte[]) (data: byte[]) (decrypt: bool) =
    checkIv c iv
    let out = ResizeArray<byte>(data.Length)
    let mutable reg = iv
    for b in blocks c data do
        let ct = xorInto b (c.EncryptBlock reg)
        out.AddRange ct
        reg <- if decrypt then b else ct // the ciphertext is fed back
    out.ToArray()

let cfbEncrypt (c: QalqanCipher) (iv: byte[]) (data: byte[]) = cfb c iv data false
let cfbDecrypt (c: QalqanCipher) (iv: byte[]) (data: byte[]) = cfb c iv data true

/// OFB; encryption and decryption are the same operation.
let ofb (c: QalqanCipher) (iv: byte[]) (data: byte[]) =
    checkIv c iv
    let out = ResizeArray<byte>(data.Length)
    let mutable reg = iv
    for b in blocks c data do
        reg <- c.EncryptBlock reg // Y_i = e_K(Y_{i-1})
        out.AddRange(xorInto b reg)
    out.ToArray()

/// CTR; encryption and decryption are the same operation.
let ctr (c: QalqanCipher) (iv: byte[]) (data: byte[]) =
    checkIv c iv
    let out = ResizeArray<byte>(data.Length)
    let counter = Array.copy iv
    for b in blocks c data do
        out.AddRange(xorInto b (c.EncryptBlock counter))
        let mutable k = counter.Length - 1 // CTR_{i+1} = CTR_i + 1 mod 2^n
        let mutable carry = true
        while carry && k >= 0 do
            counter.[k] <- counter.[k] + 1uy
            carry <- counter.[k] = 0uy
            k <- k - 1
    out.ToArray()

/// ISO/IEC 9797-1 padding method 2 (0x80, then zeros to a whole block).
let padMethod2 (data: byte[]) (blockSize: int) =
    let out = Array.zeroCreate<byte> ((data.Length / blockSize + 1) * blockSize)
    Array.blit data 0 out 0 data.Length
    out.[data.Length] <- 0x80uy
    out

/// Removes method-2 padding; None if it is invalid.
let unpadMethod2 (data: byte[]) (blockSize: int) =
    if data.Length = 0 || data.Length % blockSize <> 0 then None
    else
        let stop = data.Length - blockSize
        let mutable i = data.Length
        while i > stop && data.[i - 1] = 0uy do
            i <- i - 1
        if i = stop || data.[i - 1] <> 0x80uy then None else Some data.[.. i - 2]
