open PRNG
open TestVectors
open System
open System.IO

/// Finds the repository's resources directory from the working directory or
/// the build output directory.
let findResources () =
    [ Directory.GetCurrentDirectory(); AppContext.BaseDirectory ]
    |> List.collect (fun start ->
        Seq.unfold (fun (d: DirectoryInfo) -> if isNull d then None else Some(d.FullName, d.Parent)) (DirectoryInfo start)
        |> Seq.toList)
    |> List.map (fun d -> Path.Combine(d, "resources"))
    |> List.tryFind (fun d -> File.Exists(Path.Combine(d, "gold.txt")))
    |> Option.defaultWith (fun () -> raise (DirectoryNotFoundException "resources/gold.txt not found"))

[<EntryPoint>]
let main args =
    let resources = findResources ()
    if Array.contains "--selftest" args then
        SelfTest.run resources
    else
        init(0)
        use src = File.OpenRead(Path.Combine(resources, "input.bin"))
        use f = new StreamWriter(new FileStream(Path.Combine(resources, "output_fsharp.txt"), FileMode.Create))
        ShortTestVectors(f, src)
        0
