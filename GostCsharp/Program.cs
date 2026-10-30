using GostCsharp;
using static GostCsharp.PRNG;
using static GostCsharp.TestVectors;

// Finds the repository's resources directory from the working directory or
// the build output directory.
static string FindResources()
{
    foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
    {
        for (var dir = new DirectoryInfo(start); dir != null; dir = dir.Parent)
        {
            var candidate = Path.Combine(dir.FullName, "resources");
            if (File.Exists(Path.Combine(candidate, "gold.txt")))
                return candidate;
        }
    }
    throw new DirectoryNotFoundException("resources/gold.txt not found");
}

var resources = FindResources();
if (args.Contains("--selftest"))
    return SelfTest.Run(resources);

init(0);
using (var src = File.OpenRead(Path.Combine(resources, "input.bin")))
using (var f = new StreamWriter(new FileStream(Path.Combine(resources, "output_charp.txt"), FileMode.Create)))
    ShortTestVectors(f, src);
return 0;
