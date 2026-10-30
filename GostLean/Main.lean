import GostLean

/-- The repository's resources directory, from the GostLean or repository directory. -/
def findResources : IO System.FilePath := do
  for d in ["../resources", "resources", "../../resources"] do
    if ← System.FilePath.pathExists (System.FilePath.mk d / "gold.txt") then
      return d
  throw (IO.userError "resources/gold.txt not found")

def main (args : List String) : IO UInt32 := do
  let resources ← findResources
  if args.contains "--selftest" then
    selfTest resources
  else
    let input ← IO.FS.readBinFile (resources / "input.bin")
    IO.FS.writeFile (resources / "output_lean.txt") (shortTestVectors input.data)
    return 0
