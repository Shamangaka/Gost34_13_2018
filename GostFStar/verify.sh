#!/bin/sh
# Type-checks the F* specification of СТ РК 4009-2025 and its modes, then
# checks the Appendix A values and known answers by normalisation
# (Qalqan.Test takes a few minutes). Needs fstar.exe (tested with 2025.03.25).
set -e
cd "$(dirname "$0")"
fstar.exe --cache_checked_modules PRNG.fst
fstar.exe --cache_checked_modules Qalqan.fst
fstar.exe --cache_checked_modules Qalqan.Modes.fst
fstar.exe --cache_checked_modules Qalqan.Test.fst
