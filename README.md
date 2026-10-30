# СТ РК 4009-2025 block cipher (Qalqan)

Implementations of the Kazakhstan block cipher standard СТ РК 4009-2025
«Информационные технологии. Криптографическая защита информации. Алгоритм
блочного симметричного шифрования» and of the modes of operation of
СТ РК ISO/IEC 10116-2019 it refers to (ECB, CBC, CFB, OFB, CTR).

Reference code from the public discussion of the draft:
https://ksm.kz/public-discussion/standards/discussion-of-draft-of-st-rk/112716/

| Directory | Language |
|---|---|
| `src/` | C++20 (the reference implementation of Appendix B, fixed) |
| `GostCsharp/` | C# |
| `GostFSharp/` | F# |
| `GostGolang/` | Go |
| `GostRust/` | Rust |
| `GostLean/` | Lean 4 |
| `GostFStar/` | F* (executable specification, checked by normalisation) |

All of them reproduce the mandatory test vectors of Appendix A
(`resources/gold.txt`) and the shared known answers in `resources/`. See
[CONFORMANCE.md](CONFORMANCE.md) for the requirements, the errata in the
printed standard, and how to run each test suite.

# Interesting read.
- https://ceurspt.wikidata.dbis.rwth-aachen.de/Vol-3187/paper19.pdf
- https://ela.kpi.ua/server/api/core/bitstreams/856eff0d-9d31-44d8-a5bf-485dac939344/content
- https://ouci.dntb.gov.ua/en/works/40w1egv7/
- http://tacs.ipt.kpi.ua/article/view/274112/269340
