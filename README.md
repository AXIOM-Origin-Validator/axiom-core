# Lineage artifact — CoreID 42285e6b

This orphan branch preserves the **Core ELF cited by the paper
*Continuity Without Consensus*** (Zenodo DOI 10.5281/zenodo.21295772):
`artifacts/axiom-core.elf`, BLAKE3 CoreID
`42285e6bd3110d2ce97b465d431cf12ba0be5f58b410785a012f4218b27afccc`.

Verify: `b3sum artifacts/axiom-core.elf` and compare to `artifacts/CORE_ID.txt`
(and to the paper's pinned CoreID). The same ELF ships inside the paper's
Zenodo artifact bundle.

The full source tree on `master` is the current protocol generation (its own
CoreID lives in `artifacts/CORE_ID.txt` there). This branch exists so the
paper's exact consensus artifact has a permanent, tagged home in the protocol
repo's history.
