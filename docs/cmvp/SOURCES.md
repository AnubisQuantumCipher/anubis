# CMVP source snapshot

This is the authoritative-source inventory used for the ANUBIS validation
readiness review. It records what was retrieved on 2026-09-01 without
committing large or fast-changing NIST binaries. A digest identifies the bytes
reviewed; it does not make a document current forever and is not evidence of a
validation.

## Versioned artifacts reviewed

| Artifact | Version or date shown by NIST | SHA-256 of retrieved bytes |
| --- | --- | --- |
| [FIPS 140-3 CMVP Management Manual](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS-140-3-CMVP%20Management%20Manual.pdf) | Version 2.7, 2026-04-09 | e2efe42a638efd3b96446aa502079925ef875d4794ae530aa4f8b74983dc4584 |
| [FIPS 140-3 Implementation Guidance](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/FIPS%20140-3%20IG.pdf) | Updated 2026-08-19 | 15ebdd396a31129f9d75137ace99be56b1085feb25a95c990f8b6558440aeb02 |
| [MIS JSON Schema](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/Module%20Processes/SchemaMis-2.8.4.json) | Version 2.8.4 | 62ebb615f03d4f7df36ca56e3ed9395bc0e8af36a5ae9dd7bbee63390b8d05d9 |
| [CMVP Security Policy template](https://csrc.nist.gov/csrc/media/Projects/cryptographic-module-validation-program/documents/fips%20140-3/Module%20Processes/SP%20Template%20-%20V5.8.docx) | Version 5.8 | 032ae3707c6291e345c3694da9942a87a11c5ad2d7e34d1f016597a3cd88ac98 |

The [SP 800-140B support page](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140b)
also identified ModVerifyApp V4.6.3 and resource files dated 2026-07-15 when
reviewed. Those executables are not vendored. The selected CST laboratory must
refresh the schema, template, application, and resource files immediately
before package generation.

## Normative and program sources

- [FIPS 140-3](https://csrc.nist.gov/pubs/fips/140-3/final)
- [FIPS 140-3 standards and process](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/fips-140-3-standards)
- [SP 800-140 series supplemental information](https://csrc.nist.gov/projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information)
- [SP 800-140B submission and Security Policy resources](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140b)
- [SP 800-140C approved security functions](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140c)
- [SP 800-140D approved SSP generation and establishment methods](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/sp-800-140-series-supplemental-information/sp800-140d)
- [CAVP overview](https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program)
- [CAVP prerequisites](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/prerequisites)
- [ACVTS access](https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/how-to-access-acvts)
- [CAVP validation search](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/validation-search)
- [CMVP validated-module search](https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules/search)
- [CST laboratory accreditation and fees](https://csrc.nist.gov/Projects/cryptographic-module-validation-program/cst-lab-accreditation-and-fees)
- [NVLAP laboratory directory](https://www-s.nist.gov/niws/index.cfm?event=directory.search)
- [NIST cost-recovery fees](https://csrc.nist.gov/projects/cryptographic-module-validation-program/nist-cost-recovery-fees)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [SP 800-227: KEM recommendations](https://csrc.nist.gov/pubs/sp/800/227/final)
- [SP 800-38D: GCM](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [SP 800-38F: AES key wrapping](https://csrc.nist.gov/pubs/sp/800/38/f/final)
- [SP 800-90 series random-bit generation](https://csrc.nist.gov/projects/random-bit-generation/sp-800-90-updates)

## Refresh rule

Before any architecture freeze, ACVTS campaign, report submission, or release
claim, the CST laboratory and vendor must:

1. fetch every applicable source from its official NIST location;
2. record the displayed revision/date and the retrieved-byte digest;
3. compare the requirements with this repository and the exact candidate
   module build;
4. update this inventory through review; and
5. discard downloaded working copies unless the lab evidence plan requires
   retention.

The repository retains links, versions, digests, decisions, and compact test
evidence. It does not retain unbounded PDF, solver, ACVTS-session, or build
trees.
