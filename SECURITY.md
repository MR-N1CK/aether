# Security policy

Aether is a read-only Linux compromise-assessment tool. Reports about the scanner itself are welcome. Findings Aether produces on a host you are authorized to assess are operational results, not vulnerabilities in this project.

## Report a vulnerability

Use a private report so exploit detail does not land in a public issue:

[Open a GitHub security advisory](https://github.com/MR-N1CK/aether/security/advisories/new)

If private advisories are not available on the repository yet, contact the maintainer directly and wait for acknowledgement before any public write-up. Please include the version or commit, the platform, and a minimal way to observe the issue without live malware.

## In scope

- The `aether` binary, its installer, and the HTML report renderer
- File-access bugs that write to a target, follow an unexpected symlink, or change timestamps the tool claims to preserve
- Report-generation bugs that execute attacker-controlled content in the offline HTML report
- Rule-loading bugs that trust a world-writable rules directory without `--trust-rules-dir`

## Out of scope

- Detections or false positives on a specific sample, unless the scanner violates its read-only rules while producing them
- Attacks that require an already-compromised root kernel the scanner cannot observe
- Social-engineering against the maintainer

## Safe testing

Inspect samples statically. Do not execute untrusted binaries, scripts, or dumps from this repository as part of a report.
