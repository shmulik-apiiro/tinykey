# Long tail: vendored CA bundles that contain emSign ECC Root CA - G3

Snapshot: default branches as of 2026-10-21. Repositories are not named; the point is how many independent copies exist, not who has them.

## Collection

GitHub code search for the string "emSign ECC Root CA - G3" estimates about 100,000 files. Search returns at most 1,000 results per query, so the query was split into 22 partitions: cacert.pem by size bucket, common bundle file names (ca-bundle.crt, ca-certificates.crt, cacerts.pem, roots.pem, cert.pem, ca-bundle.pem), and source/text extensions (h, c, go, rs, py, js, ts, java, cs, txt, crt, pem). Result: 8,597 files in 5,696 repositories (a floor: a few pages were lost to rate limits, and code search excludes forks and private code).

## Sample

338 repositories: the 38 most-starred from an initial 1,000-hit pass, the 200 most-starred of the rest (at least 116 stars), and 100 picked at random (seed 20261021) from the remaining 5,458.

## Classification

For each repository, a reviewer read the code that loads the bundle and assigned one class:

- default: the trust store by default at runtime, or baked into a shipped artifact (binary, firmware, image, package) that trusts it by default. Build inputs count here only if the shipped output trusts it by default.
- fallback: used only when the system store is missing or fails.
- opt-in: used only if the user enables it (flag, config, environment variable).
- CI-only: tests, CI or developer tooling.
- unused/unclear: nothing loads it, or it could not be determined.

A second reviewer re-checked 52 calls (every low-evidence call, 30 random "default" calls and every build input); 2 changed.

| Class | Most-starred (238) | Random (100) | Total (338) |
|---|---|---|---|
| default | 159 | 44 | 203 |
| fallback | 10 | 3 | 13 |
| opt-in | 14 | 3 | 17 |
| CI-only | 15 | 2 | 17 |
| unused/unclear | 40 | 48 | 88 |

Firmware or embedded projects: 46 of the 338, 25 of them default.

Revocation: of the first 38, 29 use their bundle and none of those checks revocation (2 could not be confirmed either way). Revocation was not checked for the other 300.
