# Data backing the post

Public data: aggregate results plus the public CA artifacts (certificates, CRLs) and per-endpoint verification rows. Snapshot dates: 2026-10-20 (GH Archive day used for the GitHub sweep) and 2026-10-21 (all other collections).

- sweep/: tiny-scalar sweep per dataset (sweep_summary.tsv, README.md): counts and bounds only.
- crlsweep/: CRL and OCSP signature sweep across the web PKI (counts.tsv, verify.tsv, ocsp_verify.tsv, README.md). Public CA data.
- crl11/: emSign Root TLS CA - G1 CRL #11 evidence. CRL #11, CRL #12, the G1 root and cross-signed certs, the OCSP responder cert. `python3 crl11/verify.py` checks the hashes and that the revoked entries (serial, revocation date, extensions) match in #11 and #12, that #11 verifies under the responder key (not the root), #12 under the root.
- archived_2025/: Internet Archive capture of the EM DV TLS CA - G3C CRL (SOURCE.txt has the archive URL), the issuer certs, and verify.py, which prints "signature valid" and "issuer key weak: yes/no" using ../tinykey/tinykey.py (it never outputs the scalar) and exits 0 only if the signature is valid and the issuer key is weak.
- longtail.md: class counts of other projects' trust of the affected CAs.

Re-run everything: `python3 crl11/verify.py && python3 archived_2025/verify.py` (needs Python 3 and `cryptography`).

License: see LICENSE-DATA.md.
