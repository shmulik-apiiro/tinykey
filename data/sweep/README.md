# Tiny-scalar sweep (snapshot 2026-10-20/21)

Test: public key Q = d*G with |d| <= bound (d or n-d small), baby-step giant-step (see ../../tinykey/bsgs). Detection only; no private values were stored or printed.
Keys are deduplicated by SPKI. Curve mix per dataset is mostly P-256, P-384 and Ed25519 (mapped to its Weierstrass form); CT also has 4 P-521 keys.

Bounds are |d| <= 2*M*J + M as reported by the scanner: 6.9e10 (>= 2^36) and 2.75e11 (>= 2^38), plus the 2^41 and 2^44 rows for the CA and trust-list sets (see sweep_summary.tsv).

The Ed25519 to Weierstrass conversion code is not included in this repo; Ed25519 results rely on that external conversion and the self-test below was run outside it.

Ed25519/X25519 limit: only keys whose scalar is used directly (no SHA-512 + clamping) are found. A weak seed yields a full-size scalar and is not detected.

Self-test: planted scalars {1, 2, 255, 12345, 2^31+7, 2^32-5, n-999} were found on P-256, P-384, P-521, secp256k1 and Ed25519; 50 random keys per curve were not flagged.

Not covered: SSH host-key scans, PGP keyserver dumps, Android APK signing certs, active scanning.

Result: the CCADB and eMudhra-related sets hit only the 8 known eMudhra intermediates (the positive control). Nostr has 178 public keys with tiny scalars (mostly dormant accounts, consistent with test or bulk-generated keys). Every other dataset has 0 hits. See sweep_summary.tsv.
