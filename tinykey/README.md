# tinykey

Flags EC public keys (P-256, P-384, P-521, secp256k1) whose private scalar k is tiny: the public point equals +-k*G with 1 <= k <= 2^B, i.e. k at most 2^B (default B = 16, up to 24). The check uses a table of x-coordinates, since k and n-k share x. The tool never prints, logs or returns k.

## Why

A tiny scalar is a perfectly valid private key. The point is on the curve, in the right subgroup, the signatures verify, and the certificate chains. No validity check catches it, but anyone can recover the key by enumeration. A key like this usually comes from a broken or misconfigured key generation step.

## Limits

- Heuristic, not a standards rule: no spec forbids small scalars, and a random key lands below 2^16 with probability about 2^-368 on P-384.
- It does not find weak seeds or low-entropy generators that produce full-size scalars, or non-EC keys.
- `--bits 24` builds a 16M-entry table in pure Python (minutes, GBs of RAM). For larger bounds use `bsgs/` (C, OpenSSL).

## Usage

    pip install cryptography
    python3 tinykey.py cert.pem                    # cert, bundle, SPKI PEM or DER
    python3 tinykey.py --bits 20 /etc/ssl/certs    # directories are searched recursively

Output per EC key (tab-separated): file, subject (`-` for bare public keys), SPKI SHA-256, curve, and either `ok` or `WEAK: private scalar at most 2^B (or n minus it)`.

Exit codes: 1 if any weak key is found; 2 if no weak key was found but something could not be scanned (unreadable file, parse failure, EC key on an unsupported curve, each reported on stderr; scanning continues past them); 0 only if everything scanned clean. Non-EC keys are skipped silently. Supported curves: P-256, P-384, P-521, secp256k1; others (e.g. brainpool, secp224r1) are reported as unsupported.

Tests: `python3 tests/test_tinykey.py` (synthetic keys only). Larger bounds: see `bsgs/README.md`.

## Prior art

badkeys issue #38: https://github.com/badkeys/badkeys/issues/38

## License

MIT, copyright Apiiro. See LICENSE.
