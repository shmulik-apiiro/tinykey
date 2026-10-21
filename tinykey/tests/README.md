# Tests

`python3 tests/test_tinykey.py` generates synthetic keys on P-256, P-384, P-521 and secp256k1 (k = 1, 2, 255, 2^16, n-7 must be flagged; 2^16+1 and 5 random keys must be ok), checks `--bits`, bundle and directory input, asserts the scalar never appears in the output, and checks exit code 2 for unparsable files, unreadable files and unsupported curves (brainpoolP256r1, secp224r1), and exit code 1 when a weak key sits alongside unscannable inputs. No eMudhra keys are used as test vectors. Takes about 2 minutes (each case rebuilds the table).

## Real-world run

`python3 tinykey.py <CCADB eMudhra CA bundle, 71 certificates>` (snapshot 2026-10-21): 16 weak certificates, 8 unique weak SPKIs (all P-384), exit code 1; the other 55 certificates are ok.
