# tinykey

Detection of elliptic-curve public keys whose private scalar is tiny, plus the public data behind Apiiro's research on the eMudhra CA keys with private scalars below 256 (Mozilla bug 2083449).

- [tinykey/](tinykey/): the detector (`tinykey.py`, pure Python) and a C baby-step giant-step scanner for larger bounds (`tinykey/bsgs/`). Detection only: neither tool prints a recovered scalar.
- [data/](data/): sweep results, the CRL and OCSP signature sweep, the CRL #11 evidence and the archived 2025 CRL, each with a verify script.

Quick start:

    pip install cryptography
    python3 tinykey/tinykey.py /etc/ssl/certs

Code: MIT (tinykey/LICENSE). Data: see data/LICENSE-DATA.md.
