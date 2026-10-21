#!/usr/bin/env python3
"""Check the archived 2025 CRL against its issuer cert; prints only two lines.
Usage: python3 verify.py   (needs ../../tinykey/tinykey.py)"""
import sys
from pathlib import Path
from cryptography import x509

here = Path(__file__).resolve().parent
sys.path.insert(0, str(here.parent.parent / "tinykey"))
import tinykey

crl = x509.load_der_x509_crl((here / "EMDVTLSCAG3C.20250625073552.crl").read_bytes())
issuers = [x509.load_pem_x509_certificate(b.encode() + b"-----END CERTIFICATE-----\n")
           for b in (here / "issuer_EM_DV_TLS_CA_G3C.pem").read_text().split("-----END CERTIFICATE-----\n") if b.strip()]
valid = [c for c in issuers if crl.is_signature_valid(c.public_key())]
print("signature valid" if valid else "signature INVALID")
weak = any(c.public_key().public_numbers().x in tinykey.table(c.public_key().curve.name, 16) for c in valid)
print("issuer key weak:", "yes" if weak else "no")
sys.exit(0 if valid and weak else 1)
