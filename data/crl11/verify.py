#!/usr/bin/env python3
"""Re-verify the emSign Root TLS CA - G1 CRL #11 evidence. Usage: python3 verify.py"""
import hashlib
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

here = Path(__file__).resolve().parent
HASHES = {  # SHA-256 of the CRLs
    "emsign-root-tls-g1-crl-11.crl": "9846bf9a4f213d8fba87e79d464732b9cc35a784f7992334ec3bc6db2a6f7dbd",
    "emsign-root-tls-g1-crl-12.crl": "bd8f716ef9994931446ce90537ce69e85637aaddcd8a3b34f668e362d8b3d950",
}
cert = lambda n: x509.load_pem_x509_certificate((here / n).read_bytes())
ok = True
def check(label, cond):
    global ok
    ok &= bool(cond)
    print(("PASS" if cond else "FAIL"), label)

for n, h in HASHES.items():
    if h:
        check(f"sha256 {n}", hashlib.sha256((here / n).read_bytes()).hexdigest() == h)
resp, root, cross = cert("emsign-root-tls-g1-ocsp-2026-4.pem"), cert("emsign-root-tls-g1-root.crt.pem"), cert("emsign-root-tls-g1-cross.crt.pem")
check("responder cert SHA-256", resp.fingerprint(hashes.SHA256()).hex() == "9b43aa54cd6971c1432a1cca607d3d79d7b9128959d5ab7b796b2bf7f45450bf")
crl11 = x509.load_der_x509_crl((here / "emsign-root-tls-g1-crl-11.crl").read_bytes())
crl12 = x509.load_der_x509_crl((here / "emsign-root-tls-g1-crl-12.crl").read_bytes())
check("CRL #11 signature valid under the OCSP responder key", crl11.is_signature_valid(resp.public_key()))
check("CRL #11 signature NOT valid under the G1 root key", not crl11.is_signature_valid(root.public_key()))
check("CRL #12 signature valid under the G1 root key", crl12.is_signature_valid(root.public_key()))
def signed_by(c, k):
    try:
        k.verify(c.signature, c.tbs_certificate_bytes, padding.PKCS1v15(), c.signature_hash_algorithm)
        return True
    except Exception:
        return False
check("responder cert signed by the G1 key (root and cross-signed cert share it)", signed_by(resp, root.public_key()) and signed_by(resp, cross.public_key()))
entries = lambda crl: [(r.serial_number, r.revocation_date_utc, [(e.oid.dotted_string, e.critical, e.value.public_bytes()) for e in r.extensions]) for r in crl]
check("revoked entries identical in CRL #11 and #12 (serial, revocation date, entry extensions)", entries(crl11) == entries(crl12))
print("ALL PASSED" if ok else "FAILED")
raise SystemExit(0 if ok else 1)
