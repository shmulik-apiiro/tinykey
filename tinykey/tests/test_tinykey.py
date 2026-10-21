#!/usr/bin/env python3
"""Synthetic tests: plant tiny scalars, check detection; random keys must be ok.
Run: python3 tests/test_tinykey.py"""
import subprocess, sys, tempfile
from pathlib import Path
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec

TOOL = Path(__file__).resolve().parent.parent / "tinykey.py"
N = {  # group orders (test data only)
    "P-256": (ec.SECP256R1, 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551),
    "P-384": (ec.SECP384R1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973),
    "P-521": (ec.SECP521R1, int("1FF" + "F" * 63 + "A51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16)),
    "secp256k1": (ec.SECP256K1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141),
}


def run(path, *extra):
    r = subprocess.run([sys.executable, str(TOOL), *extra, str(path)], capture_output=True, text=True)
    return r.returncode, r.stdout


def run_err(path, *extra):
    r = subprocess.run([sys.executable, str(TOOL), *extra, str(path)], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


def pem(key):
    return key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)


def main():
    fails = 0
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        for name, (cls, n) in N.items():
            cases = [("k=1", 1, True), ("k=2", 2, True), ("k=255", 255, True), ("k=2^16", 2**16, True),
                     ("k=n-7", n - 7, True), ("k=2^16+1", 2**16 + 1, False)]
            for label, k, expect in cases:
                p = d / "k.pem"
                p.write_bytes(pem(ec.derive_private_key(k, cls())))
                rc, out = run(p)
                ok = (rc == 1 and "WEAK" in out) if expect else (rc == 0 and "ok" in out)
                fails += not ok
                print(("PASS" if ok else "FAIL"), name, label)
                assert not {str(k), hex(k), f'{k:x}'} & set(out.split())  # scalar never printed
            for i in range(5):
                p = d / "r.pem"
                p.write_bytes(pem(ec.generate_private_key(cls())))
                rc, out = run(p)
                ok = rc == 0 and "ok" in out
                fails += not ok
                print(("PASS" if ok else "FAIL"), name, f"random #{i}")
        # --bits: 2^16+1 is found with --bits 17; bundle and directory input
        p = d / "b.pem"
        p.write_bytes(pem(ec.derive_private_key(2**16 + 1, ec.SECP256R1())) + pem(ec.generate_private_key(ec.SECP256R1())))
        rc, out = run(p, "--bits", "17")
        ok = rc == 1 and out.count("WEAK") == 1 and out.count("\n") == 2
        fails += not ok
        print(("PASS" if ok else "FAIL"), "--bits 17 on a 2-key bundle")
        rc, out = run(d, "--bits", "17")
        ok = rc == 1 and "WEAK" in out
        fails += not ok
        print(("PASS" if ok else "FAIL"), "directory input")
        # exit 2: nothing weak but something unscannable; exit 1 still wins if a weak key is present
        junk = d / "junk.txt"
        junk.write_text("not a key")
        rc, out, err = run_err(junk)
        ok = rc == 2 and "not a certificate" in err
        fails += not ok
        print(("PASS" if ok else "FAIL"), "unparsable file -> exit 2")
        rc, out, err = run_err(d / "missing.pem")
        ok = rc == 2 and "unreadable" in err
        fails += not ok
        print(("PASS" if ok else "FAIL"), "unreadable file -> exit 2")
        for cname, cls in (("brainpoolP256r1", ec.BrainpoolP256R1), ("secp224r1", ec.SECP224R1)):
            u = d / "unsupported.pem"
            u.write_bytes(pem(ec.generate_private_key(cls())))
            rc, out, err = run_err(u)
            ok = rc == 2 and "unsupported curve" in err and "ok" not in out
            fails += not ok
            print(("PASS" if ok else "FAIL"), f"unsupported curve {cname} -> exit 2")
        mixed = d / "mixed"
        mixed.mkdir()
        (mixed / "a.pem").write_bytes(pem(ec.derive_private_key(3, ec.SECP256R1())))
        (mixed / "b.pem").write_bytes(pem(ec.generate_private_key(ec.SECP224R1())))
        (mixed / "c.txt").write_text("junk")
        rc, out, err = run_err(mixed)
        ok = rc == 1 and "WEAK" in out and "unsupported curve" in err
        fails += not ok
        print(("PASS" if ok else "FAIL"), "weak key plus unscannable inputs -> exit 1, scan continues")
    print("FAILED" if fails else "ALL PASSED", fails)
    sys.exit(1 if fails else 0)


main()
