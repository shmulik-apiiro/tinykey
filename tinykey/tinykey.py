#!/usr/bin/env python3
"""tinykey: flag EC public keys whose private scalar k is tiny (k or n-k at most 2^B).

Never prints or returns k: the table maps only x-coordinates to a set.
Usage: tinykey.py [--bits B] PATH...   (cert/pubkey PEM or DER, bundles, directories)
Exit status: 1 if any weak key is found; 2 if no weak key but something could not be scanned
(unreadable file, parse failure, unsupported EC curve); 0 only if everything scanned clean.
Non-EC keys are out of scope and skipped silently.
"""
import argparse, hashlib, re, sys
from pathlib import Path
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec

# curve name -> (curve class, field prime p, a). Generator comes from `cryptography`.
CURVES = {
    "secp256r1": (ec.SECP256R1, 2**256 - 2**224 + 2**192 + 2**96 - 1, -3),
    "secp384r1": (ec.SECP384R1, 2**384 - 2**128 - 2**96 + 2**32 - 1, -3),
    "secp521r1": (ec.SECP521R1, 2**521 - 1, -3),
    "secp256k1": (ec.SECP256K1, 2**256 - 2**32 - 977, 0),
}
_tables = {}
problems = 0


def warn(msg):
    """Report something that could not be scanned (makes the exit status 2 unless a weak key is found)."""
    global problems
    problems += 1
    print(msg, file=sys.stderr)


def _add(P, Q, p, a):
    """Jacobian + affine point addition (P != +-Q), or doubling if P == Q."""
    X1, Y1, Z1 = P
    x2, y2 = Q
    Z1s = Z1 * Z1 % p
    U2, S2 = x2 * Z1s % p, y2 * Z1s * Z1 % p
    H, R = (U2 - X1) % p, (S2 - Y1) % p
    if H == 0:
        if R:
            raise ValueError("point at infinity")  # unreachable below the group order
        S = 4 * X1 * Y1 * Y1 % p
        M = (3 * X1 * X1 + a * Z1s * Z1s) % p
        X3 = (M * M - 2 * S) % p
        return X3, (M * (S - X3) - 8 * pow(Y1, 4, p)) % p, 2 * Y1 * Z1 % p
    H2 = H * H % p
    H3 = H * H2 % p
    V = X1 * H2 % p
    X3 = (R * R - H3 - 2 * V) % p
    return X3, (R * (V - X3) - Y1 * H3) % p, Z1 * H % p


def table(name, bits):
    """Set of x(k*G) for 1 <= k <= 2^bits (x is shared by k and n-k)."""
    if (name, bits) not in _tables:
        cls, p, a = CURVES[name]
        g = ec.derive_private_key(1, cls()).public_key().public_numbers()
        G, P, xs = (g.x, g.y), (g.x, g.y, 1), {g.x}
        for _ in range(2**bits - 1):
            P = _add(P, G, p, a)
            xs.add(P[0] * pow(P[2] * P[2], -1, p) % p)
        _tables[(name, bits)] = xs
    return _tables[(name, bits)]


def keys_in(path):
    """Yield (subject or '-', public key) from a PEM/DER cert, public key or bundle."""
    try:
        data = Path(path).read_bytes()
    except OSError as e:
        return warn(f"{path}: unreadable: {e}")
    if b"-----BEGIN" in data:
        if not re.search(rb"-----BEGIN (TRUSTED )?(CERTIFICATE|PUBLIC KEY)-----.*?-----END", data, re.S):
            return warn(f"{path}: no complete certificate or public key PEM block")
        for m in re.finditer(rb"-----BEGIN ([A-Z0-9 ]+)-----.*?-----END \1-----", data, re.S):
            blk = m.group(0)
            try:
                if m.group(1) in (b"CERTIFICATE", b"TRUSTED CERTIFICATE"):
                    c = x509.load_pem_x509_certificate(blk)
                    yield c.subject.rfc4514_string(), c.public_key()
                elif m.group(1) == b"PUBLIC KEY":
                    yield "-", ser.load_pem_public_key(blk)
            except (ValueError, UnsupportedAlgorithm) as e:
                warn(f"{path}: unparsable block: {e}")
        return
    for load, subj in ((x509.load_der_x509_certificate, True), (ser.load_der_public_key, False)):
        try:
            obj = load(data)
            yield (obj.subject.rfc4514_string(), obj.public_key()) if subj else ("-", obj)
            return
        except (ValueError, UnsupportedAlgorithm):
            pass
    warn(f"{path}: not a certificate or public key")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--bits", type=int, default=16, choices=range(1, 25), metavar="B",
                    help="check scalars up to 2^B (default 16, max 24; 24 is slow)")
    args = ap.parse_args()
    files = []
    for a in args.paths:
        pth = Path(a)
        files += sorted(f for f in pth.rglob("*") if f.is_file()) if pth.is_dir() else [pth]
    weak = 0
    for f in files:
        for subj, key in keys_in(f):
            spki = hashlib.sha256(key.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
            if not isinstance(key, ec.EllipticCurvePublicKey):
                continue
            if key.curve.name not in CURVES:
                warn(f"{f}\t{subj}\t{spki}\tunsupported curve {key.curve.name}: not scanned")
                continue
            name = key.curve.name
            is_weak = key.public_numbers().x in table(name, args.bits)
            weak += is_weak
            verdict = f"WEAK: private scalar at most 2^{args.bits} (or n minus it)" if is_weak else "ok"
            print(f"{f}\t{subj}\t{spki}\t{name}\t{verdict}")
    sys.exit(1 if weak else 2 if problems else 0)


if __name__ == "__main__":
    main()
