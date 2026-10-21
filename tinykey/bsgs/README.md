# bsgs: baby-step giant-step scanner for larger bounds

Finds public keys Q = d*G with |d| <= bound (d or n-d small) using a baby table of
x(i*G), i = 1..M, and giant steps of 2M*G. Prints only a label on a hit:

    HIT <label> scalar within bound

It never prints the scalar or its size. Final line: `DONE <curve> keys=N bound |d|<=B (~2^b)`.

## Build

    make            # uses pkg-config openssl, else Homebrew openssl@4/@3

## Usage

    ./bsgs <curve> <keys.txt> <logM> <J> <threads>

- `curve`: OpenSSL short name (`prime256v1`, `secp384r1`, `secp521r1`, `secp256k1`, brainpool...) or `custom:p:a:b:gx:gy:n:h` (short Weierstrass, all fields hex; `h` is the cofactor and is required, e.g. `1` for prime-order curves, `8` for Ed25519 in Weierstrass form).
- `keys.txt`: lines `<label> <hex SEC1 point>`, all on one curve (uncompressed `04...` or compressed).
- `logM` is 1..31 and `threads` 1..64; invalid arguments, an unreadable key file or bad curve parameters exit 1. Lines that are not a valid finite point on the curve are reported on stderr and make the exit status 2. Duplicate or colliding baby-table keys are all kept and every candidate is verified against the full point.
- Baby table size M = 2^logM (memory about 16 bytes x M). Bound = 2*M*J + M.
- Cost: building the table is M point additions per thread-set; scanning is (J+1) x 2 additions per key.

Example, bound about 2^36 (logM=24, J=2048), 8 threads:

    ./bsgs secp384r1 keys_p384.txt 24 2048 8

Extract points from certificates with any tool, e.g. `openssl x509 -pubkey -noout | openssl ec -pubin -conv_form uncompressed -text`.
