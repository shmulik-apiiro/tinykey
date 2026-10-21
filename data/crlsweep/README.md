# CRL and OCSP signature sweep (snapshot 2026-10-21)

Scope: 3,659 unexpired, unrevoked CA certs in CCADB chaining to a root included in Mozilla, Chrome, Apple or Microsoft; 18,486 CRL URLs and 199 OCSP URLs. Each CRL was verified against every CCADB key whose subject equals the CRL issuer (8,173 unique keys).

- counts.tsv: result classes (CRLs from CCADB, plus a supplement of 457 URLs flagged by crt.sh). Counts are URLs; rows are not mutually exclusive (for example Stale overlaps the status rows). The OK row's unique count is 17,662 OK CRLs out of 17,668 unique CRLs fetched; the other statuses account for the rest.
- verify.tsv: one row per CRL URL: index, status (OK, MISMATCH, NO_ISSUER, UNPARSABLE, UNREACHABLE), detail, CRL SHA-256, issuer name, number of candidate keys, matching key (SPKI prefix), signature algorithm, thisUpdate, nextUpdate, URL. The 18,943 rows include the crt.sh supplement.
- ocsp_verify.tsv: one row per (responder URL, issuer key): status, URL, issuer name, issuer key id, response digest, direct or delegated signer, certificate status. 330 OK, 0 MISMATCH, 2 BAD_DELEGATION.

Result: no publicly trusted CA serves a CRL that fails signature verification under its issuer certificate's key, other than the 2025 eMudhra case and the 2026-10-14 emSign Root TLS CA - G1 CRL #11 (../crl11). In 2025 the CRLs were flagged as failing verification and eMudhra attributed this to using the wrong private key (Mozilla bugs 1970727 and 1970728: https://bugzilla.mozilla.org/show_bug.cgi?id=1970727, https://bugzilla.mozilla.org/show_bug.cgi?id=1970728); its fix re-signed them with the issuer's own key, which is itself a weak key (tiny private scalar). The archived 2025-06-25 CRL therefore verifies under the weak issuer key (../archived_2025). The 5 MISMATCH rows are non-program CAs or rollovers, all RSA.

OCSP: no response has a signature that fails under its issuer key. The 2 BAD_DELEGATION rows (DVV Gov. Root CA - G3 RSA and ECC responders) are delegated responder certificates that lack the OCSP-signing extended key usage; they are not key mismatches.
