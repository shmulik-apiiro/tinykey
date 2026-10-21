# Data license

The derived tables in this directory (crlsweep/counts.tsv, crlsweep/verify.tsv, crlsweep/ocsp_verify.tsv, sweep/sweep_summary.tsv and the READMEs) are licensed under Creative Commons Attribution 4.0 International (CC BY 4.0): https://creativecommons.org/licenses/by/4.0/

The raw certificates and CRLs (crl11/, archived_2025/) are public artifacts published by the certificate authorities and redistributed unmodified for verification; we claim no rights in them. Sources:

- crl11/: CRL #11 from the attachment to Mozilla bug 2083449 comment 8 (https://bugzilla.mozilla.org/show_bug.cgi?id=2083449#c8); CRL #12 from eMudhra's public CRL endpoint; the OCSP responder certificate as embedded in responses from eMudhra's public OCSP responders (ocsp.emsign.com); the root and cross-signed certificates from CCADB (https://www.ccadb.org/) and Certificate Transparency (https://crt.sh/).
- archived_2025/: Internet Archive capture of https://crl.emsign.com/?EMDVTLSCAG3C.crl (https://web.archive.org/web/20250625073552id_/https://crl.emsign.com/?EMDVTLSCAG3C.crl); the issuer certificates come from CCADB.
- crlsweep/ rows describe public CRL and OCSP URLs published in CCADB and certificates; the URLs are listed per row.

The tinykey/ code is MIT licensed (see ../tinykey/LICENSE).
