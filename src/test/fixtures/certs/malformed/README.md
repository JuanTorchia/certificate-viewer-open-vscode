# Malformed DER and ASN.1 fixtures

These fixtures are synthetic byte sequences for parser hardening tests. They are not real certificates and do not contain private material.

- `truncated-sequence.der`: starts a long-form ASN.1 SEQUENCE length but omits the length bytes.
- `declared-length-too-long.der`: declares more SEQUENCE content than the file contains.
- `unexpected-top-level-tag.der`: uses a SET tag where certificate parsing expects certificate DER structure.
