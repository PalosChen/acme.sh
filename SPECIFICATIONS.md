# Persistent DNS client specification baseline

The client implements the DNS-name path of [draft-ietf-acme-dns-persist-03](https://www.ietf.org/archive/id/draft-ietf-acme-dns-persist-03.txt).
SHA-256 `6e8032494d9bf5c24056030b7b460b6e06ef08ecf2f152a8809dd0792d004611`.

- §§3.1–3.2 and 4.5. Pre-provisioning uses a conforming directory
  `meta.issuerDomainNames` array. Interactive challenges require their own
  conforming array. It includes the directory baseline when available and is
  checked against normalized `caaIdentities` when available.
- §§4.1 and 12.2. Preserve the advertised `accountHashPrefix`. Append
  `sha-256/` and the unpadded base64url digest of the record-domain length
  octet, ASCII domain, RFC 7638 account key thumbprint and exact account URL.
  The `*` opt-out is explicit. Draft-01 cleartext TXT values require replacement.
- §4.5. Read the directory over HTTPS and verify the account with an empty
  JWS POST-as-GET to its exact URL, with redirects disabled and account status
  `valid`, before printing a record for publication.
- §§4, 5 and 6. POST `{}` for exact names. An explicit proper ancestor uses
  `ancestorDomain` and `policy=wildcard`. Validate DNS label and full owner
  lengths, use the selected record domain in the digest and save ancestor
  selection for renewals. The CA enforces public suffix policy.
- §§4.1 and 9.10. Optional `persistUntil` is a decimal Unix timestamp that
  also bounds authorization expiry and reuse. DNS TTL controls caching.
- §7. Reverse-IP validation is optional. This branch supports DNS identifiers.

The offline HTTPS fixture exercises record output, account verification, exact
and ancestor challenge POSTs, ancestor renewal and refusal of invalid metadata.
It includes the published §13.2 hash vectors.
