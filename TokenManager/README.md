# TokenManager (PrivateKeyJWT)

External library for OutSystems Developer Cloud that encodes and decodes PrivateKeyJWT tokens and calls token endpoints over HTTPS.

## TLS behaviour of GetTokensFromUrl

| `certificateToAllow` | `ignoreCertificateValidation` | Result |
| --- | --- | --- |
| supplied | any | Accepted only if the server certificate is byte-for-byte equal to `certificateToAllow`. The flag has no effect. |
| not supplied | `false` | Normal TLS validation. Any certificate error rejects the call. |
| not supplied | `true` | Certificate errors are ignored and the server certificate is not validated. |

Supply `certificateToAllow` whenever the server uses a self-signed certificate. Leaving it out with `ignoreCertificateValidation = true` accepts the risk of a man-in-the-middle on that connection.

## Supported key parameters

All key generation actions validate their parameters and reject anything outside the lists below before generating a key.

### CreateECJWKPair (EC keys)

| `crv` | Curve | Key size | `use = sig` algorithm | `use = enc` algorithms |
| --- | --- | --- | --- | --- |
| `P-256` | nistP256 | 256 bits | `ES256` | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` |
| `P-384` | nistP384 | 384 bits | `ES384` | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` |
| `P-521` | nistP521 | 521 bits | `ES512` | `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A192KW`, `ECDH-ES+A256KW` |

For `use = sig`, the algorithm must match the curve. Any other `crv` value is rejected.

### CreateRSAJWKPair (RSA keys, 2048 bits)

- `use = enc`: `RSA-OAEP`, `RSA-OAEP-256`
- `use = sig`: `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`

### use

Only `sig` (signing) and `enc` (encryption) are accepted.
