# TokenManager (PrivateKeyJWT)

External library for OutSystems Developer Cloud that encodes and decodes PrivateKeyJWT tokens and calls token endpoints over HTTPS.

## TLS behaviour of GetTokensFromUrl

| `certificateToAllow` | `ignoreCertificateValidation` | Result |
| --- | --- | --- |
| supplied | any | Accepted only if the server certificate is byte-for-byte equal to `certificateToAllow`. The flag has no effect. |
| not supplied | `false` | Normal TLS validation. Any certificate error rejects the call. |
| not supplied | `true` | Certificate errors are ignored and the server certificate is not validated. |

Supply `certificateToAllow` whenever the server uses a self-signed certificate. Leaving it out with `ignoreCertificateValidation = true` accepts the risk of a man-in-the-middle on that connection.
