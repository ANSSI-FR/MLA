# MLAKEY file format

MLA can use cryptography for signature and/or encryption. Thus it needs to operate with keys. An implementation can get access to these keys from a serialized format described here.

The string `||` denotes concatenation.

## Private key file format

A private key file is an ASCII file, which may use `mlapriv` as file extension. The file (or whatever serialization medium) content is `PrivEncHdr||B64Priv4Enc||<CR><LF>||PrivSigHdr||B64Priv4Sig||<CR><LF>||B64PrivOpts||<CR><LF>` where `<CR>` is ASCII carriage return, `<LF>` is ASCII line feed, and `PrivEncHdr`, B64Priv4Enc`, `PrivSigHdr`, `B64Priv4Sig` and `B64PrivOpts` are described below.

* `PrivEncHdr` is the ASCII string `MLA PRIVATE DECRYPTION KEY " (note the trailing space).
* `PrivSigHdr` is the ASCII string `MLA PRIVATE SIGNATURE KEY " (note the trailing space).
* `B64Priv4Enc` is the base64 encoding (RFC 4648) of `EncMethodId||PrivEncOpts||X25519PrivKey||MLKEM1024PrivKey` where `EncMethodId`, `PrivEncOpts`, `X25519PrivKey` and` MLKEM1024PrivKey` are described below.
* `B64Priv4Sig` is the base64 encoding of `SigMethodId||PrivSigOpts||Ed25519PrivKey||MLDSA87PrivKey` where `MethodId`, `PrivEncOpts`, `Ed25519PrivKey` and` MLDSA87PrivKey` are described below.

* The only valid `EncMethodId` for the moment is the ASCII `mla-kem-private-x25519-mlkem1024`.
* The only valid `SigMethodId` for the moment is the ASCII `mla-signature-private-ed25519-mldsa87`.
* `X25519PrivKey` is a X255519 private key as specified in RFC 7748.
* `MLKEM1024PrivKey` is an ML-KEM-1024 private key as specified in FIPS 203.
* `Ed25519PrivKey` is a Ed255519 private key as specified in RFC 8032.
* `MLDSA87PrivKey` is an ML-DSA-87 private key as specified in FIPS 204.

For `PrivEncOpts` and `PrivSigOpts`, refer to below generic explaination for `KeyOpts`.

* `B64PrivOpts` is a base64 encoded `KeyOpts`.

## Public key file format

A public key file is an ASCII file, which may use `mlapub` as file extension. The file (or whatever serialization medium) content is `PubEncHdr||B64Pub4Enc||<CR><LF>||PubSigHdr||B64Pub4Sig||<CR><LF>||B64PubOpts||<CR><LF>` where `<CR>` is ASCII carriage return, `<LF>` is ASCII line feed, and `PubEncHdr`, B64Pub4Enc`, `PubSigHdr`, `B64Pub4Sig` and `B64PubOpts` are described below.

* `PubEncHdr` is the ASCII string `MLA PUBLIC ENCRYPTION KEY " (note the trailing space).
* `PubSigHdr` is the ASCII string `MLA PUBLIC SIGNATURE VERIFICATION KEY " (note the trailing space).
* `B64Pub4Enc` is the base64 encoding (RFC 4648) of `EncMethodId||PubEncOpts||X25519PubKey||MLKEM1024PubKey` where `EncMethodId`, `PubEncOpts`, `X25519PubKey` and` MLKEM1024PubKey` are described below.
* `B64Pub4Sig` is the base64 encoding of `SigMethodId||PubSigOpts||Ed25519PubKey||MLDSA87PubKey` where `MethodId`, `PubEncOpts`, `Ed25519PubKey` and` MLDSA87PubKey` are described below.

* The only valid `EncMethodId` for the moment is the ASCII `mla-kem-public-x25519-mlkem1024`.
* The only valid `SigMethodId` for the moment is the ASCII `mla-signature-verification-public-ed25519-mldsa87`.
* `X25519PubKey` is a X255519 public key as specified in RFC 7748.
* `MLKEM1024PubKey` is an ML-KEM-1024 public key as specified in FIPS 203.
* `Ed25519PubKey` is a Ed255519 public key as specified in RFC 8032.
* `MLDSA87PubKey` is an ML-DSA-87 public key as specified in FIPS 204.

For `PubEncOpts` and `PubSigOpts`, refer to below generic explaination for `KeyOpts`.

`KeyOpts` fields are options fields for future-proofing the format in case of later non-breaking optional additions to the key file format. It is a length-value field where `length` is the length in bytes of value, serialized as a 4 bytes little-endian integer. Possible `values` are left unspecified for the moment, but implementations, particularly for public keys, should read `length` bytes correctly in case an options are specified later.

* `B64PubOpts` is a base64 encoded `KeyOpts`.

## Options

`KeyOpts` fields are options fields for future-proofing the format in case of later non-breaking optional additions to the key file format. It is a length-value field where `length` is the length in bytes of value, serialized as a 4 bytes little-endian integer. Possible `values` are left unspecified for the moment, but implementations, particularly for public keys, should read `length` bytes correctly in case an options are specified later.
