# MLA key file format

MLA can use cryptography for signature and/or encryption. Thus it needs to operate with keys. An implementation can get access to these keys from a serialized format described here.

The string `||` denotes concatenation.

## Private key file format

A private key file is an ASCII file, which may use `mlapriv` as file extension. The file (or whatever serialization medium) content is `PrivFormatHeader||<CR><LF>PrivEncHdr||B64Priv4Enc||<CR><LF>||PrivSigHdr||B64Priv4Sig||<CR><LF>||B64PrivOpts||<CR><LF>||PrivFormatFooter||<CR><LF>` where `<CR>` is ASCII carriage return, `<LF>` is ASCII line feed, and `PrivFormatHeader`, `PrivEncHdr`, `B64Priv4Enc`, `PrivSigHdr`, `B64Priv4Sig`, `B64PrivOpts` and `PrivFormatFooter` are described below.

* `PrivFormatHeader` is the ASCII string `DO NOT SEND THIS TO ANYONE - MLA PRIVATE KEY FILE V1`.
* `PrivEncHdr` is the ASCII string `MLA PRIVATE DECRYPTION KEY ` (note the trailing space).
* `PrivSigHdr` is the ASCII string `MLA PRIVATE SIGNING KEY ` (note the trailing space).
* `B64Priv4Enc` is the base64 encoding (RFC 4648) of `EncMethodId||PrivEncOpts||X25519PrivKey||MLKEM1024PrivKey` where `EncMethodId`, `PrivEncOpts`, `X25519PrivKey` and` MLKEM1024PrivKey` are described below.
* `B64Priv4Sig` is the base64 encoding of `SigMethodId||PrivSigOpts||Ed25519PrivKey||MLDSA87PrivKey` where `MethodId`, `PrivEncOpts`, `Ed25519PrivKey` and` MLDSA87PrivKey` are described below.
* `PrivFormatFooter` is the ASCII string `END OF MLA PRIVATE KEY FILE`

* The only valid `EncMethodId` for the moment is the ASCII `mla-kem-private-x25519-mlkem1024`.
* The only valid `SigMethodId` for the moment is the ASCII `mla-signature-private-ed25519-mldsa87`.
* `X25519PrivKey` is a X25519 private key as specified in RFC 7748.
* `MLKEM1024PrivKey` is an ML-KEM-1024 private key seed (d,z) as specified in FIPS 203 algorithm 16. d and z are concatenated in this order.
* `Ed25519PrivKey` is a Ed25519 private key as specified in RFC 8032.
* `MLDSA87PrivKey` is an ML-DSA-87 private key seed xi as specified in FIPS 204 algorithm 6.

For `PrivEncOpts` and `PrivSigOpts`, refer to below generic explanation for `KeyOpts`.

* `B64PrivOpts` is a base64 encoded `KeyOpts`.

## Public key file format

A public key file is an ASCII file, which may use `mlapub` as file extension. The file (or whatever serialization medium) content is `PubFormatHeader||<CR><LF>||PubEncHdr||B64Pub4Enc||<CR><LF>||PubSigHdr||B64Pub4Sig||<CR><LF>||B64PubOpts||<CR><LF>||PubFormatFooter||<CR><LF>` where `<CR>` is ASCII carriage return, `<LF>` is ASCII line feed, and `PubFormatHeader`, `PubEncHdr`, `B64Pub4Enc`, `PubSigHdr`, `B64Pub4Sig`, `B64PubOpts` and `PubFormatFooter` are described below.

* `PubFormatHeader` is the ASCII string `MLA PUBLIC KEY FILE V1`.
* `PubEncHdr` is the ASCII string `MLA PUBLIC ENCRYPTION KEY " (note the trailing space).
* `PubSigHdr` is the ASCII string `MLA PUBLIC SIGNATURE VERIFICATION KEY " (note the trailing space).
* `B64Pub4Enc` is the base64 encoding (RFC 4648) of `EncMethodId||PubEncOpts||X25519PubKey||MLKEM1024PubKey` where `EncMethodId`, `PubEncOpts`, `X25519PubKey` and` MLKEM1024PubKey` are described below.
* `B64Pub4Sig` is the base64 encoding of `SigMethodId||PubSigOpts||Ed25519PubKey||MLDSA87PubKey` where `MethodId`, `PubEncOpts`, `Ed25519PubKey` and` MLDSA87PubKey` are described below.
* `PubFormatFooter` is the ASCII string `END OF MLA PUBLIC KEY FILE`

* The only valid `EncMethodId` for the moment is the ASCII `mla-kem-public-x25519-mlkem1024`.
* The only valid `SigMethodId` for the moment is the ASCII `mla-signature-verification-public-ed25519-mldsa87`.
* `X25519PubKey` is a X25519 public key as specified in RFC 7748.
* `MLKEM1024PubKey` is an ML-KEM-1024 public key as specified in FIPS 203.
* `Ed25519PubKey` is a Ed25519 public key as specified in RFC 8032.
* `MLDSA87PubKey` is an ML-DSA-87 public key as specified in FIPS 204.

For `PubEncOpts` and `PubSigOpts`, refer to below generic explanation for `KeyOpts`.

* `B64PubOpts` is a base64 encoded `KeyOpts`.

## Options

`KeyOpts` fields are options fields for future-proofing the format in case of later non-breaking optional additions to the key file format. It is serialized with a tag of value 0 as a u8 if no option is present. Otherwise it is serialized with a tag of value 1 as u8 followed by a `keyoptslen` u64 and a sequence of `TLVKeyOpt`. This sequence of `TLVKeyOpt` is of `keyoptslen` size in bytes. Multiple fields in this key format are of type `KeyOpts` for future proofing reasons, but no option is defined at the moment. For future proofing, implementers of this format version must still handle the tag of value 1 and read the `keyoptslen` bytes even if not using their values. Thus, if an option is specified in the future, pre-dating implementations will be able to work with new keys containing the optional values. A `TLVKeyOpt` is a u32 `KeyOptType` followed by a `Vec<u8>` whose interpretation depends on the `KeyOptType` value. `KeyOptType` values from `0x80000000` to `0xFFFFFFFF` are reserved and must not defined by third parties. For interoperability reasons, third parties willing to define new options must contact `MLA` maintainers to register an `OptType` value in the `0x00000000-0x7FFFFFFF` range.
