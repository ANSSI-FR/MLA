# Cryptography in MLA

MLA uses cryptographic primitives essentially for the purpose of the `Encrypt` layer.

This document introduces the primitives used, arguments for the choice made and some security considerations.

## High-level overview

### Objectives

The purpose of the `Encrypt` layer is to provide confidentiality and data integrity of the inner layer.

These objectives are obtained using:

- Authenticated encryption
- Asymmetric cryptography, for several recipients

This layer **does not provide signature**.

### General design guidelines

1. The size and the initial computation time used for the encryption needs are not a big issue, if kept reasonable. Indeed, in the author understanding, MLA archives are usually several MB long and the computation time is primarily spent in compression/decompression and encryption/decryption of the data

As a result, some optimization have not been performed -- which help keeping an hopefully auditable and conservative design.

2. Only one encryption method and key type is available, to avoid confusion and potential corner cases errors

3. When possible, use audited code and test vectors

### Main bricks: Encryption

The data is encrypted using AES-256-GCM, an AEAD algorithm.
To offer a *seekable* layer, data is encrypted using chunks of 128KB each, except for the last one. These encrypted chunks are all present with their associated tag. Tags are checked during decryption before returning data to the upper layer.

To prevent truncation attacks, another chunk is added at the end corresponding to the encryption of the ASCII string "FINALBLOCK" with "FINALAAD" as additional authenticated data. Any usage of the archive must check correct decryption (including tag verification) of this last block.

The key, the base nonce and the nonce derivation for each data chunk are computed following HPKE (RFC 9180) [^hpke].
HPKE is parameterized with:

- Mode: "Base" (no PSK, no sender authentication)
- KDF: HKDF-SHA512
- AEAD: AES-256-GCM
- KEM: Multi-Recipient Hybrid KEM, a custom KEM described later in this document

Thus, only one cryptography suite is available for now. If this setting ends up broken by cryptanalysis, we will move users onward to the next MLA version, using appropriate cryptography. Therefore, MLA lacks cryptography agility which is an encouraged property regarding post-quantum cryptography by ANSSI [^frsuggest]. Still, HPKE improves this aspect of MLA [^hpke].

Full details are available below.

Additionally, "key commitment" is included using a method described in [^keycommit] and detailed in [^issuekeycommit].

### Main bricks: Asymmetric encryption

Since the format `v2`, the `Encrypt` layer is using post-quantum cryptography (PQC) through an hybrid approach, to avoid "Harvest now, decrypt later" attacks.

The algorithms used are:

- Curve 25519 for pre-quantum cryptography, using DHKEM (RFC 9180) [^hpke]
- FIPS 203[^fips203] (CRYSTALS Kyber) MLKEM-1024 for post-quantum cryptography

The two keys are mixed together (see below) in a manner keeping the IND-CCA2 properties of the two algorithms.

Sending to multiple recipients is achieved using a two-step process:

1. For each recipient, a per-recipient Hybrid KEM is done, leading to a per-recipient shared secret
1. These per-recipient shared secret are derived through HPKE to obtain a key and a nonce
1. These per-recipient key and nonce are used to decrypt a secret shared by all recipients

This final secret is the one later used as an input to the encryption layer.
The whole process can be viewed as a KEM encapsulation for multiple recipients.

## Details

The following sections describe the whole process for data encryption and seed derivation.
They are meant to ease the understanding of the code and MLA format re-implementation. 

The interested reader could also look at the Rust implementation in this repository for more details.
The implementation also includes tests (including some test vectors) and comments.

### Asymmetric encryption - Per-recipient KEM

#### Notations

- $pk_{ecc}^i$, $sk_{ecc}^i$, $pk_{mlkem}^i$ and $sk_{mlkem}^i$: respectively the curve 25519 public key and secret key, and the MLKEM-1024 (FIPS 203 [^fips203]) encapsulating key and decapsulating key
- $\textrm{DHKEM.Encapsulate}$ and $\textrm{DHKEM.Decapsulate}$: key encapsulation methods on the curve 25519, as defined in RFC 9180, section 4 [^hpke]
- $\textrm{MLKEM.Encapsulate}$ and $\textrm{MLKEM.Decapsulate}$: key encapsulation methods on MLKEM-1024, as defined in FIPS 203 [^fips203]
- $ss_{recipients}$: a 32-bytes secret, produced by a cryptographic RNG. Informally, this is the secret shared among recipients, encapsulated separately for each recipient
- $\textrm{KeySchedule}_{recipient}$: `KeySchedule` function from RFC 9180 [^hpke], instanciated with:
    - Mode: "Base"
    - KDF: HKDF-SHA-512
    - AEAD: AES-256-GCM
    - KEM: a custom KEM ID, numbered 0x1120
- $\textrm{Encrypt}_{AES\ 256\ GCM}$: AES-256-GCM encryption, returning the encrypted data concatened with the associated tag
- $\textrm{Decrypt}_{AES\ 256\ GCM}$ AES-256-GCM decryption, returning the decrypted data after verifying the tag
- $\textrm{Serialize}$ and $\textrm{Deserialize}$: respectively produce a byte string encoding the data in argument, and produce the data from the byte string in argument

#### Process

To encrypt to a target recipient $i$, knowing $pk_{ecc}^i$ and $pk_{mlkem}^i$:

1. Compute shared secrets and ciphertexts for both KEM:

```math
\begin{align}
(ss_{ecc}^i, ct_{ecc}^i) &= \textrm{DHKEM.Encapsulate}(pk_{ecc}^i) \\
(ss_{mlkem}^i, ct_{mlkem}^i) &= \textrm{MLKEM.Encapsulate}(pk_{mlkem}^i)
\end{align}
```

2. Combine the shared secrets (implemented in `mla::crypto::hybrid::combine`):

```python
def combine(ss1, ss2, ct1, ct2):
    uniformly_random_ss1 = HKDF-SHA512-Extract(
        salt=0,
        ikm=ss1
    )
    key = HKDF(
        salt=uniformly_random_ss1,
        ikm=ss2,
        info=ct1 . ct2
    )
    return key
```

```math
ss_{recipient}^i = \textrm{combine}(ss_{ecc}^i, ss_{mlkem}^i, ct_{ecc}^i, ct_{mlkem}^i)
```

3. Wrap the recipients' shared secret:

```math
\begin{align}
(key^i, nonce^i) &= \textrm{KeySchedule}_{recipient}(
        shared\_secret=ss_{recipient}^i,
    \textrm{info}=\mathtt{"MLA\ Recipient"}
)\\
ct_{wrap}^i &= \textrm{Encrypt}_{AES\ 256\ GCM}(\textrm{key}=key^i, \textrm{nonce}=nonce^i, \textrm{data}=ss_{recipients})\\
ct_{recipient}^i &= \textrm{Serialize}(ct_{wrap}^i, ct_{ecc}^i, ct_{mlkem}^i)
\end{align}
```

Informally, this process can be viewed as a per-recipient KEM taking a shared secret $ss_{recipients}$, the recipient public key (made of the elliptic curve and the PQC public keys) and returning a ciphertext $ct_{recipient}^i$.

----

To obtain the shared secret from $ct_{recipient}^i$ for a recipient $i$ knowing $sk_{ecc}^i$ and $sk_{mlkem}^i$:

1. Compute the recipient's shared secret:

```math
\begin{align}
(ct_{wrap}^i, ct_{ecc}^i, ct_{mlkem}^i) &= \textrm{Deserialize}(ct_{recipient}^i)\\
ss_{ecc}^i &= \textrm{DHKEM.Decapsulate}(sk_{ecc}^i, ct_{ecc}^i) \\
ss_{mlkem}^i &= \textrm{MLKEM.Decapsulate}(sk_{mlkem}^i, ct_{mlkem}^i)\\
ss_{recipient}^i &= \textrm{combine}(ss_{ecc}^i, ss_{mlkem}^i, ct_{ecc}^i, ct_{mlkem}^i)
\end{align}
```

2. Try to decrypt the secret shared among recipients:

```math
\begin{align}
(key^i, nonce^i) &= \textrm{KeySchedule}_{recipient}(
        shared\_secret=ss_{recipient}^i,
    \textrm{info}=\mathtt{"MLA\ Recipient"}
)\\
ss_{recipients} &= \textrm{Decrypt}_{AES\ 256\ GCM}(\textrm{key}=key^i, \textrm{nonce}=nonce^i, \textrm{data}=ct_{wrap}^i)
\end{align}
```

If the decryption is a success, returns $ss_{recipients}$. Otherwise, returns an error.

#### Arguments

- Using HPKE (RFC 9180 [^hpke]) for both elliptic curve encryption (DHKEM) and post-quantum encryption (MLKEM) offers several benefits[^issuehpke]:
    - Easier re-implementation of the format MLA, thanks to the availability of HPKE in cryptographic libraries
    - An existing formal analysis [^hpkeanalysis]
    - Easier code and security auditing, thanks to the use of known bricks
    - Availability of test vectors in the RFC, making the implementation more reliable
    - If signature is added to MLA in a future version, it could also be integrated using HPKE
- To the knowledge of the author, no HPKE algorithm has been standardized for quantum hybridation, hence the custom algorithm
- FIPS 203 is used as, at the time of writing:
    - It is the only KEM algorithm standardized by the NIST [^nist]
    - It is in line with the French suggestions [^frsuggest] for PQ cryptography
- The MLKEM-1024 mode is used for stronger security, and to limit consequence of future advances [^mlkemcon1][^mlkemcon2]. This is also the choice of other industry standards [^signal][^imessage]
- The shared secret from the two-KEM is produced using a "Nested Dual-PRF Combiner", proved in [^dualnest] (3.3):
    - The use of concatenation scheme **including ciphertexts** keeps IND-CCA2 if one of the two underlying scheme is IND-CCA2, as proved in [^combinearg1] and explained in [^combinearg4]
    - TLS [^combinearg2] uses a similar scheme, and IKE [^combinearg3] also uses a concatenation scheme
    - This kind of scheme follows ANSSI recommendations [^frsuggest]
    - HKDF can be considered as a Dual-PRF if both inputs are uniformly random [^combinearg7]. In MLA, the `combine` method is called with a shared secret from ML-KEM, and the resulting ECC key derivation -- both are uniformly random
    - To avoid potential mistake in the future, or a mis-reuse of this method, the "Nested Dual-PRF Combiner" is used instead of the "Dual-PRF Combiner" (also from [^dualnest]). Indeed, this combiner force the "salt" part of HKDF to be uniformly random using an additional PRF use, ensuring the following HKDF is indeed a Dual-PRF

### Asymmetric encryption - Multi-Recipient Hybrid KEM

#### Intuition

KEM, such as the one described above, returns a fresh and distinct secret for each recipient.

To obtain a "meta-KEM", working for multi-recipient, the strategy is the use of per-recipient KEM to encrypt a common secret.

This whole process can then be viewed as a KEM for multi-recipient, taking in input a list of public keys and returning a shared secret and a ciphertext made of the concatenation of each per-recipient ciphertext.

To avoid marking which per-recipient ciphertext correspond to which recipient public key, the decapsulation process "brute-force" each ciphertext for a given decapsulation key. If the decryption works (with the associated tag), the shared secret is returned.

Key commitment, to avoid rather unlikely mismatch, is further ensured inside the `Encrypt` layer (see below).

#### Process

The "Per-recipient KEM" process described above is noted:
- $\mathrm{PerRecipientKEM.Encapsulate}$, taking a couple of public key ($pk_{ecc}^i$ and $pk_{mlkem}^i$), a shared secret $ss_{recipients}$ and returning a recipient ciphertext $ct_{recipient}^i$
- $\mathrm{PerRecipientKEM.Decapsulate}$, taking a couple of private key ($sk_{ecc}^i$ and $sk_{mlkem}^i$), a ciphertext $ct_{recipients}$ and returning either a shared secret $ss_{recipients}$ if the recipient $i$ is a legitimate recipient (if the AEAD decryption works), or an error otherwise

$\mathrm{CSPRNG(n)}$ is a cryptographically secured RNG producing a n-bytes secret.

To encapsulate to a list of recipient $[(pk_{ecc}^0, pk_{mlkem}^0), ..., (pk_{ecc}^{n-1}, pk_{mlkem}^{n-1})]$:

```math
\begin{align*}
\mathtt{def\ } & \mathrm{HybridKEM.Encapsulate}([(pk_{ecc}^0, pk_{mlkem}^0), ..., (pk_{ecc}^{n-1}, pk_{mlkem}^{n-1})])\\
& ss_{recipients} = \mathrm{CSPRNG(32)}\\
& ct_{recipient}^0 = \mathrm{PerRecipientKEM}((pk_{ecc}^0,pk_{mlkem}^0),ss_{recipients})\\
& \dots\\
& ct_{recipient}^{n-1} = \mathrm{PerRecipientKEM}((pk_{ecc}^{n-1},pk_{mlkem}^{n-1}),ss_{recipients})\\
& ct_{recipients} = \mathrm{Serialize}(ct_{recipient}^0, \dots, ct_{recipient}^{n-1})\\
& \mathtt{return}\ ss_{recipients},\ ct_{recipients}
\end{align*}
```
----

To decapsulate from a ciphertext $ct_{recipients}$, knowing a recipient private key $(sk_{ecc}^i,sk_{mlkem}^i)$:

$\mathtt{def\ } \mathrm{HybridKEM.Decapsulate}((sk_{ecc}^i,sk_{mlkem}^i), ct_{recipients})$\
$\hspace{1cm}\mathtt{foreach\ } ct_k \mathtt{\ in\ } \mathrm{Deserialize}(ct_{recipients})$\
$\hspace{2cm}\mathtt{try:}$\
$\hspace{3cm}ss_{recipients} = \mathrm{PerRecipientKEM.Decapsulate}((sk_{ecc}^i,sk_{mlkem}^i), ct_k)$\
$\hspace{2cm}\mathtt{success:}$\
$\hspace{3cm}\mathtt{return}\ ss_{recipients}$\
$\hspace{2cm}\mathtt{error:}$\
$\hspace{3cm}\mathtt{continue}$\
$\hspace{1cm}\mathtt{throw\ KeyNotFoundError}$

#### Arguments

- The shared secret is cryptographically generated, so it can later be used as a shared secret in HPKE encryption
- This secret is unique per archive, as it is generated on archive creation. Even "converting" or "repairing" an archive in `mlar` CLI will force a newly fresh secret. It is a new secret as there is no edit feature implemented, even if it is doable. Hence, a new random symetric key is used to encrypt its content while "converting" or "repairing" an archive. 
- Even if the AEAD decryption worked for an non legitimate recipient, for instance following an intentional manipulation, the shared secret obtained will later be checked using Key commitment before decrypting actual data (see below)
- Optimization would have been possible here, such as sharing a common ephemeral key for the DHKEM. But the size gain is not worth enough regarding the ciphertext size of MLKEM and would move the implementation away from the DHKEM in RFC 9180

### Encryption

#### Notation

The "Multi-Recipient Hybrid KEM" process described above is noted:
- $\mathrm{MultiRecipientHybridKEM.Encapsulate}$, taking a list of public keys $[(pk_{ecc}^0, pk_{mlkem}^0), ..., (pk_{ecc}^{n-1}, pk_{mlkem}^{n-1})]$ and returing a shared secret $ss_{recipients}$ and a ciphertext $ct_{recipients}$
- $\mathrm{MultiRecipientHybridKEM.Decapsulate}$, taking a couple of private keys ($sk_{ecc}^i$ and $sk_{mlkem}^i$), a ciphertext $ct_{recipients}$ and returning either a shared secret $ss_{recipients}$ if the recipient $i$ is a legitimate recipient (if the AEAD decryption works), or an error otherwise

`KeyCommitmentChain` is defined as the array of 64-bytes: `-KEY COMMITMENT--KEY COMMITMENT--KEY COMMITMENT--KEY COMMITMENT-`.

$\textrm{KeySchedule}_{hybrid}$: `KeySchedule` function from RFC 9180 [^hpke], instanciated with:

- Mode: "Base"
- KDF: HKDF-SHA-512
- AEAD: AES-256-GCM
- KEM: a custom KEM ID, numbered 0x1020

$\mathrm{ComputeNonce}$: function from RFC 9180 [^hpke].

#### Process

To encrypt n-bytes `data` to a list of public keys $[(pk_{ecc}^0, pk_{mlkem}^0), ..., (pk_{ecc}^{n-1}, pk_{mlkem}^{n-1})]$:

1. Compute a shared secret and the corresponding ciphertext:

```math
ss_{recipients},\ ct_{recipients} = \mathrm{MultiRecipientHybridKEM.Encapsulate}([(pk_{ecc}^0, pk_{mlkem}^0), ..., (pk_{ecc}^{n-1}, pk_{mlkem}^{n-1})])
```

2. Derive the key and base nonce using HPKE

```math
(key, base\_nonce) = \textrm{KeySchedule}_{hybrid}(
        shared\_secret=ss_{recipients},
    \textrm{info}=\mathtt{"MLA\ Encrypt\ Layer"}
)
```

3. Ensure key-commitment

```math
\begin{align*}
keycommit& = \textrm{Encrypt}_{AES\ 256\ GCM}(\\
    &\textrm{key}=key,\\
    &\textrm{nonce}=\mathrm{ComputeNonce}(base\_nonce, 0),\\
    &\textrm{data}=\textrm{KeyCommitmentChain}\\
)&
\end{align*}
```

4. For each 128KB $chunk_j$ of data:

```math
\begin{align*}
enc_j& = \textrm{Encrypt}_{AES\ 256\ GCM}(\\
    &\textrm{key}=key,\\
    &\textrm{nonce}=\mathrm{ComputeNonce}(base\_nonce, j + 1),\\
    &\textrm{data}=chunk_j\\
)&
\end{align*}
```

Note: $j$ starts at 0. $j+1$ is used because the sequence numbered 0 has already been used by the Key commitment.

5. When the layer is finalized, the last chunk of data (with a length lower than or equals to 128KB) is encrypted the same way

6. Finally, a final chunk with sequence number $n+1$ (where $n$ is the number of data chunks) and special content and additional authenticated data is appended:

```math
\begin{align*}
final\_chunk& = \textrm{Encrypt}_{AES\ 256\ GCM}(\\
    &\textrm{key}=key,\\
    &\textrm{nonce}=\mathrm{ComputeNonce}(base\_nonce, n + 1),\\
    &\textrm{data}="FINALBLOCK"\\
    &\textrm{aad}="FINALAAD"\\
)&
\end{align*}
```

The resulting layer is composed of:

- header: $ct_{recipients}$
- data: $keycommit \ .\ enc_0\ . \dots\ enc_n \ .$ $`final\_chunk`$

Special care must be taken not to reuse a sequence number in implementations as this would be catastrophic given GCM properties. For $n$ chunks of data:
* sequence 0: key commitment
* sequence 1 to $n$: data
* sequence $n+1$: $`final\_chunk`$ with only the 10 bytes "FINALBLOCK" as content

----

To decrypt the data at position $pos$:

1. Once for the whole session, get the cryptographic materials

```math
\begin{align}
ss_{recipients} &= \mathrm{MultiRecipientHybridKEM.Decapsulate}((sk_{ecc}^i, sk_{mlkem}^i), ct_{recipients})\\
(key, base\_nonce) &= \textrm{KeySchedule}_{hybrid}(
        shared\_secret=ss_{recipients},
    \textrm{info}=\mathtt{"MLA\ Encrypt\ Layer"}
)
\end{align}
```

2. Once for the whole session, check the key commitment

```math
\begin{align*}
commit& = \textrm{Decrypt}_{AES\ 256\ GCM}(\\
    &\textrm{key}=key,\\
    &\textrm{nonce}=\mathrm{ComputeNonce}(base\_nonce, 0),\\
    &\textrm{data}=keycommit\\
)&
\end{align*}
```

```math
\mathtt{assert\ }commit = \textrm{KeyCommitmentChain}
```

3. Retrieve the encrypted chunk of data

```math
\begin{align}
start &= pos - \mathtt{sizeof}(keycommit)\\
j &= pos \div 128KiB\\
\end{align}
```

Where $\div$ is the Euclidian division.

Then:
```math
\begin{align*}
chunk_j& = \textrm{Decrypt}_{AES\ 256\ GCM}(\\
    &\textrm{key}=key,\\
    &\textrm{nonce}=\mathrm{ComputeNonce}(base\_nonce, j + 1),\\
    &\textrm{data}=enc_j\\
)&
\end{align*}
```

#### Arguments

- Key commitment is always checked before returning clear-text data to the caller
- AEAD tag of a chunk is always checked before returning the corresponding clear-text data to the caller
- Arguments for HPKE use are very similar to the ones mentioned above. In particular, this is a standardized approach with existing analysis
- As there is two kind of custom KEM used ("Per-recipient KEM" and "Hybrid KEM"), two distinct KEM ID are used. In addition, two distinct MLA specific `info` are used to bind this derivation to MLA
- As described in [^keycommit] and [^keycommit2], AES in GCM mode does not ensure "key commitment". This property is added in the layer using the "padding fix" scheme from [^keycommit] with the recommended 512-bits size for a 256-bits security
- Key commitment is mainly used to ensure that two recipients will decrypt to the same plaintext if given the same ciphertext, i.e. an attacker modifying the header of an archive cannot provide two distinct plaintext to two distinct recipient
- AES-GCM is used as an industry standard AEAD
    - the base nonce, and therefore each nonce used, are unique per archive because they are generated from the archive-specific shared secret, limiting the nonce-reuse risk to standard acceptability [^hpke]
    - no more than $2^{64}$ chunks will be produced, as the sequence's type used in MLA implementation is a `u64` checked for overflow. As this is a widely accepted limit of AES-GCM, this value is also within the range provided by [^hpke]
    - the tag size is 128-bits (standard one), avoiding attacks described in [^weaknessgcm]
    - 128KiB is lower than the maximum plaintext length for a single message in AES-GCM (64 GiB)[^weaknessgcm]

### Seed derivation

The asymmetric encryption in MLA, particularly the KEMs, provides deterministic API.

These API are usually fed with cryptographically generated data, except for the regression test and the "seed derivation" feature in `mlar` CLI.

This feature is meant to provide a way for client to implement:

- A derivation tree
- Keep the root secret in a safe place, and be able to find back the derived secrets

The derivation scheme is based on the same ideas than `mla::crypto::hybrid::combine`:

1. A dual-PRF (HKDF-Extract with a uniform random salt [^combinearg7]) to extract entropy from the private key
2. HKDF-Expand to derive along the given path component

From a private key ($sk_{ecc}^i$ and $sk_{mlkem}^i$), the secret is derived from the path component $pc$ through:

```math
\begin{align}
ecc\_rnd &= \mathrm{HKDF.Extract_{SHA512}}(\mathrm{salt}=0, \mathrm{ikm}=sk_{ecc}^i)\\
seed &= \mathrm{HKDF_{SHA512}}(
    \mathrm{salt}=ecc\_rnd,
    \mathrm{ikm}=sk_{mlkem}^i,
    \mathrm{info}=\mathtt{"PATH\ DERIVATION"}\ .\ pc
)
\end{align}
```

To derive a key using a `seed`, a `ChaChaRng` is used.
If a `seed` is provided, the `ChaChaRng` is seeded with the first 32-bytes of $\mathrm{SHA512}(seed)$. Otherwise, the `ChaChaRng::from_entropy` is used, wrapping OS Cryptographic RNG sources.

The CSRNG is then provided to MLA deterministic APIs.

## Implementation specificities

### External dependencies

Some of the external cryptographic libraries have been reviewed:

- RustCrypto AES-GCM, reviewed by NCC Group [^reviewncc]
- Dalek cryptography library, reviewed by Quarkslab [^reviewqb]
- `rust-hpke` library, reviewed in version 0.8 by CloudFlare [^reviewcloudflare]

In addition to the review, `rust-hpke` is mainly based on `RustCrypto`, avoiding the need for additional newer dependencies.

The MLKEM implementation used is the one of `RustCrypto`, as MLA already depends on this project and the code quality and auditability are, in the author understanding, rather good.

The generation uses `OsRng` from crate `rand`, that uses `getrandom()` from crate `getrandom`. `getrandom` provides implementations for many systems, listed [here](https://docs.rs/getrandom/0.1.14/getrandom/).
On Linux it uses the `getrandom()` syscall and falls back on `/dev/urandom`.
On Windows it uses the `RtlGenRandom` API (available since Windows XP/Windows Server 2003).

In order to be "better safe than sorry", a `ChaChaRng` is seeded from the bytes generated by `OsRng` in order to build a CSPRNG(Cryptographically Secure PseudoRandom Number Generator). This `ChaChaRng` provides the actual bytes used in keys and nonces generations.

The authors decided to use elliptic curve over RSA, because:
* No ready-for-production Rust-based libraries have been found at the date of writing
* A security-audited Rust library already exists for Curve25519
* Curve25519 is widely used and [respects several criteria](https://safecurves.cr.yp.to/)
* Common arguments, such as the ones of [Trail of bits](https://blog.trailofbits.com/2019/07/08/fuck-rsa/)

AES-GCM is used because it is one of the most commonly used AEAD algorithms and using one avoids a whole class of attacks. In addition, it lets us rely on hardware acceleration (like AES-NI) to keep reasonable performance.

### AES-GCM re-implementation

While the AES and GHash bricks come from RustCrypto, the GCM mode for AES-256 has been re-implemented in MLA.

Indeed, the repair mode must be able to only partially decrypt a data chunk, and decide whether the associated tag must be verified or not. This API is not provided by the RustCrypto project, for very understandable reasons.

To ensure the implementation follows the standard, it is tested against AES-256-GCM test vectors in MLA regression tests.

### HPKE Key Schedule re-implementation

For several reasons described in the code, but mainly due to the availability of API, the possibility to add custom KEM ID and the relative few lines needed for re-implementation, the $\mathrm{KeySchedule}$ method has been re-implemented in MLA.

It still use some bricks from `rust-hpke`, as the KDF, $\mathrm{LabeledExtract}$ and $\mathrm{LabeledExpand}$. It is tested against RFC 9180 [^hpke] test vectors in MLA regression tests.

### MLKEM implementation without a review

Thanks to the hybrid approach, a flawed implementation of MLKEM would have limited consequences. It satisfies ANSSI guidelines for the transition first phase to PQC hybridization [^frsuggest]. For this reason, MLA is eligible for a security visa evaluation.

For now, it is therefore accepted by the author (as a trade-off) to use a MLKEM implementation without existing review to bring as soon as possible a reasonable protection against "Harvest now, decrypt later" attacks.

If a reviewed implementation with acceptable dependency emerges in the future, it can be easily swapped in MLA. Thus, MLA would also satisfy the requirements to get a security visa evaluation in the second and third phases of these guidelines by including its PQC implementation.

## Security consideration

### Absence of signature

As there is no signature for now in MLA, an attacker knowing the recipient public key can always create a custom archive with arbitrary data.

For this reason, several known attacks are considered acceptable, such as:

- The bit indicating if the `Encrypt` layer is present is not protected in integrity

An attacker can remove it, making the reader treating the archive as if encryption was absent. *The reader is responsible of checking for encryption bit if it was expected in the first place*.

For instance, the `mlar` CLI will refuse to open an archive without the `Encrypt` bit unless `--accept-unencrypted` is provided on the command line.

- An attacker with the ability to modify a real archive in transit can replace what the reader will be able to read with arbitrary data

To perform this attack, the attacker will have to either remove the `Encrypt` bit or modify the key used for decryption with one she has.
The remaining encrypted data will then act as random values.

Still, the attacker could expect to gain enough privilege, like arbitrary code execution in the process, during the archive read. One can then try to reuse the provided key to decrypt, then act on the real data.

Limiting this attack is beyond the scope of this document. It mainly involves the security features of Rust, reviewed implementation, testing & fuzzing, zeroizing secrets when possible [^issuezeroize], etc.

- An attacker can truncate an archive and hope for repair

This attack is based on a trade-off: should the `SafeReader` try to get as many bytes as possible, or should it return only data that have been authenticated?

The choice has been made to report the decision to the user of the library[^issueallowunauth].

### Other properties

- Plaintext length

The `Encrypt` layer does not hide the plaintext length.

Usually, this layer is used with the `Compress` layer. If an attacker knows the original file size, he might learn information about the original data entropy.

- Hidden recipient list

Only the owner of a recipient's private key can determine that they are a recipient of the archive. In other words, while the recipient list remains private, the total number of recipients is still visible. 

This is an intentional privacy feature.

[^keycommit]: ["How to Abuse and Fix Authenticated Encryption Without Key Commitment", Usenix'22](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini)
[^issuekeycommit]: https://github.com/ANSSI-FR/MLA/issues/206
[^hpke]: [Hybrid Public Key Encryption, RFC 9180](https://datatracker.ietf.org/doc/rfc9180/)
[^fips203]: [FIPS 203 - MLKEM Standard](https://csrc.nist.gov/pubs/fips/203/ipd)
[^issuehpke]: https://github.com/ANSSI-FR/MLA/issues/211
[^hpkeanalysis]: https://eprint.iacr.org/2020/1499.pdf
[^issuepqc]: https://github.com/ANSSI-FR/MLA/issues/195
[^frsuggest]: https://cyber.gouv.fr/en/publications/follow-position-paper-post-quantum-cryptography
[^nist]: https://csrc.nist.gov/News/2022/pqc-candidates-to-be-standardized-and-round-4
[^mlkemcon1]: https://blog.cr.yp.to/20231003-countcorrectly.html
[^mlkemcon2]: https://kyberslash.cr.yp.to/
[^signal]: https://signal.org/docs/specifications/pqxdh/
[^imessage]: https://security.apple.com/blog/imessage-pq3/
[^dualnest]: https://eprint.iacr.org/2018/903.pdf
[^combinearg1]: https://eprint.iacr.org/2018/024
[^combinearg2]: https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
[^combinearg3]: https://datatracker.ietf.org/doc/html/rfc9370
[^combinearg4]: https://eprint.iacr.org/2024/039 
[^combinearg7]: https://eprint.iacr.org/2023/861
[^keycommit2]: https://eprint.iacr.org/2019/016.pdf
[^weaknessgcm]: ["Authentication weaknesses in GCM"](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf)
[^reviewncc]: https://research.nccgroup.com/wp-content/uploads/2020/02/NCC_Group_MobileCoin_RustCrypto_AESGCM_ChaCha20Poly1305_Implementation_Review_2020-02-12_v1.0.pdf
[^reviewqb]: https://blog.quarkslab.com/security-audit-of-dalek-libraries.html
[^reviewcloudflare]: https://blog.cloudflare.com/using-hpke-to-encrypt-request-payloads/
[^issuezeroize]: https://github.com/ANSSI-FR/MLA/issues/46
[^issueallowunauth]: https://github.com/ANSSI-FR/MLA/issues/167
