# mla-wasm

Bindings WebAssembly de la bibliotheque [MLA](https://github.com/ANSSI-FR/MLA), un format d'archive chiffree post-quantique (ML-KEM 1024 + ChaCha20-Poly1305) certifie par l'ANSSI. Expose une API JS/TS utilisable directement dans le navigateur.

## Build

```bash
wasm-pack build mla-wasm --target web --out-dir pkg
```

Le package genere dans `mla-wasm/pkg/` est reference par le frontend via :

```json
"mla-wasm": "file:../mla-wasm/pkg"
```

## Installation (depuis le workspace)

```bash
npm install
```

Le script `build.sh --wasm-only` effectue le build WASM et copie les fichiers necessaires dans `mla-transfert-web/public/`.

## API

### `generate_keypair() => MlaKeypair`

Genere une nouvelle paire de cles MLA (cle privee + cle publique serialisees en bytes).

```typescript
import init, { generate_keypair } from 'mla-wasm';

await init();

const keypair = generate_keypair();
const privateKey: Uint8Array = keypair.private_key;
const publicKey: Uint8Array  = keypair.public_key;
```

---

### `encrypt_with_password(fileNames, fileContents, password) => Uint8Array`

Chiffre un ou plusieurs fichiers dans une archive MLA en derivant une paire de cles depuis le mot de passe (Argon2id). L'archive resultante ne peut etre dechiffree qu'avec le meme mot de passe.

```typescript
import init, { encrypt_with_password } from 'mla-wasm';

await init();

const fileNames: string[]     = ['document.pdf'];
const fileContents: Uint8Array[] = [new Uint8Array(await file.arrayBuffer())];
const password = 's3cr3t';

const mlaArchive: Uint8Array = encrypt_with_password(fileNames, fileContents, password);
```

---

### `decrypt_with_password(mlaData, password) => [string, Uint8Array][]`

Dechiffre une archive MLA protegee par mot de passe. Retourne un tableau de tuples `[nom_du_fichier, contenu]`.

```typescript
import init, { decrypt_with_password } from 'mla-wasm';

await init();

const entries: [string, Uint8Array][] = decrypt_with_password(mlaArchive, 's3cr3t');

for (const [name, data] of entries) {
  console.log(name, data.byteLength);
}
```

---

### `encrypt_with_keys(fileNames, fileContents, senderPrivKey, receiverPubKey) => Uint8Array`

Chiffre des fichiers avec la cle publique du destinataire et signe avec la cle privee de l'expediteur (chiffrement authentifie). Seul le destinataire peut dechiffrer ; il peut verifier que c'est bien l'expediteur qui a signe.

```typescript
import init, { encrypt_with_keys } from 'mla-wasm';

await init();

const mlaArchive: Uint8Array = encrypt_with_keys(
  fileNames,          // string[]
  fileContents,       // Uint8Array[]
  senderPrivateKey,   // Uint8Array — cle privee de l'expediteur
  receiverPublicKey,  // Uint8Array — cle publique du destinataire
);
```

---

### `decrypt_with_keys(mlaData, receiverPrivKey, senderPubKey) => [string, Uint8Array][]`

Dechiffre une archive MLA avec la cle privee du destinataire et verifie la signature via la cle publique de l'expediteur.

```typescript
import init, { decrypt_with_keys } from 'mla-wasm';

await init();

const entries: [string, Uint8Array][] = decrypt_with_keys(
  mlaArchive,          // Uint8Array — archive chiffree
  receiverPrivateKey,  // Uint8Array — cle privee du destinataire
  senderPublicKey,     // Uint8Array — cle publique de l'expediteur
);
```

---

## Note de securite

Tout le chiffrement et le dechiffrement s'effectuent dans le navigateur (WebAssembly). Le serveur ne recoit que des donnees chiffrees et ne dispose d'aucune cle. Le module ne transmet aucune donnee a l'exterieur.

Les cles MLA sont basees sur ML-KEM 1024 (post-quantique). Note : l'OID ML-KEM 1024 utilise est encore provisoire (suivi : [issue #234](https://github.com/ANSSI-FR/MLA/issues/234)) — les archives produites pourraient necessiter une migration lors de la finalisation de l'OID par le NIST.
