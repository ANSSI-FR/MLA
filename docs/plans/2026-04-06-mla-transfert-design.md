# MLA-Transfert -- Design Spec

## Vision

Service web de transfert de fichiers securise utilisant le chiffrement MLA (post-quantique) cote client. Zero-knowledge : le serveur ne voit jamais les fichiers en clair ni les cles.

Cible initiale : communaute securite / CLUSIR. Cible future : grand public.

## Architecture

```
+---------------------------------------------+
|              Navigateur (Client)             |
|                                             |
|  +----------+    +-----------------------+  |
|  |  UI Web   |<-->|  MLA WASM Module     |  |
|  | (Astro/   |    |  - keygen            |  |
|  |  React)   |    |  - encrypt/archive   |  |
|  |           |    |  - decrypt/extract   |  |
|  +-----+-----+    +-----------------------+  |
|        |                                     |
|        | fichiers chiffres uniquement        |
+--------+-------------------------------------+
         |
    +----+----+
    | Mode ?  |
    +---------+
    |         |
    v         v
+--------+  +----------+
| Relais |  |   P2P    |
| Server |  | (WebRTC) |
| (Axum) |  |          |
+--------+  +----------+
```

### 3 composants

1. **MLA WASM** : lib `mla` compilee en WebAssembly. Chiffrement, dechiffrement, keygen -- tout cote client. Le serveur ne voit jamais le clair.

2. **UI Web (Astro + React TSX + TailwindCSS)** : interface user-friendly avec deux modes :
   - Mode simple : mot de passe -> derivation de cle -> chiffrement
   - Mode avance : import de cles MLA (.mlapub/.mlapriv)

3. **Backend (Axum, Rust)** :
   - Mode relais : stocke temporairement les fichiers chiffres, genere un lien de partage, purge apres expiration
   - Mode P2P : serveur de signaling WebRTC, les fichiers transitent directement entre navigateurs

## Workflows

### Mode Simple (mot de passe)

**Envoi :**
1. Drag & drop des fichiers
2. Saisie d'un mot de passe
3. Choix de l'expiration (1h, 24h, 7j)
4. Choix du mode de transfert (relais ou P2P)
5. WASM derive une cle MLA du mot de passe (Argon2) -> chiffre -> archive .mla
6. Upload du .mla chiffre au serveur (ou attente du peer en P2P)
7. Lien de partage genere

**Reception :**
1. Ouverture du lien
2. Saisie du mot de passe
3. WASM derive la cle -> dechiffre -> extrait
4. Telechargement des fichiers en clair

### Mode Avance (cles MLA)

**Envoi :**
1. Drag & drop des fichiers
2. Import de la cle privee (`.mlapriv`) pour signer
3. Import de la cle publique du destinataire (`.mlapub`) pour chiffrer
4. Choix expiration + mode de transfert
5. WASM chiffre et signe -> archive .mla
6. Lien de partage genere

**Reception :**
1. Ouverture du lien
2. Import de la cle privee (`.mlapriv`) pour dechiffrer
3. Import de la cle publique de l'expediteur (`.mlapub`) pour verifier la signature
4. WASM dechiffre et verifie -> extrait

### Keygen integre

- Bouton "Generer mes cles" dans le mode avance
- WASM genere la paire de cles MLA
- L'utilisateur telecharge ses `.mlapriv` et `.mlapub`
- Les cles ne quittent jamais le navigateur

## Stack technique

### Frontend
- Astro + React (TSX)
- TailwindCSS
- wasm-bindgen / wasm-pack pour les bindings MLA WASM
- WebRTC API pour le mode P2P

### Backend
- Axum (Rust) -- API REST :
  - `POST /upload` : recoit le .mla chiffre, retourne un ID/lien
  - `GET /download/:id` : sert le .mla chiffre
  - `GET /signal/:room` : WebSocket pour le signaling WebRTC
- Stockage temporaire : filesystem local avec cron de purge selon l'expiration
- Pas de base de donnees -- index en memoire (ou SQLite si persistance au redemarrage necessaire)

### Module WASM
- Crate Rust dedie (`mla-wasm`) dans le workspace
- Expose via `wasm-bindgen` :
  - `generate_keypair()`
  - `encrypt_with_password(files, password) -> mla_blob`
  - `encrypt_with_keys(files, sender_priv, receiver_pub) -> mla_blob`
  - `decrypt_with_password(mla_blob, password) -> files`
  - `decrypt_with_keys(mla_blob, receiver_priv, sender_pub) -> files`
- Derivation mot de passe -> cle MLA via Argon2 (cote WASM)

### Structure du repo

```
MLA-Transfert/
├── mla/                  # lib MLA existante (inchangee)
├── mlar/                 # CLI existant (inchange)
├── mla-wasm/             # nouveau : bindings WASM
├── mla-transfert-server/ # nouveau : backend Axum
├── mla-transfert-web/    # nouveau : frontend Astro+React
└── ...
```

## Securite & limites

### Zero-knowledge garanti
- Le serveur ne manipule que des blobs chiffres
- Pas de logs du contenu, pas de cles cote serveur
- En mode P2P, le serveur ne voit meme pas le fichier transiter

### Limites de fichiers
- Taille max : 2 Go par transfert (contrainte WASM en memoire navigateur)
- Streaming par chunks dans le WASM pour les gros fichiers

### Expiration
- Fichiers chiffres purges cote serveur apres l'expiration choisie (1h, 24h, 7j)
- Lien mort apres expiration, pas de recuperation possible

### Pas de comptes utilisateurs
- Aucune inscription, aucun login
- App stateless cote user

### Risques identifies
- **Mode mot de passe** : securite dependante de la qualite du mot de passe. Indicateur de force cote UI.
- **WASM en navigateur** : code dans un environnement non totalement controle (extensions, devtools). Compromis du zero-install web vs client lourd. Mitigation prevue en V2 avec client Tauri.

## Exemples CLI (mlar)

### Generer les cles

```bash
mlar keygen sender
mlar keygen receiver
```

### Creer une archive chiffree

```bash
mlar create -o nxo-mlar.mla -k sender.mlapriv -p receiver.mlapub /Users/tipunch/Gitlab/nxo
```

- `-o` : fichier archive de sortie
- `-k` : cle privee de l'expediteur (pour signer)
- `-p` : cle publique du destinataire (pour chiffrer)
- dernier argument : dossier ou fichiers a archiver

### Extraire une archive

```bash
mlar extract -k receiver.mlapriv -p sender.mlapub -i nxo-mlar.mla -o test
```

- `-k` : cle privee du destinataire (pour dechiffrer)
- `-p` : cle publique de l'expediteur (pour verifier la signature)
- `-i` : archive en entree
- `-o` : dossier de sortie

## Roadmap

- **V1** : App web (ce design)
- **V2** : Client lourd Tauri (meme UI, crypto native Rust, securite renforcee)
