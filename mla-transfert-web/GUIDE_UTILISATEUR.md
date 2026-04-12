# Guide utilisateur — MLA-Share

MLA-Transfert est un service de transfert de fichiers chiffré de bout en bout.
Vos fichiers sont chiffrés **dans votre navigateur** avant d'être envoyés — le serveur
ne voit jamais leur contenu.

---

## Envoyer des fichiers

### 1. Déposer les fichiers

Glissez-déposez vos fichiers dans la zone d'upload, ou cliquez pour parcourir.
Taille maximale : **100 Mo** par transfert. Plusieurs fichiers peuvent être inclus.

### 2. Choisir un mode de chiffrement

**Mode simple — Mot de passe**

Saisissez un mot de passe d'au moins 12 caractères. Ce mot de passe devra être
communiqué au destinataire par un canal séparé (appel téléphonique, message chiffré…).

**Mode avancé — Clés MLA**

Importez votre clé privée (`.mlapriv`) et la clé publique du destinataire (`.mlapub`).
Ce mode garantit l'authentification de l'expéditeur — aucun secret partagé à transmettre.

> Pour générer une paire de clés, cliquez sur **Générer une paire de clés** en mode avancé.
> Conservez votre clé privée (`.mlapriv`) en lieu sûr. Ne la transmettez jamais.

### 3. Définir la durée d'expiration

Choisissez la durée de disponibilité du transfert :

| Durée | Usage recommandé |
|-------|-----------------|
| 1 heure | Transfert immédiat, sensibilité haute |
| 24 heures | Usage courant |
| 7 jours | Destinataire potentiellement indisponible |

### 4. Envoyer

Cliquez sur **Chiffrer et envoyer**. Le chiffrement s'effectue dans votre navigateur,
puis le fichier chiffré est transféré sur le serveur. Un lien de partage est généré
et copié automatiquement dans votre presse-papier.

Transmettez ce lien au destinataire.

---

## Recevoir des fichiers

### 1. Ouvrir le lien

Cliquez sur le lien reçu de l'expéditeur. La page affiche la taille du transfert
et le temps restant avant expiration.

### 2. Saisir le secret

- **Mode mot de passe** : saisissez le mot de passe communiqué par l'expéditeur.
- **Mode clés MLA** : importez votre clé privée (`.mlapriv`) et la clé publique
  de l'expéditeur (`.mlapub`).

### 3. Déchiffrer

Cliquez sur **Déchiffrer et télécharger**. Le déchiffrement s'effectue dans votre
navigateur. Téléchargez ensuite chaque fichier individuellement.

---

## Sécurité

### Architecture zero-knowledge

Le serveur stocke uniquement le ciphertext MLA — il n'a accès ni au mot de passe,
ni aux clés, ni aux données en clair. Même en cas de compromission du serveur,
vos fichiers restent illisibles.

### Cryptographie utilisée

MLA-Transfert repose sur le format **MLA** développé par l'ANSSI, audité par
Synacktiv en janvier 2026 (note globale : HIGH) :

| Fonction | Algorithme |
|----------|-----------|
| Chiffrement asymétrique | X25519 + ML-KEM 1024 (post-quantique) |
| Signature | Ed25519 + ML-DSA 87 (post-quantique) |
| Chiffrement symétrique | AES-256-GCM |
| KDF (mode mot de passe) | Argon2id (t=3, m=64 MiB, p=4) |

### Bonnes pratiques

- Transmettez le lien de partage et le mot de passe par des **canaux distincts**.
- Préférez une durée d'expiration courte pour les fichiers sensibles.
- En mode avancé, vérifiez que vous importez bien la clé publique de votre
  interlocuteur (et non la vôtre).
- Ne partagez jamais votre clé privée (`.mlapriv`).

---

## Questions fréquentes

**Le lien est expiré — peut-on récupérer les fichiers ?**
Non. Passé la durée d'expiration, les fichiers sont supprimés définitivement.
L'expéditeur doit effectuer un nouveau transfert.

**Le lien est-il suffisant pour accéder aux fichiers ?**
Non. Le lien identifie le transfert mais ne contient aucune clé de déchiffrement.
Sans le mot de passe ou la clé privée, les fichiers restent inaccessibles.

**Peut-on envoyer plusieurs fichiers ?**
Oui. Tous les fichiers sont regroupés dans une même archive chiffrée.

**Quel navigateur est requis ?**
Tout navigateur moderne supportant WebAssembly : Firefox, Chrome, Edge, Safari.

---

*MLA-Share utilise la bibliothèque MLA développée par l'ANSSI.*
*Implémentation Kodetis — [Aide en ligne](/help)*
