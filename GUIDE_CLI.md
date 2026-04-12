# Guide CLI — MLA-Share

Guide synthétique pour utiliser `mlar` (CLI ANSSI) et transférer des fichiers via MLA-Share depuis la ligne de commande.

---

## Installation

```bash
# Via Cargo (recommandé)
cargo install mlar

# Vérifier l'installation
mlar --version
```

---

## Gestion des clés

```bash
# Générer une paire de clés (produit sender.mlapriv + sender.mlapub)
mlar keygen sender
mlar keygen receiver

# Partager uniquement la clé publique avec votre interlocuteur
# Ne transmettez JAMAIS votre .mlapriv
```

> Les fichiers `.mlapriv` et `.mlapriv` sont ignorés par `.gitignore` — ne les committez pas.

---

## Chiffrer une archive

```bash
# Chiffrer un fichier pour un destinataire
mlar create \
  -k sender.mlapriv \
  -p receiver.mlapub \
  -o archive.mla \
  /chemin/vers/fichier.tar.gz

# Chiffrer plusieurs fichiers
mlar create \
  -k sender.mlapriv \
  -p receiver.mlapub \
  -o archive.mla \
  fichier1.log fichier2.db config.yaml

# Chiffrer sans signature (déconseillé pour envoi à une autorité)
mlar create --unsigned \
  -p receiver.mlapub \
  -o archive.mla \
  fichier.tar

# Plusieurs destinataires
mlar create \
  -k sender.mlapriv \
  -p receiver1.mlapub -p receiver2.mlapub \
  -o archive.mla \
  fichier.tar.gz

# Depuis un pipe (backup, image VM…)
tar czf - /var/backups/ | mlar create \
  -k sender.mlapriv \
  -p receiver.mlapub \
  -o backup_$(date +%Y%m%d).mla \
  --stdin-data
```

---

## Déchiffrer une archive

```bash
# Lister le contenu sans extraire
mlar list \
  -k receiver.mlapriv \
  -p sender.mlapub \
  -i archive.mla

# Extraire dans un dossier
mlar extract \
  -k receiver.mlapriv \
  -p sender.mlapub \
  -i archive.mla \
  -o ./extracted/

# Afficher un fichier spécifique directement
mlar cat \
  -k receiver.mlapriv \
  -p sender.mlapub \
  -i archive.mla \
  chemin/dans/archive.txt
```

---

## Uploader vers MLA-Share

> Le client upload natif est en cours de développement (voir [todo.md — Scénario A](todo.md)).
> En attendant, vous pouvez uploader l'archive `.mla` via `curl` ou l'interface web.

```bash
# Upload via curl vers l'instance MLA-Share
curl -X POST https://mla.kds.tf/api/upload \
  -F "file=@archive.mla" \
  -F "expires_hours=24" \
  | jq -r '"Lien : https://mla.kds.tf/receive/" + .id'

# Upload avec expiration 1h (fichier sensible)
curl -X POST https://mla.kds.tf/api/upload \
  -F "file=@vm_compromise.mla" \
  -F "expires_hours=1" \
  | jq .
```

Le destinataire reçoit le lien et déchiffre depuis le navigateur — **aucune installation requise de son côté**.

---

## Cas d'usage — Transfert d'une VM compromise

```bash
# 1. Créer l'archive chiffrée pour l'autorité
mlar create \
  -k analyste.mlapriv \
  -p autorite.mlapub \
  -o vm_compromise_$(date +%Y%m%d_%H%M).mla \
  dump_memoire.raw disk_image.dd

# 2. Uploader sur MLA-Share
LINK=$(curl -sX POST https://mla.kds.tf/api/upload \
  -F "file=@vm_compromise_*.mla" \
  -F "expires_hours=1" \
  | jq -r '"https://mla.kds.tf/receive/" + .id')

echo "Lien à transmettre : $LINK"
# Transmettre le lien ET votre clé publique à l'autorité
# L'autorité déchiffre depuis son navigateur avec sa .mlapriv
```

---

## Cas d'usage — Backup serveur vers admin distant

```bash
# Sur le serveur source
tar czf - /var/lib/postgresql/data/ | mlar create \
  -k serveur.mlapriv \
  -p admin.mlapub \
  -o pg_backup_$(hostname)_$(date +%Y%m%d).mla \
  --stdin-data

# Upload et récupérer le lien
curl -sX POST https://mla.kds.tf/api/upload \
  -F "file=@pg_backup_*.mla" \
  -F "expires_hours=168" \
  | jq -r '.id'
```

---

## Conversion pour archivage long terme

```bash
# Supprimer le chiffrement + compression maximale (archivage légal, RGPD)
mlar convert \
  -k receiver.mlapriv \
  -p sender.mlapub \
  -i archive.mla \
  -o archive_longterme.mla \
  --unencrypted --unsigned \
  -q 11
```

---

## Récupération d'une archive tronquée

```bash
# Mode authentifié (recommandé) — récupère uniquement les chunks validés
mlar repair \
  -k receiver.mlapriv \
  -p sender.mlapub \
  -i archive_tronquee.mla \
  -o archive_reparee.mla

# Mode non authentifié — récupère tout ce qui est lisible (à utiliser avec précaution)
mlar repair --allow-unauthenticated \
  -k receiver.mlapriv \
  -p sender.mlapub \
  -i archive_tronquee.mla \
  -o archive_reparee.mla
```

---

## Sécurité — rappels

- Transmettez le lien de partage et votre `.mlapub` par des **canaux distincts** (lien par mail, clé publique par Signal ou en personne).
- Préférez `expires_hours=1` pour tout fichier sensible (VM, dump mémoire, base de données).
- Une archive non signée (`--unsigned`) ne garantit pas l'identité de l'expéditeur — évitez-la pour les échanges avec des autorités.
- Vérifiez toujours que vous importez la clé **publique** du destinataire, pas la vôtre.
