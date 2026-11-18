# credentials

Petit coffre local de credentials pour le développement : API HTTP + interface d'admin.
Binaire Go unique, SQLite en pur Go (`modernc.org/sqlite`), **aucune dépendance système / CGO**.

## Lancer

```sh
go build -o credentials .
./credentials                       # demande la passphrase (confirmation à la 1re création)
CREDENTIALS_PASSPHRASE=... ./credentials -addr 127.0.0.1:12345 -db /autre/chemin.db
```

Base par défaut : `$XDG_DATA_HOME/credentials/credentials.db` (soit `~/.local/share/credentials/credentials.db`), dossier en `0700`, hors du dépôt.

Admin : http://localhost:12345/admin

## API

| Méthode | Route | Rôle |
|---|---|---|
| GET | `/credentials` | liste (sans les secrets) |
| GET | `/credentials/{id}` | JSON complet, secret déchiffré |
| GET | `/credentials/{id}/raw` | secret brut, `Content-Type` selon le format |
| GET | `/by-name/{name}` · `/by-name/{name}/raw` | idem, par nom |
| POST | `/credentials` | création (`{"name","description","format","credentials"}`) |
| PUT | `/credentials/{id}` | mise à jour |
| DELETE | `/credentials/{id}` | suppression |

Formats : `txt`, `json`, `yaml`, `toml`, `env`, `pem` (json/yaml/toml validés à l'enregistrement).

```sh
curl -s localhost:12345/credentials/1
curl -s localhost:12345/by-name/MyWebService/raw > config.json
```

## Sécurité

- Colonne `credentials` chiffrée en **AES-256-GCM** ; clé dérivée de la passphrase par **Argon2id**
  (sel aléatoire stocké en base). La passphrase n'est jamais stockée. Le chiffré est lié à l'id
  de la ligne (AAD), donc on ne peut pas échanger deux valeurs dans la base.
- Une mauvaise passphrase est détectée au démarrage.
- Écoute uniquement sur loopback (refus de `0.0.0.0`), en-tête `Host` vérifié (anti DNS rebinding),
  requêtes cross-origin bloquées (anti CSRF depuis un site web ouvert dans le navigateur).
- Pas d'authentification : tout processus local de votre utilisateur peut lire l'API.
- Si vous perdez la passphrase, les secrets sont irrécupérables.

## Paquet .deb et service systemd

```sh
make deb VERSION=0.2.0          # → dist/credentials_0.2.0_amd64.deb
sudo apt install ./dist/credentials_0.2.0_amd64.deb
```

- **Installation** : crée l'utilisateur système `credentials`, le dossier `/var/lib/credentials` (0700),
  demande la passphrase (debconf), active et démarre `credentials.service` (lancé au boot).
- **Mise à jour** : construire une version supérieure et refaire `apt install` ; le service redémarre
  avec le nouveau binaire, la configuration et la passphrase sont conservées.
- **Configuration** : `/etc/credentials/config.toml` (`addr`, `db`), puis `sudo systemctl restart credentials`.
- **Logs** : `journalctl -u credentials -f`
- **Désinstallation** : `sudo apt remove credentials` ; `apt purge` supprime aussi la config et la
  passphrase chiffrée. La base dans `/var/lib/credentials` n'est **jamais** supprimée automatiquement.

### Passphrase

Le service doit démarrer sans intervention, il faut donc que la passphrase soit disponible sur la
machine — mais pas en clair. Elle est chiffrée par `systemd-creds` dans
`/etc/credentials/passphrase.cred`, avec la puce **TPM2** et la clé de l'hôte
(`/var/lib/systemd/credential.secret`, lisible par root uniquement). Au lancement, systemd la
déchiffre et ne la donne qu'au service (`$CREDENTIALS_DIRECTORY/passphrase`).

Conséquence : une copie de la base, de la config et du `.cred` (sauvegarde, disque volé) est
inexploitable sur une autre machine. Gardez la passphrase dans votre gestionnaire de mots de passe :
c'est elle qui permet de restaurer la base ailleurs.

```sh
sudo credentials-passphrase           # définir la passphrase du service (si ignorée à l'installation,
                                      # après un changement de carte mère ou un reset du TPM)
sudo credentials-passphrase --change  # changer la passphrase : arrête le service, rechiffre la base,
                                      # met à jour le .cred, redémarre
```

Hors service, le binaire lit la passphrase dans `CREDENTIALS_PASSPHRASE` ou la demande au terminal.

### Changer la passphrase (hors paquet)

```sh
credentials rekey                     # base par défaut ; ou -db / -config
printf '%s\n%s\n' "$ANCIENNE" "$NOUVELLE" | credentials rekey -stdin
```

Le serveur doit être arrêté (la commande refuse si quelque chose répond sur l'adresse configurée).
Tout est rechiffré avec un nouveau sel dans une seule transaction : en cas d'erreur, la base reste
intacte. Les anciennes versions chiffrées sont effacées du fichier (`secure_delete`, WAL vidé).
