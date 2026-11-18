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
