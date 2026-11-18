# Instructions pour Claude

## Langue

- Parle-moi en français.
- Écris le code en anglais (identifiants, messages d'erreur, logs, textes de l'interface).
- Écris les commentaires en anglais.
- Écris le README en anglais.

## Qualité

- Respecte au maximum les bonnes pratiques de Go (disposition `cmd/` + `internal/`, erreurs enveloppées avec `%w`, `context` propagé, tests, `gofmt` et `go vet` sans remarque).
- Assure-toi au maximum que le code est robuste et sécurisé.
- Avant de considérer un changement comme terminé : `make check` (gofmt, go vet, tests avec `-race`).
- Le format de stockage (schéma, AAD, vérificateur) doit rester compatible avec les bases existantes : le test `TestLegacyDatabase` le garantit.

## Commits

- N'ajoute jamais de ligne `Co-Authored-By: Claude …` (ni aucune autre mention d'IA) dans les messages de commit.
