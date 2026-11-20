# NetStock Lab — boutique de démonstration volontairement vulnérable

> **Lab uniquement.** Ce site contient des failles **exprès**. Il écoute sur `127.0.0.1:8082` et ne doit jamais être
> exposé sur un réseau ni déployé sur un vrai serveur. Toutes les données sont fictives.

NetStock Lab est une petite boutique de matériel réseau (PHP + MariaDB) qui sert de cible au scanner
(étape S3 du projet), puis à des tests manuels (S5), avant d'être corrigée (S7-B) pour mesurer l'avant / après.

## Failles prévues

| Faille | Page | Ce qu'elle permet | Catégorie |
|---|---|---|---|
| Prix envoyé par le navigateur | `panier.php` | Payer un produit le prix qu'on veut | Logique métier (fraude) |
| Quantité négative acceptée | `panier.php` | Faire baisser le total, jusqu'à un total négatif | Logique métier (fraude) |
| Code promo réutilisable | `panier.php` | Cumuler les remises `BIENVENUE10` | Logique métier (fraude) |
| Commande d'un autre client visible | `commande.php?id=` | Lire l'adresse et la commande d'un autre client | Contrôle d'accès (IDOR), OWASP A01 |
| Injection SQL | `connexion.php` | Se connecter sans mot de passe | Injection, OWASP A03 |
| Texte recherché réaffiché tel quel | `index.php?q=` | Exécuter un script dans la page (XSS réfléchi) | Injection, OWASP A03 |
| Erreur SQL affichée | `connexion.php` | Révéler la requête et la structure de la base | Divulgation d'informations |
| Mots de passe en MD5 sans sel | base `clients` | Retrouver les mots de passe en cas de fuite | Défaillances cryptographiques, OWASP A02 |

Ni Nmap ni Nikto ne voient les trois fraudes de logique métier : elles se trouvent par des tests manuels (S5).

> La version vulnérable est conservée sur la branche `v3-s3-boutique`. Cette branche (`v3-s7b-corrections`) contient la version corrigée décrite ci-dessous.

## Corrections (S7-B)

| Faille | Correction |
|---|---|
| Prix envoyé par le navigateur | Le serveur relit le prix dans la base à partir de l'identifiant ; la valeur du navigateur est ignorée (`panier.php`) |
| Quantité négative | Quantité ramenée à 1 au minimum, `max(1, …)` (`panier.php`) |
| Code promo réutilisable | Codes déjà appliqués mémorisés dans la session, un seul usage par panier (`panier.php`) |
| Commande d'un autre client (IDOR) | La requête filtre aussi sur `client_id` du client connecté (`commande.php`) |
| Injection SQL | Requête préparée avec paramètre lié (`connexion.php`) |
| XSS réfléchi | Texte recherché échappé avec `htmlspecialchars` avant affichage (`index.php`) |
| Erreur SQL affichée | Message générique, aucune erreur de base révélée (`connexion.php`) |
| Mots de passe en MD5 | Hachage `password_hash` (bcrypt + sel), vérifié par `password_verify` (`inc/installer.php`, `connexion.php`) |
| (en plus) CSRF | Jeton anti-CSRF par session dans chaque formulaire POST (`inc/db.php`) |
| (en plus) En-têtes, cookie | En-têtes de sécurité et cookie de session `HttpOnly` + `SameSite` (`inc/db.php`) |

## Comptes de test (fictifs)

| E-mail | Mot de passe |
|---|---|
| alice@netstock.lab | alice2027 |
| bob@netstock.lab | bob2027 |

## Installation dans la VM

En root, depuis ce dossier : `sh installer-dans-la-vm.sh`. Le script installe `php8.1-mysql`, copie le site dans
`/var/www/netstock-lab`, crée une base `netstock_lab` avec un compte dédié (mot de passe aléatoire, écrit seulement
dans `config.php`, lisible par Apache et root), remplit les données fictives et ajoute un site Apache sur
`127.0.0.1:8082`. Le relancer remet tout à zéro.

Désinstallation (root) : `a2dissite netstock-lab && systemctl reload apache2`, puis
`mysql -e "DROP DATABASE netstock_lab; DROP USER 'netstock_lab'@'localhost';"` et `rm -r /var/www/netstock-lab`.

## Photos des produits

Les photos ne sont pas stockées dans le dépôt. `telecharger-photos.sh` (root, après l'installation) les télécharge
depuis Pexels et Unsplash, deux banques d'images à licence libre, d'après `app/img/photos.txt`, les met à
400 × 260 px et les copie dans le site. Le pied de page crédite chaque photo avec un lien vers sa page d'origine.
Le SSD n'a pas de photo libre sans marque : il a une illustration originale (`app/img/produit-6.svg`), stockée dans le dépôt.
Le clavier (produit 5) utilise une photo personnelle copiée à la main dans la VM (`/var/www/netstock-lab/img/produit-5.jpg`) :
elle n'est jamais mise dans le dépôt, car ses droits appartiennent à son auteur.
Un produit sans photo ni illustration garde une vignette texte.

## Tests automatiques

`scanner/tests/test_boutique.py` lance la boutique avec le serveur intégré de PHP et une base SQLite. Sur cette
branche corrigée, chaque test rejoue une attaque et vérifie qu'elle **échoue** maintenant (injection SQL bloquée,
XSS échappé, prix relu dans la base, IDOR refusé, action sans jeton CSRF rejetée, en-têtes de sécurité présents).
