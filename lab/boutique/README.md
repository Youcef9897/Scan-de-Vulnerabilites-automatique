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

## Tests automatiques

`scanner/tests/test_boutique.py` lance la boutique avec le serveur intégré de PHP et une base SQLite, et vérifie
que chaque faille est bien présente. Après la correction (S7-B), ces tests seront inversés.
