# Scanner de vulnérabilités web — version 2

Plateforme web qui analyse un site **autorisé** avec Nmap, Nikto et SSLScan, **vérifie** chaque constat par des requêtes directes, puis produit un rapport en français (page web et PDF) : synthèse, score expliqué, constats classés par gravité avec preuves et recommandations.

> **Cadre légal.** Scanner un système sans l'autorisation de son propriétaire est interdit (articles 323-1 et suivants du Code pénal). La plateforme refuse toute cible absente de sa liste blanche et demande de confirmer l'autorisation avant chaque analyse.

## Ce qui a changé par rapport à la première version

| Avant | Maintenant |
|---|---|
| Outils lancés l'un après l'autre (≈ 5 min avec l'IA) | Outils en parallèle, résumé court : **1 à 2 min** |
| L'IA rédigeait tout le rapport à partir de la sortie brute | Les constats sont calculés et rédigés en français par le programme ; l'IA n'écrit qu'un résumé de quelques phrases (résumé automatique si l'IA ne répond pas) |
| Score calculé en comptant des mots-clés | Score sur 100 avec un barème affiché ; faux positifs exclus |
| Aucune vérification des alertes | Chaque constat est **reconfirmé** : Confirmé, Non confirmé, Faux positif probable ou À vérifier |
| N'importe quelle cible acceptée | Liste blanche + case d'autorisation obligatoire, un seul scan à la fois |
| Un seul fichier de 600 lignes | Code découpé en modules et **tests automatiques** |

## Contrôles ajoutés (version 3, étape S4)

Le premier scan réel du site de la VM donnait 64/100, avec deux faux positifs et deux failles non vues. Ces contrôles corrigent les deux défauts :

| Contrôle | Ce qu'il apporte |
|---|---|
| Chemins sensibles (`chemins.py`) | Trouve les dossiers listés (« Index of »), le code source et les copies de sauvegarde téléchargeables (`.py`, `.bak`, `.old`), les fichiers de secrets (`.env`, `.git`, `.sql`) et les zones d'administration. Requêtes GET uniquement, sous l'adresse analysée, 80 au maximum. |
| Écoute locale (`ecoute.py`) | Quand la cible est la machine elle-même, lit l'adresse d'écoute réelle de chaque service (`ss`). Un service limité à 127.0.0.1 est noté « écoute locale » et ne retire aucun point. |
| ETag | L'alerte « fuite d'inode » de Nikto est classée « Faux positif probable » quand l'ETag n'a que deux champs (taille et date). |
| CVE (script `vulners` de Nmap) | Liste les CVE publiées pour les versions détectées, avec leur score CVSS. Constat « À vérifier », car il repose sur le seul numéro de version. |
| Versions des outils | Nikto et SSLScan affichés proprement dans la méthodologie. |

Limites connues : le contrôle des chemins utilise une courte liste de noms courants et les liens de la page d'accueil ; un dossier au nom inhabituel doit être ajouté avec `CHEMINS_SUPPLEMENTAIRES`. Les CVE demandent un accès à Internet (les numéros de version sont envoyés à vulners.com).

## Installation (Ubuntu 22.04)

```bash
sudo apt update
sudo apt install -y nmap nikto sslscan python3-flask python3-requests python3-reportlab fonts-dejavu-core
```

Optionnel, pour le résumé rédigé par l'IA locale : installer [Ollama](https://ollama.com/) puis `ollama pull mistral`.

## Lancement

```bash
cd scanner
python3 app.py
```

Puis ouvrir **http://127.0.0.1:5000**. Les rapports sont enregistrés dans `scanner/scans/` (un dossier par analyse).

## Réglages

Ils se changent au lancement, sans modifier le code :

| Variable | Rôle | Valeur par défaut |
|---|---|---|
| `CIBLES_AUTORISEES` | Liste blanche (noms, IP ou réseaux) | `localhost,127.0.0.1,192.168.56.0/24` |
| `IA_ACTIVE` | `0` pour désactiver le résumé par IA | `1` |
| `IA_MODELE` | Modèle Ollama | `mistral` |
| `IA_DUREE_MAX` | Délai maximal de l'IA, en secondes | `120` |
| `DUREE_MAX_NIKTO` | Durée maximale de Nikto, en secondes | `240` |
| `NMAP_PORTS` | Ports vérifiés par Nmap | `21,22,23,25,80,443,631,3306,3389,5432,8080,8443` |
| `CVE_ACTIVE` | `0` pour ne pas chercher les CVE (aucun envoi à vulners.com) | `1` |
| `CHEMINS_ACTIFS` | `0` pour désactiver le contrôle des chemins sensibles | `1` |
| `CHEMINS_SUPPLEMENTAIRES` | Chemins propres au site à contrôler en plus (`dossier/` ou `fichier`) | vide |
| `CHEMINS_MAX_REQUETES` | Nombre maximal de requêtes du contrôle des chemins | `80` |

Exemple : `IA_ACTIVE=0 python3 app.py`

## Organisation du code

```
scanner/
├── app.py                 interface web (Flask)
├── vulnscan/
│   ├── config.py          réglages
│   ├── cible.py           validation de la cible et liste blanche
│   ├── outils.py          lancement de Nmap, Nikto et SSLScan en parallèle
│   ├── analyse.py         lecture des sorties (XML de Nmap, texte de Nikto et SSLScan)
│   ├── verification.py    vérification directe par requêtes HTTP de lecture
│   ├── chemins.py         contrôle des chemins sensibles (listage, sauvegardes, code source)
│   ├── ecoute.py          adresse d'écoute réelle des services locaux (ss)
│   ├── constats.py        règles : constats en français, gravité, preuves, recommandations
│   ├── score.py           score sur 100 et barème
│   ├── resume.py          résumé exécutif (IA locale ou automatique)
│   ├── scan.py            déroulement complet d'une analyse
│   └── rapport_pdf.py     mise en page du rapport PDF
├── templates/             pages web
└── tests/                 tests automatiques (avec de vraies sorties de scan)
```

## Tests

```bash
cd scanner
python3 -m pytest -q
```

Les tests utilisent de faux outils et un faux site qui imitent le lab : ils ne scannent rien de réel.

## Avant une mise en ligne

La plateforme est prévue pour tourner en local. Avant de l'exposer sur Internet, il faudra au minimum : une authentification des utilisateurs, une limite du nombre d'analyses, une file d'attente, un serveur web de production (par exemple Gunicorn derrière Nginx en HTTPS) et une liste blanche gérée par compte.
