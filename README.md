# Scanner de vulnérabilités web

**Projet personnel — outil d'analyse de sécurité de sites web, avec son propre laboratoire de test.**

J'ai développé un scanner qui analyse un site, puis j'ai construit une boutique
volontairement vulnérable pour le mettre à l'épreuve : je l'ai attaquée à la main,
puis je l'ai corrigée, et des tests automatiques prouvent l'avant et l'après.

> Projet mené de bout en bout : l'outil, les cibles de test, les attaques et les corrections.
> Tout tourne en local (`127.0.0.1`), dans un cadre d'apprentissage.

---

## Ce que ce projet démontre

La plupart des démos de sécurité montrent **une** chose. Ici, le cycle est complet :

1. **Construire** — un scanner, et un site e-commerce vulnérable pour le tester.
2. **Attaquer** — exploiter les failles à la main (injection SQL, XSS, détournement de prix, accès aux données d'un autre client).
3. **Mesurer** — l'outil donne un score, mais **ne voit pas** les failles de logique applicative : il faut un test manuel.
4. **Corriger** — requêtes préparées, échappement, hachage bcrypt, jetons anti-CSRF, en-têtes de sécurité.
5. **Prouver** — rejouer les attaques (elles échouent) et des tests automatiques qui valident les corrections.

C'est le point clé : **je comprends la sécurité des deux côtés — l'attaque et la défense — et je connais les limites d'un scanner automatique.**

---

## Le scanner

- Lance **Nmap, Nikto, SSLScan et OWASP ZAP** (analyse passive) en parallèle.
- **Vérifie chaque constat** par une requête directe au site, pour écarter les faux positifs.
- Contrôle les **chemins sensibles**, les **en-têtes HTTP**, le **certificat TLS**, les **CVE connues** des services détectés.
- **Compare deux analyses** d'un même site (avant / après correction) avec l'écart de score et le statut de chaque constat.
- Produit un **rapport PDF** complet, rédigé en français.
- Rapide : une analyse en **~15 secondes** (l'ancienne version, basée sur une IA, prenait 2 min 42).

## Le laboratoire : NetStock Lab

Une boutique PHP/MySQL de matériel réseau, **volontairement vulnérable**, que j'ai codée pour servir de cible réaliste. Elle existe en deux versions :

- **Version vulnérable** — 8 failles (injection SQL, XSS, IDOR, prix contrôlé par le client, mots de passe en MD5, etc.).
- **Version corrigée** — toutes les failles fermées, avec en plus jetons anti-CSRF, en-têtes de sécurité et cookie de session protégé.

**8 tests automatiques prouvent les failles sur la version vulnérable ; ces mêmes tests, inversés, prouvent qu'elles sont corrigées sur la version corrigée.**

---

## Résultats

| Mesure | Résultat |
|---|---|
| Durcissement du serveur (mêmes conditions) | score **51 → 97 / 100** |
| Failles de la boutique trouvées **et** corrigées | **4 majeures** démontrées à la main + 4 prouvées par tests |
| Cibles attaquées manuellement | ma boutique, **DVWA**, **OWASP Juice Shop** |
| Tests automatiques au vert | **88** |
| Durée d'une analyse | **~15 s** |

---

## Stack technique

**Python** (plateforme d'analyse, orchestration des outils, génération PDF) · **Nmap / Nikto / SSLScan / OWASP ZAP** · **PHP / MySQL (MariaDB) / Apache** (le laboratoire) · **pytest** (tests automatiques) · **VirtualBox / Ubuntu** (environnement isolé).

---

## Structure du dépôt

```
.
├── scanner/            La plateforme d'analyse (code + tests)
├── lab/
│   └── boutique/       NetStock Lab : la boutique vulnérable et sa version corrigée
├── docs/               Rapport de projet (PDF), captures avant/après
└── archive-v1/         La toute première version (projet d'origine), conservée pour l'historique
```

---

## Lancer le projet

```bash
# La plateforme d'analyse
cd scanner && IA_ACTIVE=0 PORT_ECOUTE=5001 python3 app.py
# puis ouvrir http://127.0.0.1:5001

# Les tests
cd scanner && python3 -m pytest
```

Le laboratoire (boutique NetStock Lab) s'installe avec le script fourni dans `lab/boutique/`.

---

## Démonstration

_Vidéo de démonstration en cours de montage — attaque, correction et nouvelle analyse en 2 minutes._

---

## À propos

Projet personnel, à vocation d'apprentissage et de démonstration de compétences en sécurité web.
Toutes les cibles sont des environnements de test que je contrôle, sur `127.0.0.1`.
Né d'un projet d'école, il est devenu un projet que je fais évoluer pour moi.
