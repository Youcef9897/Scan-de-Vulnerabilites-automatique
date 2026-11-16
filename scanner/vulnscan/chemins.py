"""Contrôle des chemins sensibles : ce que Nmap, Nikto et SSLScan ne regardent pas.

On cherche, sous l'adresse analysée :
  - les dossiers dont le contenu est listé (« Index of ») ;
  - les copies de sauvegarde et le code source téléchargeables (.bak, .old, .py…) ;
  - les fichiers de secrets ou de données (.env, .git, .sql…) ;
  - les zones d'administration joignables.

Règles de prudence : uniquement des requêtes GET (lecture), uniquement sur le
même hôte et sous l'adresse analysée, et un nombre de requêtes borné.
"""
import re
import uuid
from urllib.parse import urljoin, urlparse

import requests

from . import config

# Dossiers courants essayés en plus de ceux trouvés dans la page d'accueil.
DOSSIERS_COURANTS = [
    "admin/", "administrator/", "phpmyadmin/", "backup/", "backups/", "old/", "test/", "tmp/", "dev/",
    "private/", "config/", "includes/", "uploads/", "files/", "data/", "db/", "logs/", "scripts/",
    "src/", "app/", "api/", "tools/",
]
# Fichiers sensibles classiques, essayés à la racine de l'adresse analysée.
FICHIERS_COURANTS = [
    ".git/HEAD", ".env", ".htpasswd", "backup.zip", "backup.tar.gz", "backup.sql", "dump.sql",
    "database.sql", "config.php.bak", "wp-config.php.bak", ".DS_Store",
]
SUFFIXES_SAUVEGARDE = [".bak", ".old", "~"]
ZONES_ADMIN = ("admin/", "administrator/", "phpmyadmin/")

# Extensions classées par niveau de risque.
_SECRETS = re.compile(r"(\.env|\.htpasswd|\.sql|\.sqlite3?|\.db|\.pem|\.key|id_rsa|\.zip|\.tar\.gz|\.tgz|\.git/HEAD)$", re.I)
_SOURCES = re.compile(r"(\.bak|\.old|\.orig|\.save|\.swp|~|\.py|\.sh|\.inc|\.log|\.conf|\.ini|\.ya?ml)$", re.I)
_LISTAGE = re.compile(r"<title>\s*Index of\s", re.I)
_LIENS = re.compile(r"""(?:href|src)\s*=\s*["']([^"'#]+)["']""", re.I)


def _base(url: str) -> str:
    """Adresse du dossier analysé, terminée par « / »."""
    p = urlparse(url)
    chemin = p.path if p.path.endswith("/") else p.path.rsplit("/", 1)[0] + "/"
    return f"{p.scheme}://{p.netloc}{chemin}"


def classer(chemin: str):
    """« secret », « source » ou None selon le nom du fichier."""
    if _SECRETS.search(chemin):
        return "secret"
    if _SOURCES.search(chemin):
        return "source"
    return None


class _Explorateur:
    def __init__(self, cible):
        self.base = _base(cible.url)
        self.session = requests.Session()
        self.requetes = 0
        self.journal = []          # lignes « code chemin » pour l'annexe du rapport
        self.vus = set()

    def relatif(self, url: str) -> str:
        return url[len(self.base):] or "./"

    def dans_perimetre(self, url: str) -> bool:
        return url.startswith(self.base) and ".." not in url[len(self.base):]

    def get(self, url: str):
        """GET borné : renvoie (code, début du corps) ou (None, '') si budget épuisé ou erreur."""
        if url in self.vus or not self.dans_perimetre(url) or self.requetes >= config.CHEMINS_MAX_REQUETES:
            return None, ""
        self.vus.add(url)
        self.requetes += 1
        try:
            r = self.session.get(url, timeout=config.DUREE_MAX_CHEMIN, allow_redirects=False,
                                 verify=False, stream=True)
            corps = r.raw.read(4000, decode_content=True).decode("utf-8", errors="replace")
            r.close()
        except (requests.RequestException, OSError):
            self.journal.append(f"--- {self.relatif(url)}")
            return None, ""
        self.journal.append(f"{r.status_code} {self.relatif(url)}")
        return r.status_code, corps


def controler(cible, page_accueil: str = "") -> dict:
    """Renvoie les chemins sensibles trouvés sous l'adresse analysée."""
    ex = _Explorateur(cible)
    res = {"listages": [], "secrets": [], "sources": [], "admin": [], "requetes": 0,
           "ignore": "", "journal": ex.journal}

    # Le site répond-il « 200 » à n'importe quelle adresse ? Si oui, impossible de conclure.
    code, _ = ex.get(ex.base + f"introuvable-{uuid.uuid4().hex[:10]}.txt")
    if code is None or code == 200:
        res["ignore"] = ("Le site répond « 200 » même pour une page qui n'existe pas : le contrôle des chemins "
                         "sensibles n'est pas fiable sur cette cible." if code == 200 else
                         "Le site n'a pas répondu au contrôle des chemins sensibles.")
        res["requetes"] = ex.requetes
        return res

    # Candidats : liens de la page d'accueil, dossiers et fichiers courants, chemins ajoutés à la main.
    dossiers, fichiers = [], []

    def ajouter(url):
        if not ex.dans_perimetre(url) or "?" in url:
            return
        (dossiers if url.endswith("/") else fichiers).append(url)

    pages = []
    for lien in _LIENS.findall(page_accueil or ""):
        url = urljoin(ex.base, lien.strip())
        if not ex.dans_perimetre(url) or "?" in url:
            continue
        # chaque dossier traversé par le lien (assets/, assets/img/…)
        morceaux = ex.relatif(url).split("/")[:-1]
        for i in range(1, len(morceaux) + 1):
            ajouter(ex.base + "/".join(morceaux[:i]) + "/")
        if re.search(r"\.(html?|php)$", url, re.I):
            pages.append(url)
    for d in DOSSIERS_COURANTS + [c for c in config.CHEMINS_SUPPLEMENTAIRES if c.endswith("/")]:
        ajouter(ex.base + d)
    for f in FICHIERS_COURANTS + [c for c in config.CHEMINS_SUPPLEMENTAIRES if not c.endswith("/")]:
        ajouter(ex.base + f)
    # copies de sauvegarde des pages connues : index.html.bak, login.html.old…
    for page in [ex.base + "index.html", ex.base + "index.php"] + pages:
        for s in SUFFIXES_SAUVEGARDE:
            ajouter(page + s)

    def noter_fichier(url, origine):
        genre = classer(url)
        if genre:
            cle = "secrets" if genre == "secret" else "sources"
            if not any(e["chemin"] == ex.relatif(url) for e in res[cle]):
                res[cle].append({"chemin": ex.relatif(url), "origine": origine})

    def explorer_dossier(url, profondeur):
        code, corps = ex.get(url)
        if code != 200:
            return
        if _LISTAGE.search(corps):
            res["listages"].append(ex.relatif(url))
            for lien in _LIENS.findall(corps):
                if lien.startswith(("?", "/")) or "://" in lien or ".." in lien:
                    continue          # liens de tri et « Parent Directory »
                enfant = urljoin(url, lien)
                if enfant.endswith("/"):
                    if profondeur < config.CHEMINS_PROFONDEUR:
                        explorer_dossier(enfant, profondeur + 1)
                elif classer(enfant):
                    c2, _ = ex.get(enfant)
                    if c2 == 200 or c2 is None:    # None : budget épuisé, le listage reste une preuve
                        noter_fichier(enfant, "vu dans le listage" + (", téléchargeable" if c2 == 200 else ""))
        elif ex.relatif(url) in ZONES_ADMIN:
            res["admin"].append(ex.relatif(url))

    for d in dict.fromkeys(dossiers):
        explorer_dossier(d, 1)
    for f in dict.fromkeys(fichiers):
        code, corps = ex.get(f)
        if code != 200:
            continue
        if f.endswith(".git/HEAD") and not re.match(r"(ref:|[0-9a-f]{40})", corps.strip()):
            continue                  # une page d'erreur déguisée, pas un vrai dépôt Git
        noter_fichier(f, "téléchargeable (code 200)")

    res["requetes"] = ex.requetes
    return res
