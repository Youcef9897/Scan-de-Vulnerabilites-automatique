"""Vérification directe : on reconfirme les constats par des requêtes HTTP simples.

Seules des requêtes de lecture sont envoyées (GET, OPTIONS, TRACE, DEBUG) :
aucune donnée n'est modifiée sur le site.
"""
import re
from urllib.parse import urlparse, urlunparse

import requests
import urllib3

from . import config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ENTETES_SECURITE = [
    "X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options",
    "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy",
]


def _cookies(reponse) -> list:
    """Cookies posés par le serveur, avec leurs attributs de sécurité."""
    bruts = []
    try:
        bruts = reponse.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        valeur = reponse.headers.get("Set-Cookie")
        bruts = [valeur] if valeur else []
    cookies = []
    for brut in bruts:
        nom = brut.split("=", 1)[0].strip()
        attributs = brut.lower()
        cookies.append({
            "nom": nom,
            "httponly": "httponly" in attributs,
            "secure": "secure" in attributs,
            "samesite": "samesite" in attributs,
            "brut": brut,
        })
    return cookies


def _methode(url: str, methode: str):
    try:
        r = requests.request(methode, url, timeout=config.DUREE_MAX_HTTP,
                             allow_redirects=False, verify=False)
        return r.status_code, r.text[:500]
    except requests.RequestException:
        return None, ""


def verifier(cible) -> dict:
    """Interroge le site et renvoie ce qui a été observé directement."""
    obs = {"accessible": False, "erreur": ""}
    try:
        r = requests.get(cible.url, timeout=config.DUREE_MAX_HTTP, allow_redirects=True, verify=False)
    except requests.RequestException as e:
        obs["erreur"] = str(e)
        return obs

    obs["accessible"] = True
    obs["statut"] = r.status_code
    obs["url_finale"] = r.url
    obs["entetes"] = dict(r.headers)
    obs["entetes_absents"] = [h for h in ENTETES_SECURITE if h.lower() not in {k.lower() for k in r.headers}]
    csp = r.headers.get("Content-Security-Policy", "")
    obs["protection_cadres"] = ("X-Frame-Options" in r.headers) or ("frame-ancestors" in csp.lower())
    obs["serveur"] = r.headers.get("Server", "")
    obs["serveur_avec_version"] = bool(re.search(r"\d", obs["serveur"]))
    obs["powered_by"] = r.headers.get("X-Powered-By", "")
    obs["cookies"] = _cookies(r)
    obs["page"] = r.text[:200000]      # sert au contrôle des chemins sensibles (liens de la page)

    # Méthodes HTTP : OPTIONS (liste annoncée), TRACE et DEBUG (doivent être refusées).
    obs["methodes_annoncees"] = ""
    try:
        ro = requests.options(cible.url, timeout=config.DUREE_MAX_HTTP, allow_redirects=False, verify=False)
        obs["methodes_annoncees"] = ro.headers.get("Allow", "")
    except requests.RequestException:
        pass
    code_trace, corps_trace = _methode(cible.url, "TRACE")
    obs["trace_active"] = code_trace == 200 and "TRACE" in corps_trace.upper()
    code_debug, _ = _methode(cible.url, "DEBUG")
    obs["debug_code"] = code_debug
    obs["debug_accepte"] = code_debug == 200

    # HTTPS : le site est-il aussi disponible en HTTPS, et HTTP redirige-t-il vers HTTPS ?
    p = urlparse(cible.url)
    if p.scheme == "http":
        url_https = urlunparse(p._replace(scheme="https", netloc=p.hostname))
        try:
            requests.get(url_https, timeout=config.DUREE_MAX_HTTP, verify=False)
            obs["https_disponible"] = True
        except requests.RequestException:
            obs["https_disponible"] = False
        obs["redirige_vers_https"] = r.url.startswith("https://")
    else:
        obs["https_disponible"] = True
        obs["redirige_vers_https"] = True
        try:
            requests.get(cible.url, timeout=config.DUREE_MAX_HTTP, verify=True)
            obs["certificat_valide"] = True
        except requests.exceptions.SSLError:
            obs["certificat_valide"] = False
        except requests.RequestException:
            obs["certificat_valide"] = None
    return obs
