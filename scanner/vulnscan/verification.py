"""Vérification directe : on reconfirme les constats par des requêtes HTTP simples.

Seules des requêtes de lecture sont envoyées (GET, OPTIONS, TRACE, DEBUG) :
aucune donnée n'est modifiée sur le site.
"""
import re
import socket
import ssl
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


def _methode(url: str, methode: str, entetes: dict | None = None):
    try:
        r = requests.request(methode, url, headers=entetes, timeout=config.DUREE_MAX_HTTP,
                             allow_redirects=False, verify=False)
        return r.status_code, r.text[:500]
    except requests.RequestException:
        return None, ""


# Codes d'erreur d'OpenSSL lors de la vérification d'un certificat (X509_V_ERR_*)
RAISONS_CERTIFICAT = {
    18: "auto-signé", 19: "auto-signé",                     # certificat (ou chaîne) signé par lui-même
    20: "autorité inconnue", 21: "autorité inconnue",       # émetteur absent des autorités reconnues
    9: "pas encore valide", 10: "expiré",
    62: "nom différent",                                    # le certificat est émis pour un autre nom que le site
}


def etat_certificat(hote: str, port: int = 443) -> dict:
    """Présente le certificat du site à la vérification d'un navigateur (autorités reconnues, dates, nom).

    Renvoie {"valide": True | False | None, "raison", "detail"} ; None si la connexion TLS n'a pas pu se faire.
    """
    contexte = ssl.create_default_context()
    try:
        with socket.create_connection((hote, port), timeout=config.DUREE_MAX_HTTP) as connexion:
            with contexte.wrap_socket(connexion, server_hostname=hote):
                return {"valide": True, "raison": "", "detail": ""}
    except ssl.SSLCertVerificationError as e:
        return {"valide": False, "raison": RAISONS_CERTIFICAT.get(e.verify_code, "autre"),
                "detail": e.verify_message or str(e)}
    except (OSError, ssl.SSLError) as e:
        return {"valide": None, "raison": "", "detail": str(e)}


def _noter_https(obs: dict, hote: str, port: int, reponse_https):
    """Ce qui est observé côté HTTPS : certificat et en-tête HSTS."""
    obs["port_https"] = port
    certificat = etat_certificat(hote, port)
    obs["certificat_valide"] = certificat["valide"]
    obs["certificat_raison"] = certificat["raison"]
    obs["certificat_detail"] = certificat["detail"]
    if reponse_https is not None:
        obs["hsts_present"] = "strict-transport-security" in {k.lower() for k in reponse_https.headers}


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
    # Le vrai débogage à distance (ASP.NET sous IIS) répond exactement « OK » à DEBUG avec l'en-tête
    # « Command: stop-debug ». Une application PHP répond 200 à n'importe quelle méthode en renvoyant
    # sa page normale : ce code 200 seul ne prouve donc rien.
    code_debug, corps_debug = _methode(cible.url, "DEBUG", {"Command": "stop-debug"})
    obs["debug_code"] = code_debug
    obs["debug_accepte"] = code_debug == 200 and corps_debug.strip() == "OK"

    # HTTPS : le site est-il aussi disponible en HTTPS, et HTTP redirige-t-il vers HTTPS ?
    p = urlparse(cible.url)
    if p.scheme == "http":
        obs["redirige_vers_https"] = r.url.startswith("https://")
        if obs["redirige_vers_https"]:
            rh, port = r, (urlparse(r.url).port or 443)        # la réponse reçue vient déjà du côté HTTPS
            obs["https_disponible"] = True
        else:
            port = 443
            url_https = urlunparse(p._replace(scheme="https", netloc=p.hostname))
            try:
                rh = requests.get(url_https, timeout=config.DUREE_MAX_HTTP, verify=False)
                obs["https_disponible"] = True
            except requests.RequestException:
                rh = None
                obs["https_disponible"] = False
        if obs["https_disponible"]:
            # Même si l'adresse saisie est en HTTP, le côté HTTPS du site est contrôlé lui aussi.
            _noter_https(obs, urlparse(r.url).hostname if obs["redirige_vers_https"] else p.hostname, port, rh)
    else:
        obs["https_disponible"] = True
        obs["redirige_vers_https"] = True
        _noter_https(obs, cible.hote, cible.port, r)
    return obs
