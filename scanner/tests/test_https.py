"""Tests du passage en HTTPS (suite de S7-A) : redirection HTTP → HTTPS, certificat auto-signé en lab, HSTS.

Un vrai serveur HTTPS local est monté avec un certificat auto-signé créé par la commande openssl.
"""
import shutil
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from conftest import FauxApache
from vulnscan import config, verification
from vulnscan.cible import Cible, preparer_cible
from vulnscan.constats import constats_tls
from vulnscan.scan import Scan, cible_analysee

pytestmark = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl absent")

SANS_TLS = {"protocoles": {}, "chiffrements_faibles": [], "certificat_expire_le": None, "taille_cle_rsa": None,
            "auto_signe": False}
LAB = Cible(url="https://localhost/mon-site/", schema="https", hote="localhost", port=443, adresses=["127.0.0.1"])
PUBLIC = Cible(url="https://exemple.fr/", schema="https", hote="exemple.fr", port=443, adresses=["93.184.216.34"])


class ApacheAvecHsts(FauxApache):
    def end_headers(self):
        self.send_header("Strict-Transport-Security", "max-age=31536000")
        super().end_headers()


def _serveur(handler, contexte=None):
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    if contexte:
        serveur.socket = contexte.wrap_socket(serveur.socket, server_side=True)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    return serveur


@pytest.fixture
def certificat(tmp_path):
    """Certificat auto-signé pour 127.0.0.1, comme celui d'un lab."""
    cle, cert = tmp_path / "lab.key", tmp_path / "lab.crt"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-keyout", str(cle),
                    "-out", str(cert), "-subj", "/CN=localhost", "-addext",
                    "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, capture_output=True)
    contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    contexte.load_cert_chain(cert, cle)
    return contexte


@pytest.fixture
def site_https(certificat):
    serveur = _serveur(FauxApache, certificat)
    yield serveur.server_address[1]
    serveur.shutdown()


def _site_http_qui_redirige(port_https, hote="127.0.0.1"):
    class Redirige(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(301)
            self.send_header("Location", f"https://{hote}:{port_https}{self.path}")
            self.send_header("Content-Length", "0")
            self.end_headers()
        do_HEAD = do_OPTIONS = do_GET
    return _serveur(Redirige)


# ---------------------------------------------------------------- Certificat

def test_certificat_auto_signe_reconnu(site_https):
    etat = verification.etat_certificat("127.0.0.1", site_https)
    assert etat["valide"] is False and etat["raison"] == "auto-signé" and "self" in etat["detail"].lower()


def test_port_ferme_ne_dit_rien_du_certificat():
    assert verification.etat_certificat("127.0.0.1", 1)["valide"] is None


@pytest.mark.parametrize("code, raison", [(10, "expiré"), (62, "nom différent"), (20, "autorité inconnue"),
                                          (18, "auto-signé"), (99, "autre")])
def test_raison_du_refus(site_https, monkeypatch, code, raison):
    class Contexte:
        def wrap_socket(self, *a, **k):
            erreur = ssl.SSLCertVerificationError("refus")
            erreur.verify_code, erreur.verify_message = code, "message d'OpenSSL"
            raise erreur
    monkeypatch.setattr(ssl, "create_default_context", lambda: Contexte())
    assert verification.etat_certificat("127.0.0.1", site_https)["raison"] == raison


def _certificat(raison, cible):
    obs = {"certificat_valide": False, "certificat_raison": raison, "certificat_detail": "détail"}
    (constat,) = constats_tls(SANS_TLS, obs, cible)
    return constat


def test_auto_signe_en_lab_reste_compte_mais_en_faible():
    c = _certificat("auto-signé", LAB)
    assert c.gravite == "Faible" and "auto-signé" in c.titre and "Let's Encrypt" in c.recommandation
    prive = Cible(url="https://192.168.56.10/", schema="https", hote="192.168.56.10", port=443,
                  adresses=["192.168.56.10"])
    assert _certificat("autorité inconnue", prive).gravite == "Faible"


def test_auto_signe_sur_un_site_public_reste_en_moyenne():
    c = _certificat("auto-signé", PUBLIC)
    assert (c.gravite, c.titre) == ("Moyenne", "Certificat non reconnu par les navigateurs")


def test_expire_ou_mauvais_nom_reste_en_moyenne_meme_en_lab():
    assert (_certificat("expiré", LAB).gravite, _certificat("expiré", LAB).titre) == ("Moyenne", "Certificat expiré")
    assert _certificat("nom différent", LAB).gravite == "Moyenne"
    assert _certificat("autre", LAB).gravite == "Moyenne"


def test_certificat_valide_ne_donne_aucun_constat():
    assert constats_tls(SANS_TLS, {"certificat_valide": True}, LAB) == []
    assert constats_tls(SANS_TLS, {"certificat_valide": None}, LAB) == []       # connexion impossible : rien d'affirmé


# ---------------------------------------------------------------- Redirection HTTP → HTTPS

def test_la_cible_analysee_suit_la_redirection_sur_la_meme_machine():
    http = Cible(url="http://localhost/mon-site/", schema="http", hote="localhost", port=80, adresses=["127.0.0.1"])
    suivie = cible_analysee(http, {"url_finale": "https://localhost/mon-site/"})
    assert (suivie.url, suivie.schema, suivie.port, suivie.hote) == ("https://localhost/mon-site/", "https", 443,
                                                                    "localhost")
    assert cible_analysee(http, {"url_finale": "https://localhost:8443/x/"}).port == 8443
    # Pas de redirection, ou redirection vers une autre machine : on reste sur la cible autorisée
    assert cible_analysee(http, {"url_finale": "http://localhost/mon-site/"}) is http
    assert cible_analysee(http, {"url_finale": "https://autre-site.example/"}) is http
    assert cible_analysee(http, {}) is http


def test_verification_controle_le_cote_https(site_https):
    http = _site_http_qui_redirige(site_https)
    cible = preparer_cible(f"http://127.0.0.1:{http.server_address[1]}/mon-site/", liste_blanche=["127.0.0.1"])
    obs = verification.verifier(cible)
    http.shutdown()
    assert obs["redirige_vers_https"] and obs["https_disponible"] and obs["port_https"] == site_https
    assert obs["certificat_valide"] is False and obs["certificat_raison"] == "auto-signé"
    assert obs["hsts_present"] is False


def _scanner(url, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DOSSIER_SCANS", tmp_path / "scans")
    monkeypatch.setattr(config, "IA_ACTIVE", False)
    scan = Scan(preparer_cible(url, liste_blanche=["127.0.0.1"]))
    scan.executer()
    assert scan.erreur == ""
    return scan.resultat


def test_scan_d_un_site_http_qui_redirige_vers_https(site_https, faux_outils, tmp_path, monkeypatch):
    http = _site_http_qui_redirige(site_https)
    saisie = f"http://127.0.0.1:{http.server_address[1]}/mon-site/"
    r = _scanner(saisie, tmp_path, monkeypatch)
    http.shutdown()
    assert r["cible"]["url"] == saisie and r["cible"]["url_analysee"] == f"https://127.0.0.1:{site_https}/mon-site/"
    assert "SSLScan" in r["durees"]                       # le chiffrement est analysé bien que l'adresse soit en HTTP
    assert f"127.0.0.1:{site_https}" in r["commandes"]["SSLScan"]
    assert r["commandes"]["Nikto"].startswith(f"nikto -h https://127.0.0.1:{site_https}/mon-site/")
    par_titre = {c["titre"]: c for c in r["constats"]}
    assert "Site disponible uniquement en HTTP (pas de HTTPS)" not in par_titre
    assert "HTTP ne redirige pas vers HTTPS" not in par_titre
    assert par_titre["Certificat auto-signé (acceptable en lab, à remplacer en production)"]["gravite"] == "Faible"
    assert "HSTS non activé" in par_titre
    assert any(t.startswith("Cookie « PHPSESSID » sans protection (HttpOnly, Secure") for t in par_titre)


def test_scan_avec_hsts(certificat, faux_outils, tmp_path, monkeypatch):
    serveur = _serveur(ApacheAvecHsts, certificat)
    r = _scanner(f"https://127.0.0.1:{serveur.server_address[1]}/mon-site/", tmp_path, monkeypatch)
    serveur.shutdown()
    titres = [c["titre"] for c in r["constats"]]
    assert "HSTS non activé" not in titres
    assert r["cible"]["url_analysee"] == r["cible"]["url"]
