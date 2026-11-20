"""Tests de la boutique NetStock Lab — VERSION CORRIGÉE (étape S7-B).

Chaque test rejoue une attaque de la version vulnérable (branche v3-s3-boutique) et vérifie
qu'elle échoue maintenant. La boutique est lancée avec le serveur intégré de PHP sur 127.0.0.1
et une base SQLite jetable.
"""
import re
import shutil
import socket
import subprocess
import time
from pathlib import Path

import pytest
import requests

APP = Path(__file__).resolve().parents[2] / "lab" / "boutique" / "app"

pytestmark = pytest.mark.skipif(shutil.which("php") is None or not APP.exists(), reason="php ou boutique absents")


def _port_libre():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def boutique(tmp_path):
    site = tmp_path / "site"
    shutil.copytree(APP, site)
    base = tmp_path / "netstock.sqlite"
    (site / "config.php").write_text(f"<?php return ['dsn' => 'sqlite:{base}'];\n", encoding="utf-8")
    subprocess.run(["php", str(site / "inc" / "installer.php")], check=True, capture_output=True)
    port = _port_libre()
    serveur = subprocess.Popen(["php", "-S", f"127.0.0.1:{port}", "-t", str(site)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            requests.get(url, timeout=1)
            break
        except requests.ConnectionError:
            time.sleep(0.1)
    yield url
    serveur.terminate()
    serveur.wait(timeout=5)


def _jeton(s, url, page="/index.php"):
    """Récupère le jeton anti-CSRF d'une page (et la session qui va avec)."""
    html = s.get(url + page, timeout=5).text
    m = re.search(r'name="csrf" value="([0-9a-f]+)"', html)
    return m.group(1) if m else ""


def _connecter(s, url, email, mdp):
    jeton = _jeton(s, url, "/connexion.php")
    return s.post(f"{url}/connexion.php",
                  data={"csrf": jeton, "email": email, "mot_de_passe": mdp}, timeout=5)


def _ajouter(s, url, **donnees):
    donnees.setdefault("csrf", _jeton(s, url))
    donnees["action"] = "ajouter"
    return s.post(f"{url}/panier.php", data=donnees, timeout=5)


def _total(page):
    m = re.search(r'class="total"><td colspan="3">Total</td><td>(-?[\d ,]+) €', page)
    return float(m.group(1).replace(" ", "").replace(",", ".")) if m else None


def test_catalogue_et_connexion_normale(boutique):
    s = requests.Session()
    page = s.get(boutique, timeout=5).text
    assert "Switch 8 ports Gigabit" in page and "version corrigée" in page
    assert "Connecté en tant que Alice Martin" in _connecter(s, boutique, "alice@netstock.lab", "alice2027").text
    assert "incorrect" in _connecter(requests.Session(), boutique, "alice@netstock.lab", "mauvais").text


def test_injection_sql_a_la_connexion_bloquee(boutique):
    s = requests.Session()
    page = _connecter(s, boutique, "' OR '1'='1' -- ", "nimporte").text
    assert "Connecté en tant que" not in page and "incorrect" in page


def test_aucune_erreur_sql_affichee(boutique):
    page = _connecter(requests.Session(), boutique, "'", "x").text
    assert "Erreur SQL" not in page and "SQLSTATE" not in page


def test_xss_reflechi_echappe(boutique):
    charge = "<script>alert('lab')</script>"
    page = requests.get(boutique, params={"q": charge}, timeout=5).text
    assert charge not in page                                 # le script brut n'apparaît plus
    assert "&lt;script&gt;" in page                           # il est affiché échappé


def test_prix_du_navigateur_ignore(boutique):
    s = requests.Session()
    _ajouter(s, boutique, produit_id=4, prix="0.01", quantite=1)
    page = s.get(f"{boutique}/panier.php", timeout=5).text
    assert "Point d&#039;accès Wi-Fi 6" in page and _total(page) == 89.90   # prix de la base, pas 0,01 €


def test_quantite_minimale_et_code_promo_unique(boutique):
    s = requests.Session()
    _ajouter(s, boutique, produit_id=6, prix="79.90", quantite=1)
    _ajouter(s, boutique, produit_id=1, prix="6.90", quantite=-5)          # quantité négative ramenée à 1
    for _ in range(3):
        s.post(f"{boutique}/panier.php",
               data={"csrf": _jeton(s, boutique), "action": "code", "code": "BIENVENUE10"}, timeout=5)
    page = s.get(f"{boutique}/panier.php", timeout=5).text
    assert _total(page) == pytest.approx(79.90 + 6.90 - 10)                # 76,80 € (une seule remise de 10 €)


def test_commande_d_un_autre_client_refusee(boutique):
    s = requests.Session()
    _connecter(s, boutique, "alice@netstock.lab", "alice2027")
    page = s.get(f"{boutique}/commande.php", params={"id": 1}, timeout=5).text   # commande de Bob
    assert "Bob Durand" not in page and "introuvable" in page


def test_action_sans_jeton_csrf_refusee(boutique):
    s = requests.Session()
    s.get(f"{boutique}/index.php", timeout=5)                              # ouvre une session, sans prendre le jeton
    s.post(f"{boutique}/panier.php", data={"action": "ajouter", "produit_id": 4, "quantite": 1}, timeout=5)
    page = s.get(f"{boutique}/panier.php", timeout=5).text
    assert "Ton panier est vide" in page                                  # rien n'a été ajouté


def test_fichiers_internes_non_executables_depuis_le_web(boutique):
    assert requests.get(f"{boutique}/inc/installer.php", timeout=5).status_code == 403


def test_en_tetes_de_securite_presents(boutique):
    r = requests.get(f"{boutique}/index.php", timeout=5)
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert "Content-Security-Policy" in r.headers


def test_photo_affichee_avec_son_credit_seulement_si_telechargee(tmp_path):
    site = tmp_path / "site"
    shutil.copytree(APP, site)
    base = tmp_path / "b.sqlite"
    (site / "config.php").write_text(f"<?php return ['dsn' => 'sqlite:{base}'];\n", encoding="utf-8")
    subprocess.run(["php", str(site / "inc" / "installer.php")], check=True, capture_output=True)
    (site / "img" / "produit-1.jpg").write_bytes(b"\xff\xd8\xff\xd9")      # seule la photo du câble est là
    port = _port_libre()
    serveur = subprocess.Popen(["php", "-S", f"127.0.0.1:{port}", "-t", str(site)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                page = requests.get(f"http://127.0.0.1:{port}", timeout=1).text
                break
            except requests.ConnectionError:
                time.sleep(0.1)
        assert '<img class="vignette" src="img/produit-1.jpg"' in page
        assert '<img class="vignette" src="img/produit-6.svg"' in page          # illustration du SSD
        assert page.count('<img class="vignette"') == 2 and '<div class="vignette">Réseau</div>' in page
        assert 'Photos libres de droits : <a href="https://www.pexels.com/photo/4716292/">Pexels, photo n° 4716292</a>.' in page
    finally:
        serveur.terminate()
        serveur.wait(timeout=5)
