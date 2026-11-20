"""Tests de l'étape S3 : la boutique NetStock Lab contient bien ses failles volontaires.

La boutique est lancée avec le serveur intégré de PHP sur 127.0.0.1 et une base SQLite jetable.
Après la correction (S7-B), ces tests seront inversés : chaque attaque devra échouer.
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


def _connecter(s, url, email, mdp):
    return s.post(f"{url}/connexion.php", data={"email": email, "mot_de_passe": mdp}, timeout=5)


def _total(page):
    m = re.search(r'class="total"><td colspan="3">Total</td><td>(-?[\d ,]+) €', page)
    return float(m.group(1).replace(" ", "").replace(",", "."))


def test_catalogue_et_connexion_normale(boutique):
    s = requests.Session()
    page = s.get(boutique, timeout=5).text
    assert "Switch 8 ports Gigabit" in page and "volontairement vulnérable" in page
    assert "Commande n° 3" in _connecter(s, boutique, "alice@netstock.lab", "alice2027").text
    assert "incorrect" in _connecter(requests.Session(), boutique, "alice@netstock.lab", "mauvais").text


def test_injection_sql_a_la_connexion(boutique):
    s = requests.Session()
    page = _connecter(s, boutique, "' OR '1'='1' -- ", "nimporte").text
    assert "Connecté en tant que Alice Martin" in page


def test_erreur_sql_affichee(boutique):
    page = _connecter(requests.Session(), boutique, "'", "x").text
    assert "Erreur SQL" in page


def test_xss_reflechi_dans_la_recherche(boutique):
    charge = "<script>alert('lab')</script>"
    page = requests.get(boutique, params={"q": charge}, timeout=5).text
    assert charge in page                                    # réaffiché sans échappement


def test_prix_modifie_par_le_navigateur(boutique):
    s = requests.Session()
    s.post(f"{boutique}/panier.php", data={"action": "ajouter", "produit_id": 4, "prix": "0.01", "quantite": 1})
    page = s.get(f"{boutique}/panier.php", timeout=5).text
    assert "Point d&#039;accès Wi-Fi 6" in page and _total(page) == 0.01   # au lieu de 89,90 €


def test_quantite_negative_et_code_promo_reutilise(boutique):
    s = requests.Session()
    s.post(f"{boutique}/panier.php", data={"action": "ajouter", "produit_id": 6, "prix": "79.90", "quantite": 1})
    s.post(f"{boutique}/panier.php", data={"action": "ajouter", "produit_id": 1, "prix": "6.90", "quantite": -5})
    for _ in range(3):
        s.post(f"{boutique}/panier.php", data={"action": "code", "code": "BIENVENUE10"})
    page = s.get(f"{boutique}/panier.php", timeout=5).text
    assert _total(page) == pytest.approx(79.90 - 5 * 6.90 - 30)          # 15,40 € au lieu de 79,90 €

    _connecter(s, boutique, "bob@netstock.lab", "bob2027")
    commande = s.post(f"{boutique}/panier.php", data={"action": "commander"}, timeout=5)
    assert "Commande n° 4" in commande.text and "15,40 €" in commande.text


def test_commande_d_un_autre_client_visible(boutique):
    s = requests.Session()
    _connecter(s, boutique, "alice@netstock.lab", "alice2027")
    page = s.get(f"{boutique}/commande.php", params={"id": 1}, timeout=5).text   # commande de Bob
    assert "Bob Durand" in page and "8 avenue Imaginaire" in page


def test_fichiers_internes_non_executables_depuis_le_web(boutique):
    # L'installateur refuse de tourner hors ligne de commande (la protection Apache s'ajoute dans la VM).
    assert requests.get(f"{boutique}/inc/installer.php", timeout=5).status_code == 403


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
