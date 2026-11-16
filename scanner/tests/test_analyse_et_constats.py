"""Tests de la lecture des sorties d'outils et de la construction des constats."""
from pathlib import Path

import pytest

from vulnscan import analyse, constats, score
from vulnscan.cible import Cible, CibleRefusee, est_autorisee, preparer_cible

DONNEES = Path(__file__).resolve().parent / "donnees"


def test_lecture_nmap_xml():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vm.xml")
    assert [p.numero for p in ports] == [80, 443, 631, 3306]
    assert ports[0].version == "Apache httpd 2.4.52 (Ubuntu)"
    assert ports[1].etat == "closed"


def test_lecture_nikto():
    n = analyse.lire_nikto((DONNEES / "nikto_vm.txt").read_text())
    assert n["banniere"] == "Apache/2.4.52 (Ubuntu)"
    assert n["elements_testes"] == 21
    assert not any(l.startswith(("Target", "Start Time", "No CGI")) for l in n["constats"])
    assert any("X-Frame-Options" in l for l in n["constats"])


def test_lecture_sslscan():
    s = analyse.lire_sslscan((DONNEES / "sslscan_exemple.txt").read_text())
    assert s["protocoles"]["TLSv1.0"] is True and s["protocoles"]["SSLv3"] is False
    assert "RC4-SHA" in s["chiffrements_faibles"]
    assert s["taille_cle_rsa"] == 1024


def _cible_locale():
    return Cible(url="http://localhost/mon-site/", schema="http", hote="localhost", port=80, adresses=["127.0.0.1"])


def _obs_vm():
    """Ce que la vérification directe observe sur le site de la VM."""
    return {"accessible": True, "protection_cadres": False,
            "entetes_absents": ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options",
                                "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"],
            "serveur": "Apache/2.4.52 (Ubuntu)", "powered_by": "",
            "cookies": [{"nom": "PHPSESSID", "httponly": False, "secure": False, "samesite": False,
                         "brut": "PHPSESSID=abc; path=/"}],
            "methodes_annoncees": "GET,POST,OPTIONS,HEAD", "trace_active": False,
            "debug_code": 405, "debug_accepte": False, "https_disponible": False, "redirige_vers_https": False}


def test_constats_site_vm():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vm.xml")
    nikto = analyse.lire_nikto((DONNEES / "nikto_vm.txt").read_text())
    liste = constats.construire(_cible_locale(), ports, nikto, analyse.lire_sslscan(""), _obs_vm())
    titres = {c.titre: c for c in liste}

    # Les vrais problèmes du site sont trouvés et confirmés
    assert titres["Pas de protection contre le « clickjacking »"].verification == constats.CONFIRME
    assert titres["Site disponible uniquement en HTTP (pas de HTTPS)"].gravite == "Moyenne"
    cookie = titres["Cookie « PHPSESSID » sans protection (HttpOnly, SameSite)"]
    assert cookie.gravite == "Moyenne" and "Nikto" in cookie.sources

    # Le faux positif DEBUG est reconnu comme tel
    debug = titres["Méthode DEBUG signalée par Nikto"]
    assert debug.verification == constats.FAUX_POSITIF and debug.gravite == "Info"

    # Scan lancé depuis la machine elle-même : MySQL est rabaissé et marqué « à vérifier »
    mysql = titres["Port 3306 ouvert : base de données MySQL/MariaDB"]
    assert mysql.gravite == "Moyenne" and mysql.verification == constats.NON_VERIFIABLE

    # Le cookie « security » vu seulement par Nikto est signalé comme non confirmé
    assert titres["Cookie « security » sans attribut HttpOnly (signalé par Nikto)"].verification == constats.NON_CONFIRME

    # Tri : gravité décroissante, codes C01, C02…
    assert [c.code for c in liste][:2] == ["C01", "C02"]
    ordre = [constats.GRAVITES.index(c.gravite) for c in liste]
    assert ordre == sorted(ordre)


def test_meme_site_scanne_depuis_le_reseau_est_plus_grave():
    cible = Cible(url="http://192.168.56.20/", schema="http", hote="192.168.56.20", port=80, adresses=["192.168.56.20"])
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vm.xml")
    liste = constats.construire(cible, ports, analyse.lire_nikto(""), analyse.lire_sslscan(""), _obs_vm())
    mysql = next(c for c in liste if "3306" in c.titre)
    assert mysql.gravite == "Élevée" and mysql.verification == constats.CONFIRME
    assert liste[0] is mysql


def test_constats_tls():
    s = analyse.lire_sslscan((DONNEES / "sslscan_exemple.txt").read_text())
    liste = constats.constats_tls(s, {"certificat_valide": False})
    titres = " | ".join(c.titre for c in liste)
    assert "TLSv1.0, TLSv1.1" in titres and "faibles" in titres and "1024" in titres and "Certificat" in titres


def test_score_ignore_faux_positifs():
    c1 = constats.Constat("A", "Élevée", "x", "d", "r")
    c2 = constats.Constat("B", "Moyenne", "x", "d", "r", verification=constats.FAUX_POSITIF)
    c3 = constats.Constat("C", "Faible", "x", "d", "r")
    s = score.calculer([c1, c2, c3])
    assert s["score"] == 77 and s["niveau"] == "Correct"


def test_liste_blanche():
    assert est_autorisee("localhost", ["127.0.0.1"], ["localhost"])
    assert est_autorisee("vm", ["192.168.56.12"], ["192.168.56.0/24"])
    assert not est_autorisee("exemple.com", ["93.184.215.14"], ["localhost", "192.168.56.0/24"])


def test_cible_hors_liste_refusee():
    with pytest.raises(CibleRefusee, match="liste des cibles autorisées"):
        preparer_cible("http://127.0.0.1/", liste_blanche=["192.168.56.0/24"], verifier_acces=False)
