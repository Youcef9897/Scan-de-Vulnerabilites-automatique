"""Tests de la plateforme web : liste blanche, case d'autorisation, rapport HTML et PDF."""
import time

import app as plateforme
from vulnscan import config


def _client(tmp_path, monkeypatch, liste):
    monkeypatch.setattr(config, "DOSSIER_SCANS", tmp_path / "scans")
    monkeypatch.setattr(config, "IA_ACTIVE", False)
    monkeypatch.setattr(config, "CIBLES_AUTORISEES", liste)
    plateforme.SCANS.clear()
    return plateforme.app.test_client()


def test_autorisation_obligatoire(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, ["127.0.0.1"])
    r = c.post("/scan", json={"cible": "http://127.0.0.1/", "autorisation": False})
    assert r.status_code == 400 and "autorisé" in r.get_json()["erreur"]


def test_cible_hors_liste_blanche(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, ["192.168.56.0/24"])
    r = c.post("/scan", json={"cible": "http://127.0.0.1/", "autorisation": True})
    assert r.status_code == 400 and "liste des cibles autorisées" in r.get_json()["erreur"]


def test_parcours_complet(faux_site, faux_outils, tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch, ["127.0.0.1"])
    assert c.get("/").status_code == 200

    r = c.post("/scan", json={"cible": faux_site, "autorisation": True})
    assert r.status_code == 200
    scan_id = r.get_json()["id"]

    # Un second scan pendant le premier est refusé
    assert c.post("/scan", json={"cible": faux_site, "autorisation": True}).status_code == 409

    for _ in range(30):
        etat = c.get(f"/scan/{scan_id}/etat").get_json()
        if etat["termine"]:
            break
        time.sleep(0.5)
    assert etat["termine"] and not etat["erreur"], etat

    page = c.get(f"/scan/{scan_id}").get_data(as_text=True)
    assert "Pas de protection contre le « clickjacking »" in page and "Faux positif probable" in page

    pdf = c.get(f"/scan/{scan_id}/pdf")
    assert pdf.status_code == 200 and pdf.data[:4] == b"%PDF"

    # Historique sur la page d'accueil, et identifiant invalide refusé
    assert faux_site in c.get("/").get_data(as_text=True)
    assert c.get("/scan/..%2F..%2Fetc").status_code == 404
