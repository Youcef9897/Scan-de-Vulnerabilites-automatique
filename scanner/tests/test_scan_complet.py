"""Essai de bout en bout : faux site + faux outils, sans IA."""
import time

from vulnscan import config
from vulnscan.cible import preparer_cible
from vulnscan.scan import Scan


def test_scan_complet(faux_site, faux_outils, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DOSSIER_SCANS", tmp_path / "scans")
    monkeypatch.setattr(config, "IA_ACTIVE", False)
    cible = preparer_cible(faux_site, liste_blanche=["127.0.0.1"])

    debut = time.time()
    scan = Scan(cible)
    scan.executer()
    duree = time.time() - debut

    assert scan.erreur == ""
    r = scan.resultat
    # Les outils tournent en parallèle : la durée totale ≈ celle du plus lent (Nikto, 3 s)
    assert duree < 6, duree
    assert {"Nmap", "Nikto"} <= set(r["durees"])
    assert "SSLScan" not in r["durees"]           # site en HTTP : SSLScan n'est pas lancé
    assert r["resume_origine"] == "automatique"
    assert "faiblesse" in r["resume"]
    titres = [c["titre"] for c in r["constats"]]
    assert "Pas de protection contre le « clickjacking »" in titres
    assert any(t.startswith("Cookie « PHPSESSID »") for t in titres)
    debug = next(c for c in r["constats"] if c["titre"] == "Méthode DEBUG signalée par Nikto")
    assert debug["verification"] == "Faux positif probable"
    assert (scan.dossier / "resultat.json").exists()
    assert (scan.dossier / "nikto.txt").read_text().startswith("- Nikto v2.1.5")


def test_le_pdf_contient_le_perimetre(faux_site, faux_outils, tmp_path, monkeypatch):
    import shutil
    import subprocess
    import pytest
    from vulnscan.rapport_pdf import generer_pdf
    if shutil.which("pdftotext") is None:
        pytest.skip("pdftotext absent")
    monkeypatch.setattr(config, "DOSSIER_SCANS", tmp_path / "scans")
    monkeypatch.setattr(config, "IA_ACTIVE", False)
    scan = Scan(preparer_cible(faux_site, liste_blanche=["127.0.0.1"]))
    scan.executer()
    generer_pdf(scan.resultat, tmp_path / "rapport.pdf")
    texte = subprocess.run(["pdftotext", str(tmp_path / "rapport.pdf"), "-"], capture_output=True, text=True).stdout
    assert "Périmètre" in texte and "injection SQL" in texte
