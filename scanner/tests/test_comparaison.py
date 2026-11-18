"""Tests de l'étape S8 : comparaison de deux analyses (avant / après corrections)."""
import json

import app as plateforme
from vulnscan import config
from vulnscan.comparaison import comparer, points
from vulnscan.score import calculer
from vulnscan.constats import Constat


def _c(code, titre, gravite, verification="Confirmé"):
    return {"code": code, "titre": titre, "gravite": gravite, "verification": verification,
            "categorie": "", "recommandation": "", "description": "", "preuves": [], "sources": [], "reference": ""}


def _resultat(scan_id, constats, url="http://localhost/mon-site/"):
    objets = [Constat(titre=c["titre"], gravite=c["gravite"], categorie="", description="", recommandation="",
                      verification=c["verification"]) for c in constats]
    return {"id": scan_id, "date": scan_id[:8], "cible": {"url": url}, "score": calculer(objets), "constats": constats}


# Les constats du vrai scan « avant » du 16/11/2026 (score 51)
AVANT = _resultat("20261116-220036-localhost-8933", [
    _c("C01", "Code source ou copie de sauvegarde téléchargeable", "Moyenne"),
    _c("C02", "Listage du contenu d'un dossier", "Moyenne"),
    _c("C03", "Pas de protection contre le « clickjacking »", "Moyenne"),
    _c("C04", "Site disponible uniquement en HTTP (pas de HTTPS)", "Moyenne"),
    _c("C05", "85 CVE connue(s) pour Apache httpd 2.4.52 (Ubuntu) (port 80)", "Moyenne", "À vérifier"),
    _c("C06", "En-tête X-Content-Type-Options absent", "Faible"),
    _c("C07", "Pas de politique de sécurité du contenu (CSP)", "Faible"),
    _c("C08", "Version du serveur web affichée", "Faible"),
    _c("C09", "En-têtes de confidentialité recommandés absents", "Info"),
    _c("C14", "Fuite d'inode par l'en-tête ETag signalée par Nikto", "Info", "Faux positif probable"),
])

# Un « après » plausible : en-têtes ajoutés, listage coupé, v1 déplacée, HTTPS pas encore fait
APRES = _resultat("20261117-101500-localhost-1a2b", [
    _c("C01", "Site disponible uniquement en HTTP (pas de HTTPS)", "Moyenne"),
    _c("C02", "84 CVE connue(s) pour Apache httpd 2.4.52 (Ubuntu) (port 80)", "Moyenne", "À vérifier"),
    _c("C03", "Méthode TRACE activée", "Faible"),
    _c("C04", "Informations internes divulguées par l'en-tête ETag", "Info"),
])


def test_score_avant_est_bien_51():
    assert AVANT["score"]["score"] == 51


def test_statut_de_chaque_constat():
    c = comparer(AVANT, APRES)
    statuts = {l["titre"]: l["statut"] for l in c["lignes"]}
    assert statuts["Code source ou copie de sauvegarde téléchargeable"] == "Corrigé"
    assert statuts["Version du serveur web affichée"] == "Corrigé"
    assert statuts["Site disponible uniquement en HTTP (pas de HTTPS)"] == "Toujours présent"
    # Le nombre de CVE change, mais c'est le même constat
    assert statuts["84 CVE connue(s) pour Apache httpd 2.4.52 (Ubuntu) (port 80)"] == "Toujours présent"
    assert statuts["Méthode TRACE activée"] == "Nouveau"
    # L'ETag est en Info dans les deux : il ne change pas le score, il n'est pas listé
    assert not any("etag" in t.lower() for t in statuts)
    assert c["comptes"] == {"Corrigé": 6, "Atténué": 0, "Plus vérifiable": 0, "Nouveau": 1, "Aggravé": 0,
                            "Toujours présent": 2}


def test_ecart_et_bilan():
    c = comparer(AVANT, APRES)
    assert c["apres"]["score"] == 100 - 8 - 8 - 3 == 81
    assert c["ecart"] == 30 and c["meme_cible"]
    assert c["bilan"].startswith("Le score passe de 51 à 81/100 (+30 points) : 6 constat(s) corrigé(s)")
    # La somme des points regagnés et perdus redonne l'écart de score
    assert sum(l["gain"] for l in c["lignes"]) == c["ecart"]


def test_ordre_remis_dans_le_temps():
    c = comparer(APRES, AVANT)
    assert c["avant"]["score"] == 51 and c["apres"]["score"] == 81


def test_passage_en_faux_positif_est_une_attenuation():
    a = _resultat("20261116-000000-x-0001", [_c("C01", "Méthode TRACE activée", "Faible")])
    b = _resultat("20261117-000000-x-0002", [_c("C01", "Méthode TRACE activée", "Faible", "Faux positif probable")])
    l = comparer(a, b)["lignes"][0]
    assert l["statut"] == "Atténué" and l["gain"] == 3 and points(b["constats"][0]) == 0


def test_cve_disparues_avec_la_version_masquee_ne_sont_pas_dites_corrigees():
    """Cas réel du 16/11 : après « ServerTokens Prod », Nmap ne lit plus la version d'Apache, donc plus de CVE."""
    cve = _c("C05", "85 CVE connue(s) pour Apache httpd 2.4.52 (Ubuntu) (port 80)", "Moyenne", "À vérifier")
    avant = _resultat("20261116-220036-localhost-8933", [cve])

    def apres(port):
        return {**_resultat("20261116-232825-localhost-0f75", []), "ports": [port] if port else []}

    masque = comparer(avant, apres({"numero": 80, "etat": "open", "version": "Apache httpd"}))
    assert masque["lignes"][0]["statut"] == "Plus vérifiable" and masque["lignes"][0]["gain"] == 8
    assert "1 plus vérifiable(s)" in masque["bilan"] and "pas la preuve d'une mise à jour" in masque["note_version"]
    # Version toujours lisible et plus de CVE (paquet mis à jour), ou port fermé : c'est bien une correction
    a_jour = comparer(avant, apres({"numero": 80, "etat": "open", "version": "Apache httpd 2.4.62 (Ubuntu)"}))
    ferme = comparer(avant, apres({"numero": 80, "etat": "closed", "version": ""}))
    assert a_jour["lignes"][0]["statut"] == ferme["lignes"][0]["statut"] == "Corrigé"
    assert a_jour["note_version"] == "" and comparer(avant, apres(None))["lignes"][0]["statut"] == "Corrigé"


def test_cibles_differentes_signalees():
    b = _resultat("20261117-000000-x-0002", [], url="http://192.168.56.10/")
    assert comparer(AVANT, b)["meme_cible"] is False


def _client(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DOSSIER_SCANS", tmp_path / "scans")
    for r in (AVANT, APRES):
        d = tmp_path / "scans" / r["id"]
        d.mkdir(parents=True)
        (d / "resultat.json").write_text(json.dumps(r, ensure_ascii=False), encoding="utf-8")
    plateforme.SCANS.clear()
    return plateforme.app.test_client()


def test_page_et_pdf_de_comparaison(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    accueil = c.get("/").get_data(as_text=True)
    assert "Comparer deux analyses" in accueil

    page = c.get(f"/comparer?avant={AVANT['id']}&apres={APRES['id']}")
    texte = page.get_data(as_text=True)
    assert page.status_code == 200 and "+30" in texte and "Corrigé" in texte and "Nouveau" in texte

    pdf = c.get(f"/comparer/pdf?avant={AVANT['id']}&apres={APRES['id']}")
    assert pdf.status_code == 200 and pdf.data[:4] == b"%PDF"


def test_comparaison_refusee_si_identifiants_invalides(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    assert c.get(f"/comparer?avant={AVANT['id']}&apres={AVANT['id']}").status_code == 400
    assert c.get(f"/comparer?avant={AVANT['id']}&apres=..%2F..%2Fetc").status_code == 404
    assert c.get("/comparer").status_code == 400


def test_choix_par_defaut_plus_ancienne_analyse_du_meme_site(tmp_path, monkeypatch):
    c = _client(tmp_path, monkeypatch)
    page = c.get("/").get_data(as_text=True)
    assert f'<option value="{AVANT["id"]}" selected>' in page          # avant : la plus ancienne
    assert page.count(" selected>") == 2
