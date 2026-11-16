"""Tests de l'étape S4-B : ZAP en mode passif.

`donnees/zap_exemple.json` est un exemple écrit à la main au format « traditional-json » de ZAP, sur le modèle
du site de la VM. Il contient exprès : des alertes déjà trouvées par la plateforme (doublons), des alertes
nouvelles, une alerte d'information à ignorer, un faux positif de ZAP, une règle inventée (99999) sans fiche
en français, et un second site hors périmètre.
"""
import json
import os
import stat
import sys
from pathlib import Path

from vulnscan import config, zap
from vulnscan.cible import Cible, preparer_cible
from vulnscan.constats import CONFIRME, NON_VERIFIABLE, Constat, constats_zap, construire
from vulnscan.regles_zap import FICHES, IGNOREES
from vulnscan.scan import Scan
from vulnscan.score import calculer

EXEMPLE = Path(__file__).resolve().parent / "donnees" / "zap_exemple.json"
CIBLE = Cible(url="http://localhost/mon-site/", schema="http", hote="localhost", port=80, adresses=["127.0.0.1"])


def _alertes():
    return zap.lire_rapport(EXEMPLE, CIBLE)["alertes"]


def _existants():
    """Ce que la plateforme trouve déjà sans ZAP sur le site de la VM (titres réels)."""
    def c(titre, gravite):
        return Constat(titre=titre, gravite=gravite, categorie="", description="", recommandation="",
                       preuves=["Vérification : …"], sources=["Vérification"])
    return [c("Listage du contenu d'un dossier", "Moyenne"),
            c("Pas de protection contre le « clickjacking »", "Moyenne"),
            c("En-tête X-Content-Type-Options absent", "Faible"),
            c("Pas de politique de sécurité du contenu (CSP)", "Faible"),
            c("Version du serveur web affichée", "Faible"),
            c("Cookie « PHPSESSID » sans protection (HttpOnly, SameSite)", "Moyenne")]


# ---------------------------------------------------------------- Réglages et plan

def test_zap_est_desactive_par_defaut():
    assert os.environ.get("ZAP_ACTIF") is None and config.ZAP_ACTIF is False


def test_plan_passif_uniquement(tmp_path):
    texte = zap.plan(CIBLE, tmp_path)
    assert "activeScan" not in texte.replace("aucune tâche activeScan", "")   # seule mention : le commentaire
    assert "postForm: false" in texte and "type: passiveScan-wait" in texte
    assert "template: 'traditional-json'" in texte and "reportFile: 'zap.json'" in texte
    assert r"- 'http://localhost/mon\-site/.*'" in texte          # ZAP reste dans le dossier analysé
    assert f"reportDir: '{tmp_path.resolve()}'" in texte


def test_plan_reste_dans_le_dossier_de_la_page_et_protege_les_apostrophes(tmp_path):
    cible = Cible(url="http://localhost/bout'ique/index.php", schema="http", hote="localhost", port=80,
                  adresses=["127.0.0.1"])
    texte = zap.plan(cible, tmp_path)
    assert "- 'http://localhost/bout''ique/index.php'" in texte
    assert zap.base_du_site(cible.url) == "http://localhost/bout'ique/"
    assert zap.base_du_site("http://localhost") == "http://localhost/"


def test_commande_en_local_et_sans_interface(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "ZAP_COMMANDE", "zaproxy")
    cmd = zap.commande(tmp_path / "zap-plan.yaml")
    assert cmd[:4] == ["zaproxy", "-cmd", "-silent", "-autorun"]
    assert cmd[cmd.index("-host") + 1] == "127.0.0.1" and "-daemon" not in cmd


# ---------------------------------------------------------------- Lecture du rapport

def test_lecture_du_rapport():
    r = zap.lire_rapport(EXEMPLE, CIBLE)
    assert r["erreur"] == "" and r["version"] == "2.16.1"
    refs = [a["ref"] for a in r["alertes"]]
    assert "10020-1" in refs and "10202" in refs and "99999" in refs
    assert "10015" not in refs                       # confiance « False Positive » : écartée
    assert "10109" not in refs and r["ignorees"] == ["Modern Web Application"]
    assert "10035-1" not in refs and r["hors_site"] == 2          # fonts.googleapis.com : hors du site analysé
    assert refs[0].startswith("10020") or r["alertes"][0]["risque"] == 2   # triées par risque décroissant
    clic = next(a for a in r["alertes"] if a["ref"] == "10020-1")
    assert len(clic["instances"]) == 3 and clic["risque"] == 2 and clic["cwe"] == 1021
    assert "<p>" not in clic["description"] and clic["description"].startswith("The response does not protect")
    nosniff = next(a for a in r["alertes"] if a["ref"] == "10021")
    assert all(i["uri"].startswith("http://localhost/") for i in nosniff["instances"])


def test_lecture_accepte_127_0_0_1_pour_localhost():
    texte = EXEMPLE.read_text(encoding="utf-8").replace("http://localhost/", "http://127.0.0.1/")
    assert len(zap.lire_rapport(texte, CIBLE)["alertes"]) == len(_alertes())


def test_rapport_absent_vide_ou_abime(tmp_path):
    assert "introuvable" in zap.lire_rapport(tmp_path / "absent.json")["erreur"]
    for texte in ("", "{pas du json", "[1, 2]"):
        r = zap.lire_rapport(texte)
        assert r["alertes"] == [] and "illisible" in r["erreur"]
    # Champs manquants ou d'un type inattendu : pas d'erreur, l'alerte incomplète est écartée
    r = zap.lire_rapport(json.dumps({"site": {"alerts": [{"pluginid": 10021, "riskcode": "x", "instances": None},
                                                         "texte", {"alert": "Sans page", "instances": []}]}}))
    assert r == {"version": "", "alertes": [], "ignorees": [], "hors_site": 0, "erreur": ""}


# ---------------------------------------------------------------- Constats

def test_pas_de_doublon_avec_les_constats_existants():
    existants = _existants()
    score_avant = calculer(existants)["score"]
    nouveaux = constats_zap(_alertes(), existants)
    titres = [c.titre for c in nouveaux]
    for deja in ("clickjacking", "X-Content-Type-Options", "CSP", "Version du serveur", "Listage"):
        assert not any(deja in t for t in titres), (deja, titres)
    # Les constats existants gardent leur gravité et reçoivent la preuve de ZAP
    assert calculer(existants)["score"] == score_avant
    clic = next(c for c in existants if "clickjacking" in c.titre)
    assert clic.sources == ["Vérification", "ZAP"] and "Missing Anti-clickjacking Header — vu sur 3 page(s)" in clic.preuves[-1]
    # Le cookie PHPSESSID est signalé par deux règles de ZAP : toujours un seul constat
    cookie = next(c for c in existants if "PHPSESSID" in c.titre)
    assert cookie.sources.count("ZAP") == 1 and not any("PHPSESSID" in t for t in titres)
    assert [p.split(" — ")[0] for p in cookie.preuves[1:]] == ["ZAP : Cookie No HttpOnly Flag",
                                                              "ZAP : Cookie without SameSite Attribute"]


def test_constats_nouveaux_en_francais():
    nouveaux = {c.titre: c for c in constats_zap(_alertes(), _existants())}
    csrf = nouveaux["Formulaire sans jeton anti-CSRF"]
    # Confiance faible côté ZAP : un cran en dessous de la fiche (Moyenne), et à vérifier à la main
    assert (csrf.gravite, csrf.verification, csrf.sources) == ("Faible", NON_VERIFIABLE, ["ZAP"])
    assert "login.html" in csrf.preuves[0] and "jeton" in csrf.recommandation
    assert 'preuve : <form action="login.html" method="post">' in csrf.preuves[0]     # extrait de page gardé tel quel
    # Un cookie que seul ZAP a vu, sur une autre page : un constat à son nom, confirmé (fait lu dans la réponse)
    panier = nouveaux["Cookie « panier » sans attribut HttpOnly (vu par ZAP)"]
    assert (panier.gravite, panier.verification) == ("Faible", CONFIRME)
    assert nouveaux["Horodatage visible dans une page"].gravite == "Info"
    assert nouveaux["Commentaires à relire dans le code des pages"].verification == NON_VERIFIABLE


def test_regle_sans_fiche_reste_a_verifier_un_cran_en_dessous():
    inconnu = next(c for c in constats_zap(_alertes(), _existants()) if c.titre.startswith("ZAP : "))
    assert inconnu.titre == "ZAP : Hypothetical New Passive Rule"
    assert (inconnu.gravite, inconnu.verification, inconnu.categorie) == ("Faible", NON_VERIFIABLE, "À examiner")
    assert "CWE-200" in inconnu.reference and "99999" in inconnu.reference


def test_sans_constat_existant_zap_cree_le_constat_une_seule_fois():
    """Si la page d'accueil est protégée mais pas les autres, seul ZAP voit le problème."""
    nouveaux = constats_zap(_alertes(), [])
    clic = [c for c in nouveaux if "clickjacking" in c.titre]
    assert len(clic) == 1 and (clic[0].gravite, clic[0].verification) == ("Moyenne", CONFIRME)
    assert len(clic[0].preuves) == 3
    assert len([c for c in nouveaux if c.titre.startswith("Cookie « PHPSESSID »")]) == 1
    nosniff = next(c for c in nouveaux if "X-Content-Type-Options" in c.titre)
    assert nosniff.preuves[-1] == "ZAP : … et 1 autre(s) page(s)"            # 6 pages, 5 affichées


def test_fiches_bien_formees():
    for ref, f in FICHES.items():
        assert f["gravite"] in ("Élevée", "Moyenne", "Faible", "Info", None), ref
        assert f["titre"] and f["description"] and f["recommandation"], ref
    assert not set(IGNOREES) & set(FICHES)


def test_construire_sans_zap_ne_change_rien():
    vide = {"constats": [], "banniere": "", "elements_testes": 0}
    obs = {"accessible": False}
    assert [c.titre for c in construire(CIBLE, [], vide, {}, obs)] == \
           [c.titre for c in construire(CIBLE, [], vide, {}, obs, zap=None)]


# ---------------------------------------------------------------- Analyse complète avec un faux ZAP

def _faux_zap(dossier: Path):
    """Faux « zaproxy » : lit le plan, attend 1 s et écrit l'exemple de rapport à l'endroit demandé."""
    f = dossier / "zaproxy"
    f.write_text(f"""#!{sys.executable}
import re, sys, time
from pathlib import Path
plan = Path(sys.argv[sys.argv.index("-autorun") + 1]).read_text()
lire = lambda cle: re.search(cle + r": '(.*)'", plan).group(1)
site = re.match(r"https?://[^/]+", lire("url")).group(0)
time.sleep(1)
rapport = Path({str(EXEMPLE)!r}).read_text().replace("http://localhost", site)
(Path(lire("reportDir")) / lire("reportFile")).write_text(rapport)
print("Job spider started\\nJob report finished\\nAutomation plan succeeded!")
""")
    f.chmod(f.stat().st_mode | stat.S_IEXEC)


def _regler(tmp_path, monkeypatch, actif=True):
    monkeypatch.setattr(config, "DOSSIER_SCANS", tmp_path / "scans")
    monkeypatch.setattr(config, "IA_ACTIVE", False)
    monkeypatch.setattr(config, "ZAP_ACTIF", actif)
    monkeypatch.setattr(config, "ZAP_COMMANDE", "zaproxy")
    monkeypatch.setattr(config, "ZAP_DOSSIER", tmp_path / "zap-home")


def test_scan_complet_avec_zap(faux_site, faux_outils, tmp_path, monkeypatch):
    _faux_zap(faux_outils)
    _regler(tmp_path, monkeypatch)
    scan = Scan(preparer_cible(faux_site, liste_blanche=["127.0.0.1"]))
    scan.executer()
    r = scan.resultat
    assert scan.erreur == "" and "ZAP" not in r["erreurs_outils"]
    assert r["zap"] == {"alertes": 11, "ignorees": ["Modern Web Application"], "hors_site": 2}
    assert r["versions"]["ZAP"] == "ZAP 2.16.1" and "ZAP" in r["durees"]
    assert r["commandes"]["ZAP"].startswith("zaproxy -cmd -silent -autorun zap-plan.yaml -dir zap-home")
    titres = [c["titre"] for c in r["constats"]]
    assert len(titres) == len(set(titres))                                    # aucun doublon
    assert "Formulaire sans jeton anti-CSRF" in titres
    clic = next(c for c in r["constats"] if "clickjacking" in c["titre"])
    assert "ZAP" in clic["sources"] and "Vérification" in clic["sources"]
    assert len([t for t in titres if "PHPSESSID" in t]) == 1
    assert (scan.dossier / "zap.json").exists() and (scan.dossier / "zap-plan.yaml").exists()

    # Le rapport HTML et le PDF affichent ZAP dans la méthodologie
    import app as plateforme
    client = plateforme.app.test_client()
    page = client.get(f"/scan/{scan.id}").get_data(as_text=True)
    assert "ZAP, analyse passive (11 alerte(s) retenue(s), 1 d'information ignorée(s))" in page
    assert "ZAP 2.16.1" in page and "Formulaire sans jeton anti-CSRF" in page
    # Un extrait de page cité en preuve est affiché comme du texte, jamais interprété par le navigateur
    assert "&lt;form action=" in page and '<form action="login.html"' not in page
    pdf = client.get(f"/scan/{scan.id}/pdf")
    assert pdf.status_code == 200 and pdf.data[:4] == b"%PDF"


def test_comparaison_signale_des_outils_differents():
    from vulnscan.comparaison import comparer
    def r(scan_id, avec_zap):
        return {"id": scan_id, "date": "", "cible": {"url": "http://localhost/"}, "constats": [],
                "score": calculer([]), "zap": {"alertes": 3} if avec_zap else None}
    assert comparer(r("20261116-000000-x-0001", False), r("20261117-000000-x-0002", True))["memes_outils"] is False
    assert comparer(r("20261116-000000-x-0001", True), r("20261117-000000-x-0002", True))["memes_outils"] is True
    assert comparer(r("20261116-000000-x-0001", False), {**r("20261117-000000-x-0002", False), "zap": None})["memes_outils"]


def test_scan_sans_zap_par_defaut(faux_site, faux_outils, tmp_path, monkeypatch):
    _faux_zap(faux_outils)
    _regler(tmp_path, monkeypatch, actif=False)
    scan = Scan(preparer_cible(faux_site, liste_blanche=["127.0.0.1"]))
    scan.executer()
    assert scan.resultat["zap"] is None and "ZAP" not in scan.resultat["durees"]
    assert not any("ZAP" in c["sources"] for c in scan.resultat["constats"])
    assert not (scan.dossier / "zap-plan.yaml").exists()


def test_zap_absent_ne_bloque_pas_le_scan(faux_site, faux_outils, tmp_path, monkeypatch):
    _regler(tmp_path, monkeypatch)
    monkeypatch.setattr(config, "ZAP_COMMANDE", "zap-introuvable")
    scan = Scan(preparer_cible(faux_site, liste_blanche=["127.0.0.1"]))
    scan.executer()
    assert scan.erreur == "" and scan.resultat["zap"] is None
    assert "n'est pas installé" in scan.resultat["erreurs_outils"]["ZAP"]
    assert any("clickjacking" in c["titre"] for c in scan.resultat["constats"])
