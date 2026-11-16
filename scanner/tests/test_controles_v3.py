"""Contrôles ajoutés à la v3 : chemins sensibles, écoute locale, ETag, versions des outils, CVE."""
from pathlib import Path

from conftest import FauxSiteFragile
from vulnscan import analyse, chemins, config, constats, ecoute, outils, score
from vulnscan.cible import Cible

DONNEES = Path(__file__).resolve().parent / "donnees"

# Sortie réelle de `ss -H -tln` sur la VM du projet (16/11/2026), plus une ligne « exposée ».
SS_VM = """\
LISTEN 0      128        127.0.0.1:631        0.0.0.0:*
LISTEN 0      80         127.0.0.1:3306       0.0.0.0:*
LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*
LISTEN 0      128            [::1]:631           [::]:*
LISTEN 0      511                *:80               *:*
LISTEN 0      128          0.0.0.0:22         0.0.0.0:*
"""


def _cible(url):
    p = url.split("/")[2]
    hote, port = p.split(":")
    return Cible(url=url, schema="http", hote=hote, port=int(port), adresses=["127.0.0.1"])


def _cible_locale():
    return Cible(url="http://localhost/mon-site/", schema="http", hote="localhost", port=80, adresses=["127.0.0.1"])


# ------------------------------------------------------------------ 1. chemins sensibles

def test_chemins_sensibles_trouves(site_fragile, monkeypatch):
    monkeypatch.setattr(config, "CHEMINS_SUPPLEMENTAIRES", ["scanner-auto/"])
    page = FauxSiteFragile.PAGES["/mon-site/"][1]
    ch = chemins.controler(_cible(site_fragile), page)

    assert ch["ignore"] == ""
    # Dossiers listés : ceux des liens de la page (assets/, assets/img/, assets/css/) et celui ajouté à la main
    assert {"assets/", "assets/img/", "assets/css/", "scanner-auto/"} <= set(ch["listages"])
    sources = {e["chemin"] for e in ch["sources"]}
    assert {"scanner-auto/app.py", "scanner-auto/app.py.bak", "login.html.bak"} <= sources
    assert ch["secrets"] == []                      # aucun .env ni .git sur ce site
    assert ch["admin"] == ["admin/"]
    assert ch["requetes"] <= config.CHEMINS_MAX_REQUETES

    # Prudence : rien n'est demandé en dehors de l'adresse analysée
    assert all(d.startswith("/mon-site/") for d in FauxSiteFragile.demandes)

    titres = {c.titre: c for c in constats.constats_chemins(ch)}
    assert titres["Code source ou copie de sauvegarde téléchargeable"].gravite == "Moyenne"
    assert titres["Listage du contenu d'un dossier"].verification == constats.CONFIRME
    assert titres["Zone d'administration joignable"].verification == constats.NON_VERIFIABLE


def test_chemins_budget_de_requetes(site_fragile, monkeypatch):
    monkeypatch.setattr(config, "CHEMINS_MAX_REQUETES", 5)
    ch = chemins.controler(_cible(site_fragile), FauxSiteFragile.PAGES["/mon-site/"][1])
    assert ch["requetes"] == 5 and len(FauxSiteFragile.demandes) == 5


def test_chemins_site_qui_repond_toujours_200(faux_site):
    """Un site qui renvoie 200 pour tout : on ne conclut rien plutôt que d'inventer des fichiers."""
    ch = chemins.controler(_cible(faux_site), "")
    assert "pas fiable" in ch["ignore"] and ch["requetes"] == 1
    assert constats.constats_chemins(ch) == []


def test_classement_des_fichiers():
    assert chemins.classer(".env") == "secret" and chemins.classer("dump.sql") == "secret"
    assert chemins.classer("app.py.bak") == "source" and chemins.classer("index.html~") == "source"
    assert chemins.classer("jean1.jpg") is None and chemins.classer("style.css") is None


# ------------------------------------------------------------------ 2. écoute locale

def test_lecture_ss():
    e = ecoute.lire_ss(SS_VM)
    assert e[3306] == {"127.0.0.1"} and e[631] == {"127.0.0.1", "::1"} and e[53] == {"127.0.0.53"}
    assert ecoute.locale_uniquement(e[3306]) and ecoute.locale_uniquement(e[631])
    assert not ecoute.locale_uniquement(e[80]) and not ecoute.locale_uniquement(e[22])
    assert not ecoute.locale_uniquement(set())


def test_port_en_ecoute_locale_ne_retire_aucun_point():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vm.xml")
    liste = constats.constats_reseau(_cible_locale(), ports, ecoute.lire_ss(SS_VM))
    mysql = next(c for c in liste if "3306" in c.titre)
    assert mysql.titre.startswith("Port 3306 en écoute locale uniquement")
    assert mysql.gravite == "Info" and mysql.verification == constats.CONFIRME
    assert any(p.startswith("ss : écoute sur 127.0.0.1:3306") for p in mysql.preuves)
    assert score.calculer([mysql])["score"] == 100


def test_port_ecoutant_sur_le_reseau_reste_grave():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vm.xml")
    liste = constats.constats_reseau(_cible_locale(), ports, {3306: {"0.0.0.0"}})
    mysql = next(c for c in liste if "3306" in c.titre)
    assert mysql.gravite == "Élevée" and mysql.verification == constats.CONFIRME


def test_sans_ss_on_garde_a_verifier():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vm.xml")
    mysql = next(c for c in constats.constats_reseau(_cible_locale(), ports, None) if "3306" in c.titre)
    assert mysql.gravite == "Moyenne" and mysql.verification == constats.NON_VERIFIABLE


# ------------------------------------------------------------------ 3. ETag

LIGNE_ETAG_VM = "Server leaks inodes via ETags, header found with file /mon-site/, fields: 0x875 0x6552d7e58b4d0"


def _web(nikto_lignes, obs=None):
    base = {"accessible": True, "protection_cadres": True, "entetes_absents": [], "serveur": "", "powered_by": "",
            "cookies": [], "methodes_annoncees": "", "https_disponible": True, "redirige_vers_https": True}
    base.update(obs or {})
    nikto = {"banniere": "", "constats": nikto_lignes, "elements_testes": 21}
    cible = Cible(url="https://localhost/", schema="https", hote="localhost", port=443, adresses=["127.0.0.1"])
    return constats.constats_web(cible, nikto, base, [])


def test_etag_a_deux_champs_est_un_faux_positif():
    (c,) = [c for c in _web([LIGNE_ETAG_VM]) if "ETag" in c.titre]
    assert c.verification == constats.FAUX_POSITIF and c.gravite == "Info"
    assert score.calculer([c])["score"] == 100


def test_etag_a_trois_champs_reste_un_constat():
    ligne = "Server leaks inodes via ETags, header found with file /, inode: 1706318, size: 177, mtime: 0x4fbcc5fa"
    (c,) = [c for c in _web([ligne]) if "ETag" in c.titre]
    assert c.gravite == "Faible" and c.verification != constats.FAUX_POSITIF
    (c,) = [c for c in _web([LIGNE_ETAG_VM], {"entetes": {"ETag": '"2c39-875-6552d7e58b4d0"'}}) if "ETag" in c.titre]
    assert c.gravite == "Faible" and c.verification == constats.CONFIRME


# ------------------------------------------------------------------ 4. versions des outils

def test_versions_affichees_proprement():
    tableau = ("---------------------------------------------------------------------------\n"
               "Nikto Versions\n---------------------------------------------------------------------------\n"
               "File                               Version      Last Mod\n"
               "Nikto main                         2.1.5        \nLibWhisker                         2.5\n")
    assert outils.version_nikto(tableau) == "Nikto 2.1.5"
    assert outils.version_nikto("Nikto v2.1.5") == "Nikto 2.1.5"
    assert outils.version_nikto("Nikto 2.5.0 (LW 2.5)") == "Nikto 2.5.0"
    assert outils.version_nikto("non installé") == "non installé"
    assert outils.version_sslscan("\x1b[1;34m2.0.7\x1b[0m") == "SSLScan 2.0.7"
    assert outils.version_sslscan("2.0.11-static") == "SSLScan 2.0.11-static"


# ------------------------------------------------------------------ 5. CVE (vulners)

def test_cve_lues_et_classees():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vulners.xml")
    apache = next(p for p in ports if p.numero == 80)
    # Sans doublon, sans les références d'exploits, de la plus grave à la moins grave
    assert [c["id"] for c in apache.cves] == ["CVE-2023-25690", "CVE-2022-31813", "CVE-2022-28330"]
    assert next(p for p in ports if p.numero == 3306).cves == []

    (c,) = constats.constats_cve(ports)
    assert c.titre == "3 CVE connue(s) pour Apache httpd 2.4.52 (Ubuntu) (port 80)"
    assert c.gravite == "Moyenne" and c.verification == constats.NON_VERIFIABLE
    assert "CVE-2023-25690 (CVSS 9.8)" in c.preuves[0]


def test_nmap_sans_script_vulners_ne_demande_pas_le_script(tmp_path, monkeypatch):
    monkeypatch.setattr(outils, "DOSSIERS_SCRIPTS_NMAP", [str(tmp_path)])
    assert "--script" not in outils.commande_nmap("localhost", tmp_path / "n.xml")
    (tmp_path / "vulners.nse").write_text("")
    cmd = outils.commande_nmap("localhost", tmp_path / "n.xml")
    assert cmd[-3:] == ["--script", "vulners", "localhost"]
    monkeypatch.setattr(config, "CVE_ACTIVE", False)
    assert "--script" not in outils.commande_nmap("localhost", tmp_path / "n.xml")


# ------------------------------------------------------------------ le site de la VM, de bout en bout

def test_rapport_du_site_de_la_vm_apres_corrections(site_fragile, monkeypatch):
    """Mêmes données que le scan réel du 16/11 : score 64 avant ; après, les deux faux positifs
    ne coûtent plus rien et les deux failles invisibles apparaissent."""
    monkeypatch.setattr(config, "CHEMINS_SUPPLEMENTAIRES", ["scanner-auto/"])
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vulners.xml")
    nikto = {"banniere": "Apache/2.4.52 (Ubuntu)", "elements_testes": 21,
             "constats": [LIGNE_ETAG_VM, "The anti-clickjacking X-Frame-Options header is not present.",
                          "Allowed HTTP Methods: POST, OPTIONS, HEAD, GET"]}
    obs = {"accessible": True, "protection_cadres": False,
           "entetes_absents": ["X-Frame-Options", "Content-Security-Policy", "X-Content-Type-Options",
                               "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"],
           "serveur": "Apache/2.4.52 (Ubuntu)", "powered_by": "", "cookies": [], "methodes_annoncees": "",
           "trace_active": False, "https_disponible": False, "redirige_vers_https": False,
           "entetes": {"ETag": '"875-6552d7e58b4d0"'}}
    ch = chemins.controler(_cible(site_fragile), FauxSiteFragile.PAGES["/mon-site/"][1])
    liste = constats.construire(_cible_locale(), ports, nikto, analyse.lire_sslscan(""), obs,
                                ecoute.lire_ss(SS_VM), ch)
    titres = {c.titre: c for c in liste}

    assert titres["Port 3306 en écoute locale uniquement : base de données MySQL/MariaDB"].gravite == "Info"
    assert titres["Fuite d'inode par l'en-tête ETag signalée par Nikto"].verification == constats.FAUX_POSITIF
    assert "Code source ou copie de sauvegarde téléchargeable" in titres
    assert "Listage du contenu d'un dossier" in titres
    assert [c.code for c in liste] == [f"C{i:02d}" for i in range(1, len(liste) + 1)]
    # 100 − 8×5 (clickjacking, HTTP seul, code source, listage, CVE) − 3×4 (nosniff, CSP, version, admin)
    assert score.calculer(liste)["score"] == 48


def test_etag_compresse_reste_un_faux_positif():
    """Scan réel du 16/11 : Apache renvoie « 875-6552d7e58b4d0-gzip » (page compressée)."""
    (c,) = [c for c in _web([LIGNE_ETAG_VM], {"entetes": {"ETag": '"875-6552d7e58b4d0-gzip"'}}) if "ETag" in c.titre]
    assert c.verification == constats.FAUX_POSITIF


def test_cve_d_un_service_en_ecoute_locale_ne_coute_rien():
    ports = analyse.lire_nmap_xml(DONNEES / "nmap_vulners.xml")
    for p in ports:
        if p.numero == 3306:
            p.cves = [{"id": "CVE-2017-15945", "cvss": 7.8}]
    liste = constats.constats_cve(ports, ecoute.lire_ss(SS_VM), _cible_locale())
    mysql = next(c for c in liste if "port 3306" in c.titre)
    apache = next(c for c in liste if "port 80" in c.titre)
    assert mysql.gravite == "Info" and "adresse locale" in mysql.recommandation
    assert apache.gravite == "Moyenne"
