"""ZAP en mode passif (étape S4-B) : plan d'analyse, lancement et lecture du rapport JSON.

« Passif » veut dire que ZAP ne lance aucune attaque : il parcourt les pages du site (liens et formulaires GET)
et lit les réponses. Le plan ci-dessous ne contient pas de tâche « activeScan » et n'envoie pas les formulaires POST.

ZAP est désactivé par défaut (ZAP_ACTIF=0) : sans lui, la plateforme fonctionne exactement comme avant.
"""
import html
import json
import re
import shutil
from pathlib import Path
from urllib.parse import urlsplit

from . import config
from .outils import ResultatOutil, executer
from .regles_zap import IGNOREES

NOM_RAPPORT = "zap.json"
NOM_PLAN = "zap-plan.yaml"
COMMANDES_CONNUES = ["zaproxy", "zap.sh", "owasp-zap"]   # paquet snap, archive officielle, paquet Kali

RISQUES = {3: "Élevée", 2: "Moyenne", 1: "Faible", 0: "Info"}
FAUX_POSITIF_ZAP = 0          # niveau de confiance « False Positive » de ZAP
CONFIANCE_FAIBLE = 1


# ---------------------------------------------------------------- Lancement

def trouver_commande() -> str:
    """Commande de ZAP : celle du réglage ZAP_COMMANDE, sinon la première trouvée sur la machine."""
    if config.ZAP_COMMANDE:
        return config.ZAP_COMMANDE
    return next((c for c in COMMANDES_CONNUES if shutil.which(c)), COMMANDES_CONNUES[0])


def base_du_site(url: str) -> str:
    """« http://hote/mon-site/ » pour « http://hote/mon-site/index.php » : le dossier analysé."""
    u = urlsplit(url)
    chemin = u.path if u.path.endswith("/") else u.path.rsplit("/", 1)[0] + "/"
    return f"{u.scheme}://{u.netloc}{chemin or '/'}"


def _yaml(texte: str) -> str:
    """Chaîne YAML entre apostrophes : seule l'apostrophe doit être doublée."""
    return "'" + str(texte).replace("'", "''") + "'"


def plan(cible, dossier: Path) -> str:
    """Plan pour l'« Automation Framework » de ZAP : exploration, analyse passive, rapport JSON."""
    base = base_du_site(cible.url)
    return "\n".join([
        "# Plan généré par la plateforme : analyse passive uniquement (aucune tâche activeScan).",
        "env:",
        "  contexts:",
        "    - name: 'cible'",
        "      urls:",
        f"        - {_yaml(cible.url)}",
        "      includePaths:",
        f"        - {_yaml(re.escape(base) + '.*')}",      # ZAP ne sort pas du dossier analysé
        "  parameters:",
        "    failOnError: false",
        "    failOnWarning: false",
        "    progressToStdout: true",
        "jobs:",
        "  - type: passiveScan-config",
        "    parameters:",
        "      scanOnlyInScope: true",
        "      maxAlertsPerRule: 10",
        "  - type: spider",
        "    parameters:",
        "      context: 'cible'",
        f"      url: {_yaml(cible.url)}",
        f"      maxDuration: {config.ZAP_DUREE_EXPLORATION}",      # en minutes
        f"      maxDepth: {config.ZAP_PROFONDEUR}",
        "      postForm: false",                                  # aucun formulaire POST n'est envoyé
        "  - type: passiveScan-wait",
        "    parameters:",
        "      maxDuration: 1",
        "  - type: report",
        "    parameters:",
        "      template: 'traditional-json'",
        f"      reportDir: {_yaml(dossier.resolve())}",
        f"      reportFile: {_yaml(NOM_RAPPORT)}",
        "",
    ])


def commande(fichier_plan: Path) -> list:
    # -cmd : sans interface, ZAP s'arrête à la fin du plan.   -silent : aucune requête non demandée (mises à jour).
    # -dir : dossier de travail à part, pour ne pas gêner un ZAP ouvert à la main.
    return [trouver_commande(), "-cmd", "-silent", "-autorun", str(fichier_plan.resolve()),
            "-dir", str(Path(config.ZAP_DOSSIER).resolve()), "-host", "127.0.0.1", "-port", str(config.ZAP_PORT)]


def lancer(cible, dossier: Path) -> ResultatOutil:
    """Écrit le plan dans le dossier du scan puis lance ZAP. Le rapport est écrit dans `dossier/zap.json`."""
    fichier_plan = dossier / NOM_PLAN
    fichier_plan.write_text(plan(cible, dossier), encoding="utf-8")
    Path(config.ZAP_DOSSIER).mkdir(parents=True, exist_ok=True)
    res = executer("ZAP", commande(fichier_plan), config.DUREE_MAX_ZAP)
    # Pas de chemin interne de la machine dans le rapport
    res.commande = (res.commande.replace(str(dossier.resolve()) + "/", "")
                    .replace(str(Path(config.ZAP_DOSSIER).resolve()), "zap-home"))
    (dossier / "zap.txt").write_text(res.sortie or res.erreur, encoding="utf-8")
    if not res.erreur and not (dossier / NOM_RAPPORT).exists():
        res.erreur = ("ZAP n'a pas produit de rapport" + (" (durée maximale atteinte)." if res.interrompu else
                      ". Voir sa sortie en annexe."))
    return res


# ---------------------------------------------------------------- Lecture du rapport

_BALISES = re.compile(r"<[^>]+>")


def _texte(valeur) -> str:
    """Texte simple à partir d'un champ du rapport (ZAP y met des balises <p>)."""
    t = re.sub(r"</p>\s*<p>|<br\s*/?>", "\n", str(valeur or ""), flags=re.I)
    t = html.unescape(_BALISES.sub("", t))
    return re.sub(r"[ \t]+", " ", t).strip()


def _brut(valeur, longueur: int) -> str:
    """Extrait cité tel quel (un morceau de page peut contenir des balises), sur une ligne et raccourci."""
    return re.sub(r"\s+", " ", str(valeur or "")).strip()[:longueur]


def _entier(valeur, defaut=0) -> int:
    try:
        return int(str(valeur).strip())
    except (TypeError, ValueError):
        return defaut


def _hotes_de_la_cible(cible) -> set:
    return {str(h).lower() for h in [cible.hote, *(cible.adresses or [])] if h}


def _meme_site(uri: str, cible) -> bool:
    """Vrai si l'adresse est sur le site analysé (même hôte et même port)."""
    try:
        u = urlsplit(uri)
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        return False
    return (u.hostname or "").lower() in _hotes_de_la_cible(cible) and port == cible.port


def lire_rapport(source, cible=None) -> dict:
    """Lit un rapport « traditional-json » de ZAP (chemin de fichier ou texte JSON).

    Renvoie {"version", "alertes", "ignorees", "hors_site", "erreur"}. Ne lève jamais d'exception :
    un rapport absent ou illisible donne une liste vide et un message dans "erreur".
    Si `cible` est fournie, seules les pages du site analysé sont gardées.
    """
    vide = {"version": "", "alertes": [], "ignorees": [], "hors_site": 0, "erreur": ""}
    try:
        texte = Path(source).read_text(encoding="utf-8") if isinstance(source, Path) else str(source)
        donnees = json.loads(texte)
    except FileNotFoundError:
        return {**vide, "erreur": "Rapport de ZAP introuvable."}
    except (OSError, ValueError) as e:
        return {**vide, "erreur": f"Rapport de ZAP illisible : {e}"}
    if not isinstance(donnees, dict):
        return {**vide, "erreur": "Rapport de ZAP illisible : format inattendu."}

    sites = donnees.get("site") or []
    if isinstance(sites, dict):
        sites = [sites]
    resultat = {**vide, "version": str(donnees.get("@version", "")).strip()}
    par_ref = {}
    for site in sites:
        if not isinstance(site, dict):
            continue
        for a in site.get("alerts") or []:
            if not isinstance(a, dict):
                continue
            plugin = str(a.get("pluginid", "")).strip()
            ref = str(a.get("alertRef") or plugin).strip()
            confiance = _entier(a.get("confidence"), 2)
            if confiance == FAUX_POSITIF_ZAP:
                continue                               # ZAP lui-même classe l'alerte en faux positif
            instances = []
            for i in a.get("instances") or []:
                if not isinstance(i, dict) or not i.get("uri"):
                    continue
                if cible is not None and not _meme_site(i["uri"], cible):
                    resultat["hors_site"] += 1
                    continue
                instances.append({"uri": str(i["uri"]), "methode": str(i.get("method") or "GET"),
                                  "param": _brut(i.get("param"), 80), "preuve": _brut(i.get("evidence"), 160)})
            if not instances:
                continue
            nom = _texte(a.get("alert") or a.get("name")) or f"Règle {plugin}"
            if plugin in IGNOREES:
                if nom not in resultat["ignorees"]:
                    resultat["ignorees"].append(nom)
                continue
            if ref in par_ref:                         # même alerte vue sur deux « sites » (http et https)
                par_ref[ref]["instances"] += instances
                continue
            par_ref[ref] = {
                "plugin": plugin, "ref": ref, "nom": nom,
                "risque": min(max(_entier(a.get("riskcode"), 0), 0), 3), "confiance": confiance,
                "description": _texte(a.get("desc")), "solution": _texte(a.get("solution")),
                "cwe": _entier(a.get("cweid"), 0), "instances": instances,
            }
    resultat["alertes"] = sorted(par_ref.values(), key=lambda x: (-x["risque"], x["ref"]))
    return resultat
