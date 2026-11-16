"""Lancement des outils externes (Nmap, Nikto, SSLScan) avec des durées bornées."""
import re
import shlex
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from functools import lru_cache
from pathlib import Path

from . import config


@dataclass
class ResultatOutil:
    nom: str
    commande: str
    sortie: str = ""
    duree: float = 0.0
    interrompu: bool = False     # vrai si la durée maximale a été atteinte
    erreur: str = ""             # message en français si l'outil n'a pas pu tourner

    def en_dict(self):
        return asdict(self)


def executer(nom: str, cmd: list, duree_max: int) -> ResultatOutil:
    """Lance une commande ; en cas de dépassement, garde la sortie partielle."""
    res = ResultatOutil(nom=nom, commande=" ".join(shlex.quote(c) for c in cmd))
    if shutil.which(cmd[0]) is None:
        res.erreur = f"{cmd[0]} n'est pas installé sur cette machine."
        return res
    debut = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duree_max)
        res.sortie = proc.stdout or ""
        if proc.returncode != 0 and proc.stderr:
            res.sortie += "\n" + proc.stderr
    except subprocess.TimeoutExpired as e:
        partiel = e.stdout or ""
        if isinstance(partiel, bytes):
            partiel = partiel.decode("utf-8", errors="replace")
        res.sortie = partiel
        res.interrompu = True
    except OSError as e:
        res.erreur = f"Impossible de lancer {cmd[0]} : {e}"
    res.duree = round(time.time() - debut, 1)
    return res


@lru_cache(maxsize=None)
def versions_outils() -> dict:
    """Versions des outils, pour la section « méthodologie » du rapport."""
    def premiere_ligne(cmd):
        if shutil.which(cmd[0]) is None:
            return "non installé"
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            texte = (out.stdout or out.stderr).strip().splitlines()
            return next((l.strip() for l in texte if l.strip()), "inconnue")
        except Exception:
            return "inconnue"
    return {
        "Nmap": premiere_ligne(["nmap", "--version"]),
        "Nikto": version_nikto(premiere_ligne_nikto()),
        "SSLScan": version_sslscan(premiere_ligne(["sslscan", "--version"])),
    }


_COULEURS_TERMINAL = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def version_nikto(texte: str) -> str:
    """« Nikto 2.1.5 » à partir de la sortie de `nikto -Version` (un tableau, selon les versions)."""
    if texte == "non installé":
        return texte
    m = re.search(r"Nikto(?: main)?\s+v?(\d+(?:\.\d+)+)", _COULEURS_TERMINAL.sub("", texte))
    return f"Nikto {m.group(1)}" if m else "inconnue"


def version_sslscan(ligne: str) -> str:
    """Retire les codes de couleur du terminal (« \x1b[1;34m ») de la version de SSLScan."""
    propre = _COULEURS_TERMINAL.sub("", ligne).strip()
    if propre in ("non installé", "inconnue", ""):
        return propre or "inconnue"
    return propre if propre.lower().startswith("sslscan") else f"SSLScan {propre}"


def premiere_ligne_nikto() -> str:
    if shutil.which("nikto") is None:
        return "non installé"
    try:
        out = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, timeout=15)
        return out.stdout or out.stderr or ""
    except Exception:
        return ""


def commande_nmap(hote: str, fichier_xml: Path) -> list:
    # -Pn : beaucoup de serveurs ne répondent pas au ping.
    # --version-light, -T4, --max-retries : détection des versions plus rapide.
    # -oX : sortie XML (analyse fiable) ; la sortie normale reste lisible pour l'annexe.
    cmd = ["nmap", "-Pn", "-sV", "--version-light", "-T4", "--max-retries", "2",
           "--host-timeout", f"{max(config.DUREE_MAX_NMAP - 10, 30)}s",
           "-p", config.NMAP_PORTS, "-oX", str(fichier_xml)]
    if config.CVE_ACTIVE and script_vulners_present():
        cmd += ["--script", "vulners"]      # CVE connues pour les versions détectées
    return cmd + [hote]


DOSSIERS_SCRIPTS_NMAP = ["/usr/share/nmap/scripts", "/usr/local/share/nmap/scripts"]


def script_vulners_present() -> bool:
    """Nmap s'arrête si on lui demande un script absent : on vérifie avant de l'ajouter."""
    return any((Path(d) / "vulners.nse").exists() for d in DOSSIERS_SCRIPTS_NMAP)


def commande_nikto(url: str) -> list:
    # Pas d'option -maxtime : elle est défectueuse dans Nikto 2.1.5 (arrêt après quelques secondes).
    # La durée est bornée par executer().
    return ["nikto", "-h", url, "-nointeractive", "-Tuning", "123b", "-timeout", "5"]


def commande_sslscan(hote: str, port: int) -> list:
    return ["sslscan", "--no-colour", f"{hote}:{port}"]


def lancer_tous(cible, dossier: Path, suivi=None) -> dict:
    """Lance les trois outils en parallèle. `suivi(nom, resultat)` est appelé à chaque fin d'outil."""
    taches = {
        "Nmap": (commande_nmap(cible.hote, dossier / "nmap.xml"), config.DUREE_MAX_NMAP),
        "Nikto": (commande_nikto(cible.url), config.DUREE_MAX_NIKTO),
    }
    resultats = {}
    if cible.schema == "https":
        taches["SSLScan"] = (commande_sslscan(cible.hote, cible.port), config.DUREE_MAX_SSLSCAN)
    else:
        resultats["SSLScan"] = ResultatOutil(
            nom="SSLScan", commande="(non lancé)",
            erreur="Non lancé : le site n'utilise pas HTTPS.")

    with ThreadPoolExecutor(max_workers=3) as pool:
        futurs = {pool.submit(executer, nom, cmd, dmax): nom for nom, (cmd, dmax) in taches.items()}
        for f in as_completed(futurs):
            res = f.result()
            res.commande = res.commande.replace(str(dossier) + "/", "")  # pas de chemin interne dans le rapport
            resultats[res.nom] = res
            (dossier / f"{res.nom.lower()}.txt").write_text(res.sortie or res.erreur, encoding="utf-8")
            if suivi:
                suivi(res.nom, res)
    return {nom: resultats[nom] for nom in ("Nmap", "Nikto", "SSLScan")}
