"""Déroulement complet d'un scan, de la cible au résultat enregistré."""
import datetime
import json
import re
import threading
import time
import uuid

from . import analyse, config, constats as mod_constats, outils, resume, score as mod_score, verification


class Scan:
    """Un scan en cours ou terminé. Chaque scan a son propre dossier dans scans/."""

    def __init__(self, cible):
        horodatage = datetime.datetime.now()
        nom_hote = re.sub(r"[^A-Za-z0-9.-]", "_", cible.hote)
        self.id = f"{horodatage:%Y%m%d-%H%M%S}-{nom_hote}-{uuid.uuid4().hex[:4]}"
        self.cible = cible
        self.debut = horodatage
        self.dossier = config.DOSSIER_SCANS / self.id
        self.dossier.mkdir(parents=True, exist_ok=True)
        self.progression = 0
        self.etape = "En attente"
        self.termine = False
        self.erreur = ""
        self.resultat = None
        self._verrou = threading.Lock()

    def _maj(self, progression=None, etape=None):
        with self._verrou:
            if progression is not None:
                self.progression = progression
            if etape is not None:
                self.etape = etape

    def etat(self) -> dict:
        with self._verrou:
            return {"id": self.id, "progression": self.progression, "etape": self.etape,
                    "termine": self.termine, "erreur": self.erreur}

    def executer(self):
        try:
            self._executer()
        except Exception as e:  # on n'arrête jamais la plateforme sur une erreur de scan
            self.erreur = f"Erreur inattendue : {e}"
            self._maj(100, "Erreur")
        finally:
            self.termine = True

    def _executer(self):
        t0 = time.time()
        durees = {}
        self._maj(5, "Vérification directe du site…")
        tv = time.time()
        obs = verification.verifier(self.cible)
        durees["Vérification directe"] = round(time.time() - tv, 1)

        self._maj(10, "Nmap, Nikto et SSLScan lancés en parallèle…")
        termines = []

        def suivi(nom, res):
            termines.append(nom)
            self._maj(10 + 22 * len(termines), f"{nom} terminé en {res.duree} s")

        res_outils = outils.lancer_tous(self.cible, self.dossier, suivi)
        for nom, r in res_outils.items():
            if r.commande != "(non lancé)":
                durees[nom] = r.duree

        self._maj(80, "Analyse des résultats…")
        ports = analyse.lire_nmap_xml(self.dossier / "nmap.xml")
        nikto = analyse.lire_nikto(res_outils["Nikto"].sortie)
        ssl = analyse.lire_sslscan(res_outils["SSLScan"].sortie)
        liste = mod_constats.construire(self.cible, ports, nikto, ssl, obs)
        sc = mod_score.calculer(liste)

        self._maj(85, "Rédaction du résumé…")
        tr = time.time()
        texte, origine = resume.resume_ia(self.cible, liste, sc)
        durees["Résumé"] = round(time.time() - tr, 1)
        durees["Total"] = round(time.time() - t0, 1)

        self.resultat = {
            "id": self.id,
            "cible": {"url": self.cible.url, "hote": self.cible.hote, "adresses": self.cible.adresses,
                      "port": self.cible.port, "locale": self.cible.est_locale},
            "date": self.debut.strftime("%d/%m/%Y à %H:%M"),
            "durees": durees,
            "versions": outils.versions_outils(),
            "commandes": {n: r.commande for n, r in res_outils.items()},
            "outils_interrompus": [n for n, r in res_outils.items() if r.interrompu],
            "erreurs_outils": {n: r.erreur for n, r in res_outils.items() if r.erreur},
            "nikto_elements_testes": nikto["elements_testes"],
            "ports": [p.en_dict() for p in ports],
            "constats": [c.en_dict() for c in liste],
            "score": sc,
            "resume": texte,
            "resume_origine": origine,
            "sorties": {n: (r.sortie or r.erreur) for n, r in res_outils.items()},
        }
        (self.dossier / "resultat.json").write_text(
            json.dumps(self.resultat, ensure_ascii=False, indent=2), encoding="utf-8")
        self._maj(100, f"Analyse terminée en {durees['Total']} s")
