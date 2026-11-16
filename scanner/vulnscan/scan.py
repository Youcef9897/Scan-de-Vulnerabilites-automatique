"""Déroulement complet d'un scan, de la cible au résultat enregistré."""
import datetime
import json
import re
import threading
import time
import uuid

from . import (analyse, chemins as mod_chemins, config, constats as mod_constats, ecoute, outils, resume,
               score as mod_score, verification, zap as mod_zap)


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

        ch = None
        if config.CHEMINS_ACTIFS and obs.get("accessible"):
            self._maj(8, "Contrôle des chemins sensibles…")
            tc = time.time()
            ch = mod_chemins.controler(self.cible, obs.get("page", ""))
            durees["Chemins sensibles"] = round(time.time() - tc, 1)
        ecoutes = ecoute.ecoutes_locales() if self.cible.est_locale else None

        # ZAP passif (facultatif) : lancé en même temps que les autres outils, car il est le plus long.
        res_zap, fil_zap = {}, None
        if config.ZAP_ACTIF and obs.get("accessible"):
            fil_zap = threading.Thread(target=lambda: res_zap.update(r=mod_zap.lancer(self.cible, self.dossier)),
                                       daemon=True)
            fil_zap.start()

        self._maj(10, "Nmap, Nikto et SSLScan lancés en parallèle…")
        termines = []

        def suivi(nom, res):
            termines.append(nom)
            self._maj(10 + 22 * len(termines), f"{nom} terminé en {res.duree} s")

        res_outils = outils.lancer_tous(self.cible, self.dossier, suivi)
        rapport_zap = None
        if fil_zap:
            self._maj(78, "ZAP explore les pages du site (analyse passive)…")
            fil_zap.join()
            res_outils["ZAP"] = res_zap.get("r") or outils.ResultatOutil(
                nom="ZAP", commande="zap", erreur="ZAP s'est arrêté sans résultat.")
            if not res_outils["ZAP"].erreur:
                rapport_zap = mod_zap.lire_rapport(self.dossier / mod_zap.NOM_RAPPORT, self.cible)
                if rapport_zap["erreur"]:
                    res_outils["ZAP"].erreur, rapport_zap = rapport_zap["erreur"], None
        for nom, r in res_outils.items():
            if r.commande != "(non lancé)":
                durees[nom] = r.duree

        self._maj(80, "Analyse des résultats…")
        ports = analyse.lire_nmap_xml(self.dossier / "nmap.xml")
        nikto = analyse.lire_nikto(res_outils["Nikto"].sortie)
        ssl = analyse.lire_sslscan(res_outils["SSLScan"].sortie)
        liste = mod_constats.construire(self.cible, ports, nikto, ssl, obs, ecoutes, ch,
                                        rapport_zap["alertes"] if rapport_zap else None)
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
            "versions": {**outils.versions_outils(),
                         **({"ZAP": f"ZAP {rapport_zap['version']}".strip()} if rapport_zap else {})},
            "zap": ({"alertes": len(rapport_zap["alertes"]), "ignorees": rapport_zap["ignorees"],
                     "hors_site": rapport_zap["hors_site"]} if rapport_zap else None),
            "commandes": {**{n: r.commande for n, r in res_outils.items()},
                          **({"Chemins sensibles": f"{ch['requetes']} requête(s) GET sous l'adresse analysée"} if ch else {})},
            "chemins": ({"requetes": ch["requetes"], "ignore": ch["ignore"]} if ch else None),
            "ecoute_locale_lue": ecoutes is not None,
            "outils_interrompus": [n for n, r in res_outils.items() if r.interrompu],
            "erreurs_outils": {n: r.erreur for n, r in res_outils.items() if r.erreur},
            "nikto_elements_testes": nikto["elements_testes"],
            "ports": [p.en_dict() for p in ports],
            "constats": [c.en_dict() for c in liste],
            "score": sc,
            "resume": texte,
            "resume_origine": origine,
            "sorties": {**{n: (r.sortie or r.erreur) for n, r in res_outils.items()},
                        **({"Chemins sensibles": ch["ignore"] or "\n".join(ch["journal"])} if ch else {})},
        }
        (self.dossier / "resultat.json").write_text(
            json.dumps(self.resultat, ensure_ascii=False, indent=2), encoding="utf-8")
        self._maj(100, f"Analyse terminée en {durees['Total']} s")
