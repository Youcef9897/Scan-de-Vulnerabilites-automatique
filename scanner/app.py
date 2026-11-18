"""Plateforme web de scan de vulnérabilités.

Lancement :  python3 app.py   puis ouvrir http://127.0.0.1:5000
"""
import json
import re
import threading

from flask import Flask, abort, jsonify, render_template, request, send_file

from vulnscan import config
from vulnscan.cible import CibleRefusee, preparer_cible
from vulnscan.comparaison import STATUTS, comparer
from vulnscan.constats import GRAVITES
from vulnscan.rapport_pdf import generer_pdf, generer_pdf_comparaison
from vulnscan.scan import Scan

app = Flask(__name__)

SCANS = {}                      # scans lancés depuis le démarrage : id -> Scan
VERROU = threading.Lock()
ID_VALIDE = re.compile(r"^\d{8}-\d{6}-[A-Za-z0-9._-]+-[0-9a-f]{4}$")


def scan_en_cours():
    return any(not s.termine for s in SCANS.values())


def charger_resultat(scan_id: str) -> dict:
    """Résultat d'un scan, en mémoire ou depuis son dossier (historique)."""
    if not ID_VALIDE.match(scan_id):
        abort(404)
    s = SCANS.get(scan_id)
    if s and s.resultat:
        return s.resultat
    fichier = (config.DOSSIER_SCANS / scan_id / "resultat.json").resolve()
    if config.DOSSIER_SCANS.resolve() not in fichier.parents or not fichier.exists():
        abort(404)
    return json.loads(fichier.read_text(encoding="utf-8"))


def historique(limite=10) -> list:
    if not config.DOSSIER_SCANS.exists():
        return []
    elements = []
    for d in sorted(config.DOSSIER_SCANS.iterdir(), reverse=True):
        f = d / "resultat.json"
        if f.exists():
            try:
                r = json.loads(f.read_text(encoding="utf-8"))
                elements.append({"id": r["id"], "url": r["cible"]["url"], "date": r["date"],
                                 "score": r["score"]["score"], "niveau": r["score"]["niveau"]})
            except (ValueError, KeyError):
                continue
        if len(elements) >= limite:
            break
    return elements


@app.route("/")
def accueil():
    choix = historique(30)
    # Par défaut : « Après » = la dernière analyse, « Avant » = la plus ancienne analyse de la même adresse
    meme_site = [h for h in choix if choix and h["url"] == choix[0]["url"]]
    avant_defaut = meme_site[-1]["id"] if len(meme_site) >= 2 else (choix[1]["id"] if len(choix) >= 2 else "")
    return render_template("index.html", historique=historique(), choix=choix, avant_defaut=avant_defaut,
                           cibles=", ".join(config.CIBLES_AUTORISEES))


@app.route("/scan", methods=["POST"])
def lancer():
    donnees = request.get_json(silent=True) or request.form
    if str(donnees.get("autorisation", "")).lower() not in ("1", "true", "on", "oui"):
        return jsonify({"erreur": "Coche la case pour confirmer que tu es autorisé à scanner cette cible."}), 400
    try:
        cible = preparer_cible(donnees.get("cible", ""))
    except CibleRefusee as e:
        return jsonify({"erreur": str(e)}), 400
    with VERROU:
        if scan_en_cours():
            return jsonify({"erreur": "Un scan est déjà en cours : attends qu'il se termine."}), 409
        scan = Scan(cible)
        SCANS[scan.id] = scan
    threading.Thread(target=scan.executer, daemon=True).start()
    return jsonify({"id": scan.id})


@app.route("/scan/<scan_id>/etat")
def etat(scan_id):
    s = SCANS.get(scan_id)
    if not s:
        abort(404)
    return jsonify(s.etat())


@app.route("/scan/<scan_id>")
def rapport(scan_id):
    r = charger_resultat(scan_id)
    return render_template("rapport.html", r=r, gravites=GRAVITES)


@app.route("/scan/<scan_id>/pdf")
def rapport_pdf(scan_id):
    r = charger_resultat(scan_id)
    chemin = config.DOSSIER_SCANS / r["id"] / "rapport.pdf"
    generer_pdf(r, chemin)
    return send_file(chemin, as_attachment=True, download_name=f"rapport-scan-{r['id']}.pdf",
                     mimetype="application/pdf")


def _comparaison():
    avant, apres = request.args.get("avant", ""), request.args.get("apres", "")
    if not avant or not apres or avant == apres:
        abort(400, "Choisis deux analyses différentes.")
    return comparer(charger_resultat(avant), charger_resultat(apres))


@app.route("/comparer")
def comparaison():
    return render_template("comparaison.html", c=_comparaison(), statuts=STATUTS)


@app.route("/comparer/pdf")
def comparaison_pdf():
    c = _comparaison()
    nom = f"comparaison-{c['avant']['id']}-{c['apres']['id']}.pdf"
    chemin = config.DOSSIER_SCANS / c["apres"]["id"] / nom
    generer_pdf_comparaison(c, chemin)
    return send_file(chemin, as_attachment=True, download_name=nom, mimetype="application/pdf")


if __name__ == "__main__":
    config.DOSSIER_SCANS.mkdir(parents=True, exist_ok=True)
    print(f"Plateforme disponible sur http://{config.HOTE_ECOUTE}:{config.PORT_ECOUTE}")
    print(f"Cibles autorisées : {', '.join(config.CIBLES_AUTORISEES)}")
    app.run(host=config.HOTE_ECOUTE, port=config.PORT_ECOUTE, debug=False, threaded=True)
