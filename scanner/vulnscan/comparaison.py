"""Comparaison de deux analyses du même site (étape S8) : ce qui a été corrigé, ce qui reste, ce qui est apparu.

Le module ne relance aucun outil : il relit deux résultats déjà enregistrés (resultat.json).
"""
import re

from .constats import FAUX_POSITIF, NON_CONFIRME
from .score import POIDS

CORRIGE = "Corrigé"
ATTENUE = "Atténué"
AGGRAVE = "Aggravé"
NOUVEAU = "Nouveau"
INCHANGE = "Toujours présent"
PLUS_VERIFIABLE = "Plus vérifiable"
STATUTS = [CORRIGE, ATTENUE, PLUS_VERIFIABLE, NOUVEAU, AGGRAVE, INCHANGE]

_CVE_DU_PORT = re.compile(r"CVE connue\(s\) pour .* \(port (\d+)\)$")


def _version_masquee(constat: dict, apres: dict) -> bool:
    """Vrai si un constat de CVE a disparu parce que le service ne montre plus son numéro de version.

    Les CVE sont cherchées à partir du numéro de version : s'il n'est plus affiché, le scanner ne peut plus rien
    dire. Le logiciel n'a pas forcément été mis à jour : ce n'est pas une correction prouvée.
    """
    m = _CVE_DU_PORT.search(constat.get("titre", ""))
    if not m:
        return False
    port = next((p for p in apres.get("ports") or [] if str(p.get("numero")) == m.group(1)), None)
    return bool(port) and port.get("etat") == "open" and not re.search(r"\d", port.get("version") or "")


def points(c: dict) -> int:
    """Points retirés au score par ce constat (0 s'il n'est pas compté)."""
    if c.get("verification") in (FAUX_POSITIF, NON_CONFIRME):
        return 0
    return POIDS.get(c.get("gravite"), 0)


def cle(c: dict) -> str:
    """Identifie « le même problème » d'une analyse à l'autre, même si son titre varie un peu."""
    titre = c.get("titre", "").lower()
    if "etag" in titre:
        return "etag"          # le titre change selon que l'alerte est confirmée ou un faux positif
    # « 85 CVE connue(s) pour Apache… » et « 3 CVE connue(s) pour Apache… » : même constat
    return re.sub(r"^\d+\s+", "", titre).strip()


def _par_cle(constats) -> dict:
    vus = {}
    for c in constats:
        k = cle(c)
        if k not in vus or points(c) > points(vus[k]):
            vus[k] = c
    return vus


def _resume(r: dict) -> dict:
    return {"id": r["id"], "date": r["date"], "url": r["cible"]["url"],
            "score": r["score"]["score"], "niveau": r["score"]["niveau"], "comptes": r["score"]["comptes"]}


def comparer(premier: dict, second: dict) -> dict:
    """Compare deux résultats. L'ordre est remis dans le temps : « avant » est toujours le plus ancien."""
    avant, apres = sorted([premier, second], key=lambda r: r["id"])
    a, b = _par_cle(avant["constats"]), _par_cle(apres["constats"])

    lignes = []
    for k in list(a) + [k for k in b if k not in a]:
        ca, cb = a.get(k), b.get(k)
        pa, pb = (points(ca) if ca else 0), (points(cb) if cb else 0)
        if pa == 0 and pb == 0:
            continue                       # sans effet sur le score dans les deux analyses
        if cb is None and _version_masquee(ca, apres):
            statut = PLUS_VERIFIABLE
        elif cb is None or pb == 0:
            statut = CORRIGE if cb is None else ATTENUE
        elif ca is None or pa == 0:
            statut = NOUVEAU
        elif pb < pa:
            statut = ATTENUE
        elif pb > pa:
            statut = AGGRAVE
        else:
            statut = INCHANGE
        ref = cb or ca
        lignes.append({
            "statut": statut, "titre": ref["titre"], "categorie": ref.get("categorie", ""),
            "avant": {"code": ca["code"], "gravite": ca["gravite"], "verification": ca["verification"]} if ca else None,
            "apres": {"code": cb["code"], "gravite": cb["gravite"], "verification": cb["verification"]} if cb else None,
            "points_avant": pa, "points_apres": pb, "gain": pa - pb,
            "recommandation": ref.get("recommandation", ""),
        })
    lignes.sort(key=lambda l: (STATUTS.index(l["statut"]), -abs(l["gain"]), -l["points_apres"]))

    compte = {s: sum(1 for l in lignes if l["statut"] == s) for s in STATUTS}
    ecart = apres["score"]["score"] - avant["score"]["score"]
    meme_cible = avant["cible"]["url"] == apres["cible"]["url"]
    # ZAP ajoute des constats : comparer une analyse avec ZAP à une analyse sans ZAP fausse l'écart.
    memes_outils = bool(avant.get("zap")) == bool(apres.get("zap"))
    return {
        "avant": _resume(avant), "apres": _resume(apres), "ecart": ecart,
        "meme_cible": meme_cible, "memes_outils": memes_outils, "lignes": lignes, "comptes": compte,
        "note_version": ("« Plus vérifiable » : le service n'affiche plus son numéro de version, donc ses CVE ne peuvent "
                         "plus être cherchées. Les points sont regagnés, mais ce n'est pas la preuve d'une mise à jour : "
                         "mettre le paquet à jour reste nécessaire.") if compte[PLUS_VERIFIABLE] else "",
        "bilan": _bilan(avant["score"]["score"], apres["score"]["score"], ecart, compte),
    }


def _bilan(sa, sb, ecart, compte) -> str:
    signe = f"+{ecart}" if ecart > 0 else str(ecart)
    morceaux = [f"{compte[CORRIGE]} constat(s) corrigé(s)"]
    if compte[ATTENUE]:
        morceaux.append(f"{compte[ATTENUE]} atténué(s)")
    if compte[PLUS_VERIFIABLE]:
        morceaux.append(f"{compte[PLUS_VERIFIABLE]} plus vérifiable(s)")
    morceaux.append(f"{compte[NOUVEAU]} nouveau(x)")
    if compte[AGGRAVE]:
        morceaux.append(f"{compte[AGGRAVE]} aggravé(s)")
    morceaux.append(f"{compte[INCHANGE]} toujours présent(s)")
    return f"Le score passe de {sa} à {sb}/100 ({signe} points) : " + ", ".join(morceaux) + "."
