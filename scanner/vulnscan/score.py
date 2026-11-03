"""Score de sécurité : un barème simple, affiché tel quel dans le rapport."""
from .constats import FAUX_POSITIF, NON_CONFIRME, GRAVITES

POIDS = {"Élevée": 20, "Moyenne": 8, "Faible": 3, "Info": 0}

NIVEAUX = [
    (90, "Bon", "Peu de points à corriger."),
    (75, "Correct", "Quelques corrections recommandées."),
    (50, "À améliorer", "Plusieurs faiblesses à corriger rapidement."),
    (0, "Insuffisant", "Des faiblesses importantes exposent le site."),
]

BAREME = ("Le score part de 100. Chaque constat retire des points selon sa gravité : "
          "Élevée −20, Moyenne −8, Faible −3, Info 0. Les constats non confirmés et les "
          "faux positifs probables ne sont pas comptés. Niveaux : 90 à 100 Bon, 75 à 89 Correct, "
          "50 à 74 À améliorer, moins de 50 Insuffisant.")


def compter(constats) -> dict:
    return {g: sum(1 for c in constats if c.gravite == g) for g in GRAVITES}


def calculer(constats) -> dict:
    retenus = [c for c in constats if c.verification not in (FAUX_POSITIF, NON_CONFIRME)]
    retrait = sum(POIDS[c.gravite] for c in retenus)
    score = max(0, 100 - retrait)
    niveau, commentaire = next((n, t) for seuil, n, t in NIVEAUX if score >= seuil)
    return {"score": score, "niveau": niveau, "commentaire": commentaire,
            "retrait": retrait, "comptes": compter(retenus), "bareme": BAREME}
