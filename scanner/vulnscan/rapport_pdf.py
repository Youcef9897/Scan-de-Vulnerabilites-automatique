"""Rapport PDF (mise en page provisoire, à adapter au modèle souhaité).

Toute la présentation est ici : changer la mise en page ne touche pas au moteur d'analyse.
"""
import textwrap
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

ACCENT = colors.HexColor("#1f4e79")
GRIS = colors.HexColor("#5b6878")
BORD = colors.HexColor("#dde3ea")
COULEURS = {"Élevée": colors.HexColor("#b42318"), "Moyenne": colors.HexColor("#c2560c"),
            "Faible": colors.HexColor("#a16207"), "Info": colors.HexColor("#5b6878")}


def _polices():
    """DejaVu (accents, flèches, symboles) si présente, sinon Helvetica."""
    dossiers = [Path("/usr/share/fonts/truetype/dejavu")]
    for d in dossiers:
        if (d / "DejaVuSans.ttf").exists():
            pdfmetrics.registerFont(TTFont("DV", str(d / "DejaVuSans.ttf")))
            pdfmetrics.registerFont(TTFont("DV-B", str(d / "DejaVuSans-Bold.ttf")))
            pdfmetrics.registerFont(TTFont("DVM", str(d / "DejaVuSansMono.ttf")))
            pdfmetrics.registerFontFamily("DV", normal="DV", bold="DV-B", italic="DV", boldItalic="DV-B")
            return "DV", "DV-B", "DVM"
    return "Helvetica", "Helvetica-Bold", "Courier"


def _styles(normal, gras, mono):
    s = getSampleStyleSheet()
    return {
        "titre": ParagraphStyle("t", parent=s["Title"], fontName=gras, fontSize=24, leading=30, textColor=ACCENT, alignment=TA_CENTER),
        "sous": ParagraphStyle("s", parent=s["Normal"], fontName=normal, fontSize=12, leading=17, textColor=GRIS, alignment=TA_CENTER),
        "h1": ParagraphStyle("h1", parent=s["Heading1"], fontName=gras, fontSize=16, leading=20, textColor=ACCENT, spaceBefore=6, spaceAfter=8),
        "h2": ParagraphStyle("h2", parent=s["Heading2"], fontName=gras, fontSize=12, leading=15, spaceBefore=8, spaceAfter=4),
        "p": ParagraphStyle("p", parent=s["Normal"], fontName=normal, fontSize=9.6, leading=13.5, spaceAfter=5),
        "petit": ParagraphStyle("pp", parent=s["Normal"], fontName=normal, fontSize=8.3, leading=11, textColor=GRIS),
        "cell": ParagraphStyle("c", parent=s["Normal"], fontName=normal, fontSize=8.8, leading=11.5),
        "cellb": ParagraphStyle("cb", parent=s["Normal"], fontName=gras, fontSize=8.8, leading=11.5, textColor=colors.white, alignment=TA_CENTER),
        "code": ParagraphStyle("code", fontName=mono, fontSize=7.2, leading=9.2, backColor=colors.HexColor("#f3f5f8"),
                               borderColor=BORD, borderWidth=0.5, borderPadding=5, spaceBefore=3, spaceAfter=8),
        "score": ParagraphStyle("sc", parent=s["Normal"], fontName=gras, fontSize=34, leading=38, textColor=ACCENT, alignment=TA_CENTER),
    }


def _bloc_code(texte, style, largeur=118):
    lignes = []
    for l in (texte or "").splitlines():
        lignes.extend(textwrap.wrap(l, largeur, replace_whitespace=False, drop_whitespace=False) or [""])
    return Preformatted("\n".join(lignes), style)


def _tableau(donnees, largeurs, entete=True):
    t = Table(donnees, colWidths=largeurs, repeatRows=1 if entete else 0)
    st = [("GRID", (0, 0), (-1, -1), 0.4, BORD), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    if entete:
        st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef2f7"))]
    t.setStyle(TableStyle(st))
    return t


def generer_pdf(r: dict, chemin: Path):
    normal, gras, mono = _polices()
    S = _styles(normal, gras, mono)
    P = lambda txt, st="p": Paragraph(escape(str(txt)), S[st])

    def pied(canvas, doc):
        canvas.saveState()
        canvas.setFont(normal, 8)
        canvas.setFillColor(GRIS)
        canvas.drawString(2 * cm, 1.2 * cm, f"Analyse de sécurité — {r['cible']['url']} — {r['date']}")
        canvas.drawRightString(19 * cm, 1.2 * cm, f"Page {doc.page}")
        canvas.restoreState()

    h = []
    # Page de garde
    h += [Spacer(1, 5 * cm), Paragraph("Rapport d'analyse de sécurité", S["titre"]), Spacer(1, 0.4 * cm),
          P("Site web et services réseau", "sous"), Spacer(1, 2 * cm)]
    garde = [[P("Cible", "cell"), P(r["cible"]["url"], "cell")],
             [P("Adresse(s)", "cell"), P(", ".join(r["cible"]["adresses"]), "cell")],
             [P("Date", "cell"), P(r["date"], "cell")],
             [P("Score", "cell"), P(f"{r['score']['score']}/100 — {r['score']['niveau']}", "cell")],
             [P("Cadre", "cell"), P("Analyse réalisée sur une cible autorisée, dans un cadre pédagogique.", "cell")]]
    h += [_tableau(garde, [3.5 * cm, 11 * cm], entete=False), PageBreak()]

    # Synthèse
    h += [Paragraph("1. Synthèse", S["h1"])]
    c = r["score"]["comptes"]
    carte = Table([[Paragraph(f"{r['score']['score']}<font size=14>/100</font>", S["score"]),
                    [P(r["score"]["niveau"], "h2"), P(r["score"]["commentaire"])]]],
                  colWidths=[4.5 * cm, 12 * cm])
    carte.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.6, BORD),
                               ("BACKGROUND", (0, 0), (0, 0), colors.HexColor("#f3f6fa"))]))
    h += [carte, Spacer(1, 0.3 * cm), P(r["resume"]), P(f"Résumé rédigé : {r['resume_origine']}.", "petit")]
    comptes = Table([[Paragraph(f"{c[g]}<br/>{g}", S["cellb"]) for g in COULEURS]], colWidths=[4.1 * cm] * 4)
    comptes.setStyle(TableStyle([("BACKGROUND", (i, 0), (i, 0), COULEURS[g]) for i, g in enumerate(COULEURS)]
                                + [("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    h += [Spacer(1, 0.2 * cm), comptes, Spacer(1, 0.2 * cm), P(r["score"]["bareme"], "petit")]

    # Tableau des constats
    h += [Paragraph("2. Constats", S["h1"])]
    lignes = [[P("Réf.", "cell"), P("Gravité", "cell"), P("Constat", "cell"), P("Vérification", "cell")]]
    style_lignes = []
    for i, k in enumerate(r["constats"], 1):
        lignes.append([P(k["code"], "cell"), Paragraph(escape(k["gravite"]), S["cellb"]), P(k["titre"], "cell"),
                       P(k["verification"], "cell")])
        style_lignes.append(("BACKGROUND", (1, i), (1, i), COULEURS[k["gravite"]]))
    t = _tableau(lignes, [1.2 * cm, 2.2 * cm, 10 * cm, 3.1 * cm])
    t.setStyle(TableStyle(style_lignes))
    h += [t, PageBreak()]

    # Détail
    h += [Paragraph("3. Détail des constats", S["h1"])]
    for k in r["constats"]:
        bandeau = Table([[Paragraph(escape(k["gravite"]), S["cellb"]), Paragraph(escape(f"{k['code']} — {k['titre']}"), S["h2"])]],
                        colWidths=[2.2 * cm, 14.3 * cm])
        bandeau.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), COULEURS[k["gravite"]]),
                                     ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LINEBELOW", (0, 0), (-1, -1), 0.6, BORD)]))
        bloc = [bandeau, Spacer(1, 0.15 * cm),
                Paragraph(f"<b>Description.</b> {escape(k['description'])}", S["p"]),
                Paragraph(f"<b>Recommandation.</b> {escape(k['recommandation'])}", S["p"]),
                Paragraph(f"<b>Vérification :</b> {escape(k['verification'])} — <b>Sources :</b> {escape(', '.join(k['sources']))}"
                          + (f" — <b>Référence :</b> {escape(k['reference'])}" if k.get("reference") else ""), S["petit"]),
                _bloc_code("\n".join(k["preuves"]), S["code"])]
        h.append(KeepTogether(bloc))

    # Ports et méthodologie
    h += [PageBreak(), Paragraph("4. Ports et services détectés", S["h1"])]
    if r["ports"]:
        lp = [[P("Port", "cell"), P("État", "cell"), P("Service", "cell"), P("Version", "cell")]]
        lp += [[P(f"{p['numero']}/{p['protocole']}", "cell"), P(p["etat"], "cell"), P(p["service"], "cell"), P(p["version"], "cell")]
               for p in r["ports"]]
        h.append(_tableau(lp, [2.2 * cm, 2.2 * cm, 2.8 * cm, 9.3 * cm]))
    else:
        h.append(P("Aucun résultat Nmap."))
    h += [Paragraph("5. Méthodologie", S["h1"]),
          P("Les outils Nmap, Nikto et SSLScan sont lancés en parallèle avec une durée maximale. "
            "Un contrôle des chemins sensibles (listage de dossiers, copies de sauvegarde, code source) est fait par des "
            "requêtes GET, en nombre limité, sous l'adresse analysée. Quand la cible est la machine elle-même, "
            "l'adresse d'écoute de chaque service est lue avec la commande ss. "
            "Chaque constat est ensuite vérifié par des requêtes HTTP de lecture (GET, OPTIONS, TRACE, DEBUG) : "
            "un constat est « Confirmé » s'il est reproduit, « Non confirmé » s'il ne l'est pas, "
            "« Faux positif probable » si la vérification le contredit, et « À vérifier » s'il demande un contrôle manuel.")]
    lm = [[P("Étape", "cell"), P("Version", "cell"), P("Durée", "cell")],
          [P("Vérification directe", "cell"), P("—", "cell"), P(f"{r['durees'].get('Vérification directe', '—')} s", "cell")]]
    if r.get("chemins"):
        lm.append([P(f"Contrôle des chemins sensibles ({r['chemins']['requetes']} requêtes GET)", "cell"), P("—", "cell"),
                   P(f"{r['durees'].get('Chemins sensibles', '—')} s", "cell")])
    for nom in ("Nmap", "Nikto", "SSLScan"):
        lm.append([P(nom, "cell"), P(r["versions"].get(nom, ""), "cell"),
                   P(f"{r['durees'][nom]} s" if nom in r["durees"] else "non lancé", "cell")])
    lm.append([P(f"Résumé ({r['resume_origine']})", "cell"), P("—", "cell"), P(f"{r['durees'].get('Résumé', '—')} s", "cell")])
    lm.append([P("Total", "cell"), P("", "cell"), P(f"{r['durees'].get('Total', '—')} s", "cell")])
    h.append(_tableau(lm, [5 * cm, 8.5 * cm, 3 * cm]))

    # Annexe
    h += [PageBreak(), Paragraph("Annexe : sorties brutes des outils", S["h1"])]
    for nom, sortie in r["sorties"].items():
        h += [Paragraph(escape(nom), S["h2"]), P(r["commandes"].get(nom, ""), "petit"), _bloc_code(sortie, S["code"])]

    chemin.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(chemin), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm,
                            title="Rapport d'analyse de sécurité", author="Scanner de vulnérabilités")
    doc.build(h, onFirstPage=pied, onLaterPages=pied)
    return chemin


COULEURS_STATUT = {"Corrigé": colors.HexColor("#15803d"), "Atténué": colors.HexColor("#0f5e8a"),
                   "Nouveau": colors.HexColor("#b42318"), "Aggravé": colors.HexColor("#b42318"),
                   "Toujours présent": GRIS}


def generer_pdf_comparaison(c: dict, chemin: Path):
    """PDF d'une page ou deux : scores avant/après et sort de chaque constat (étape S8)."""
    normal, gras, mono = _polices()
    S = _styles(normal, gras, mono)
    P = lambda txt, st="p": Paragraph(escape(str(txt)), S[st])

    def pied(canvas, doc):
        canvas.saveState()
        canvas.setFont(normal, 8)
        canvas.setFillColor(GRIS)
        canvas.drawString(2 * cm, 1.2 * cm, f"Comparaison avant / après — {c['apres']['url']}")
        canvas.drawRightString(19 * cm, 1.2 * cm, f"Page {doc.page}")
        canvas.restoreState()

    h = [Paragraph("Comparaison avant / après", S["titre"]), Spacer(1, 0.2 * cm), P(c["apres"]["url"], "sous"),
         Spacer(1, 0.6 * cm)]
    if not c["meme_cible"]:
        h += [P(f"Attention : les deux analyses ne portent pas sur la même adresse ({c['avant']['url']}).", "petit")]
    centre = ParagraphStyle("ce", parent=S["petit"], alignment=TA_CENTER)
    niveau = ParagraphStyle("ni", parent=S["h2"], alignment=TA_CENTER)
    signe = f"{c['ecart']:+d}"
    couleur_ecart = "#15803d" if c["ecart"] > 0 else "#b42318" if c["ecart"] < 0 else "#5b6878"
    duel = Table([[Paragraph(escape(f"Avant — {c['avant']['date']}"), centre), "",
                   Paragraph(escape(f"Après — {c['apres']['date']}"), centre)],
                  [Paragraph(f"{c['avant']['score']}<font size=14>/100</font>", S["score"]),
                   Paragraph(f"<font color='{couleur_ecart}'>{signe}</font>", S["score"]),
                   Paragraph(f"{c['apres']['score']}<font size=14>/100</font>", S["score"])],
                  [Paragraph(escape(c["avant"]["niveau"]), niveau), "", Paragraph(escape(c["apres"]["niveau"]), niveau)]],
                 colWidths=[6 * cm, 4.5 * cm, 6 * cm])
    duel.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("BOX", (0, 0), (-1, -1), 0.6, BORD),
                              ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f6fa"))]))
    h += [duel, Spacer(1, 0.4 * cm), P(c["bilan"]), Spacer(1, 0.3 * cm),
          Paragraph("Constats qui comptent dans le score", S["h1"])]

    if c["lignes"]:
        lignes = [[P("Statut", "cell"), P("Constat", "cell"), P("Avant", "cell"), P("Après", "cell"), P("Points", "cell")]]
        st = []
        for i, l in enumerate(c["lignes"], 1):
            av = f"{l['avant']['gravite']}" + ("" if l["points_avant"] else f" ({l['avant']['verification']})") if l["avant"] else "—"
            ap = f"{l['apres']['gravite']}" + ("" if l["points_apres"] else f" ({l['apres']['verification']})") if l["apres"] else "absent"
            lignes.append([Paragraph(escape(l["statut"]), S["cellb"]), P(l["titre"], "cell"), P(av, "cell"), P(ap, "cell"),
                           P(f"{l['gain']:+d}" if l["gain"] else "0", "cell")])
            st.append(("BACKGROUND", (0, i), (0, i), COULEURS_STATUT[l["statut"]]))
        t = _tableau(lignes, [2.8 * cm, 7.6 * cm, 2.3 * cm, 2.3 * cm, 1.5 * cm])
        t.setStyle(TableStyle(st))
        h.append(t)
    else:
        h.append(P("Aucun constat ne retire de points dans ces deux analyses."))
    h += [Spacer(1, 0.3 * cm),
          P("« Points » : points regagnés (+) ou perdus (−) sur le score pour ce constat. Barème : Élevée −20, Moyenne −8, "
            "Faible −3, Info 0 ; les constats non confirmés et les faux positifs probables ne sont pas comptés. "
            f"Analyses comparées : {c['avant']['id']} et {c['apres']['id']}.", "petit")]

    chemin.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(chemin), pagesize=A4, leftMargin=2 * cm, rightMargin=2 * cm,
                            topMargin=1.8 * cm, bottomMargin=2 * cm,
                            title="Comparaison avant / après", author="Scanner de vulnérabilités")
    doc.build(h, onFirstPage=pied, onLaterPages=pied)
    return chemin
