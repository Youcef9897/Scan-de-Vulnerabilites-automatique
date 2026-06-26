# -*- coding: utf-8 -*-

from flask import Flask, render_template, request, jsonify, send_file
import threading
import subprocess
import requests
from urllib.parse import urlparse
import datetime
import html
import re
import matplotlib.pyplot as plt

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER


app = Flask(__name__)

progress = 0
status = "En attente..."
final_report = ""
raw_results = ""
ai_analysis = ""


def site_exists(url):
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        return response.status_code < 400
    except Exception:
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            return response.status_code < 400
        except Exception:
            return False


def normalize_url(url):
    url = url.strip()

    if url.startswith(("http://", "https://")):
        return url if site_exists(url) else None

    http_url = "http://" + url
    if site_exists(http_url):
        return http_url

    https_url = "https://" + url
    if site_exists(https_url):
        return https_url

    return None


def clean_nmap_result(text):
    lines = text.splitlines()
    cleaned = []
    skip = False

    for line in lines:
        if line.startswith("SF-Port"):
            skip = True
            continue

        if "Service detection performed" in line:
            skip = False
            cleaned.append(line)
            continue

        if not skip:
            cleaned.append(line)

    return "\n".join(cleaned)


def clean_ai_text(text):
    text = text.replace("#", "")
    text = text.replace("*", "")
    text = text.replace("```", "")
    text = text.replace("###", "")
    text = text.replace("##", "")
    return text.strip()


def count_open_ports(text):
    return len(re.findall(r"\d+/tcp\s+open", text))


def count_vulnerabilities(text):
    keywords = [
        "header is not present",
        "Server leaks",
        "Allowed HTTP Methods",
        "Admin login",
        "n'utilise pas HTTPS",
        "SSLScan ignoré",
        "closed https",
        "ETags",
        "X-Frame-Options",
        "OSVDB",
        "PHPSESSID",
        "cookie",
        "not present"
    ]

    count = 0
    for key in keywords:
        if key.lower() in text.lower():
            count += 1

    return count


def generate_fallback_analysis(text):
    nb_ports = count_open_ports(text)
    nb_vulns = count_vulnerabilities(text)

    return f"""
1. Résumé exécutif

Le scan automatisé réalisé sur la cible a permis d’identifier plusieurs services réseau exposés ainsi que différentes configurations de sécurité à surveiller.

Au total, {nb_ports} port(s) ouvert(s) ont été détectés et environ {nb_vulns} point(s) de sécurité nécessitant une vérification ont été relevés.

L’analyse met principalement en évidence des risques liés à l’exposition de services web, à certaines configurations HTTP ainsi qu’à l’absence éventuelle de mécanismes de sécurisation complémentaires.

2. Santé technique de la cible

Les résultats montrent la présence d’un serveur web accessible via HTTP ainsi que plusieurs services potentiellement actifs selon la configuration de la machine analysée.

Certains services comme Apache, MySQL ou CUPS peuvent être détectés selon les ports ouverts identifiés par Nmap.

L’exposition de ces services doit être maîtrisée afin de limiter les risques d’accès non autorisés ou de fuite d’informations techniques.

3. Vulnérabilités détectées

Plusieurs points d’attention peuvent être relevés :

- absence potentielle de certains en-têtes de sécurité HTTP ;
- divulgation possible d’informations serveur ;
- présence de pages sensibles accessibles ;
- absence de HTTPS dans certains cas ;
- services réseau exposés inutilement.

Ces éléments ne constituent pas nécessairement une compromission directe mais représentent des surfaces d’attaque potentielles.

4. Recommandations pour les développeurs

Les actions suivantes sont recommandées :

- limiter les ports et services exposés ;
- ajouter les en-têtes HTTP de sécurité ;
- protéger les pages sensibles ;
- mettre en place HTTPS ;
- maintenir les composants serveur à jour ;
- surveiller régulièrement les services réseau actifs.

5. Actions correctives prioritaires

Les corrections prioritaires concernent principalement :

- la réduction de la surface d’exposition réseau ;
- le durcissement du serveur web ;
- la sécurisation des accès sensibles ;
- l’amélioration de la configuration HTTP et HTTPS.

6. Conclusion

Le niveau de sécurité global observé reste acceptable dans un contexte pédagogique ou local.

Cependant, plusieurs améliorations de configuration seraient nécessaires avant toute utilisation dans un environnement de production ou accessible publiquement.
"""


def analyse_with_ai(text):
    prompt = f"""
Tu es un analyste cybersécurité junior chargé de produire un rapport professionnel.

Tu dois analyser les résultats issus des outils Nmap, Nikto et SSLScan.

Règles obligatoires :
- Réponds uniquement en français.
- N’invente aucune vulnérabilité.
- Ne cite aucune CVE absente des résultats.
- Ne recopie jamais les résultats bruts.
- Utilise un ton professionnel et technique.
- Le rapport doit être compréhensible par une équipe de développeurs.
- Ne parle jamais d’exploitation active.
- Fais des phrases courtes et claires.
- N'utilise pas de Markdown.
- N'utilise pas le caractère #.
- Ne mets pas de titres avec des symboles.

Structure obligatoire :

1. Résumé exécutif
Présente brièvement l’état global de sécurité observé.

2. Santé technique de la cible
Présente les ports ouverts, les services détectés, les technologies identifiées et les risques liés à leur exposition.

3. Vulnérabilités détectées
Pour chaque point détecté, indique le titre, le niveau de gravité, l’explication, l’impact potentiel et la recommandation.

4. Recommandations pour les développeurs
Donne des recommandations concrètes et applicables.

5. Actions correctives prioritaires
Présente les actions les plus importantes à corriger rapidement.

6. Conclusion
Donne une conclusion professionnelle concise.

Résultats à analyser :

{text}
"""

    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "mistral",
                "prompt": prompt,
                "stream": False
            },
            timeout=600
        )

        data = response.json()
        result = data.get("response", "").strip()

        if not result:
            return generate_fallback_analysis(text)

        return clean_ai_text(result)

    except Exception:
        return generate_fallback_analysis(text)


def run_scan(url):
    global progress, status, final_report, raw_results, ai_analysis

    progress = 0
    status = "Initialisation..."
    final_report = ""
    raw_results = ""
    ai_analysis = ""

    url = normalize_url(url)

    if not url:
        progress = 100
        status = "Analyse terminée"
        final_report = "Le site n'existe pas ou ne répond pas."
        return

    parsed = urlparse(url)
    host = parsed.hostname

    progress = 10
    status = f"URL normalisée : {url}"

    status = "Analyse Nmap en cours..."
    try:
        nmap_result = subprocess.run(
            ["nmap", "-sV", "-p", "80,443,631,3306", host],
            capture_output=True,
            text=True,
            timeout=400
        ).stdout
        nmap_result = clean_nmap_result(nmap_result)
    except Exception as e:
        nmap_result = f"Erreur Nmap : {e}"

    progress = 35
    status = "Analyse Nmap terminée"

    status = "Analyse Nikto en cours..."
    try:
        nikto_process = subprocess.run(
            [
                "nikto",
                "-h", url,
                "-nointeractive",
                "-Tuning", "123b",
                "-timeout", "10"
            ],
            capture_output=True,
            text=True,
            timeout=800
        )

        nikto_result = nikto_process.stdout

        if nikto_process.stderr:
            nikto_result += "\n" + nikto_process.stderr

    except Exception as e:
        nikto_result = f"Erreur Nikto : {e}"

    progress = 65
    status = "Analyse Nikto terminée"

    status = "Analyse SSLScan en cours..."
    if url.startswith("https://"):
        try:
            sslscan_result = subprocess.run(
                ["sslscan", host],
                capture_output=True,
                text=True,
                timeout=200
            ).stdout
        except Exception as e:
            sslscan_result = f"Erreur SSLScan : {e}"
    else:
        sslscan_result = "SSLScan ignoré : le site n'utilise pas HTTPS."

    progress = 80
    status = "Analyse SSLScan terminée"

    raw_results = (
        "===== NMAP =====\n"
        + nmap_result
        + "\n\n===== NIKTO =====\n"
        + nikto_result
        + "\n\n===== SSLSCAN =====\n"
        + sslscan_result
    )

    status = "Analyse IA en cours..."
    ai_analysis = analyse_with_ai(raw_results)

    final_report = (
        "===== ANALYSE SYNTHÉTIQUE =====\n\n"
        + ai_analysis
        + "\n\n===== RÉSULTATS TECHNIQUES BRUTS =====\n\n"
        + raw_results
    )

    progress = 100
    status = "Analyse terminée"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/start_scan", methods=["POST"])
def start_scan():
    global progress, status

    url = request.form.get("url", "").strip()

    if not url:
        return jsonify({"error": "URL vide"}), 400

    progress = 0
    status = "Initialisation..."

    thread = threading.Thread(target=run_scan, args=(url,))
    thread.daemon = True
    thread.start()

    return jsonify({"message": "Scan lancé"})


@app.route("/progress", methods=["GET"])
def get_progress():
    return jsonify({
        "progress": progress,
        "status": status
    })


@app.route("/results", methods=["GET"])
def get_results():
    return jsonify({
        "report": final_report
    })


@app.route("/download_pdf")
def download_pdf():
    if not final_report:
        return "Aucun rapport disponible. Lancez d'abord un scan.", 400

    pdf_path = "/tmp/rapport_scan_vulnerabilites_web.pdf"
    chart_path = "/tmp/graphique_synthese.png"

    nb_ports = count_open_ports(raw_results)
    nb_vulns = count_vulnerabilities(raw_results)

    if nb_vulns <= 1:
        score = 85
        niveau = "Acceptable"
    elif nb_vulns <= 3:
        score = 65
        niveau = "Vulnérable"
    elif nb_vulns <= 5:
        score = 45
        niveau = "Critique"
    else:
        score = 30
        niveau = "Critique"

    gravites = {
        "Faible": 1 if nb_vulns >= 1 else 0,
        "Moyenne": 1 if nb_vulns >= 2 else 0,
        "Élevée": 1 if nb_vulns >= 4 else 0
    }

    labels = ["Ports ouverts", "Vulnérabilités", "Faible", "Moyenne", "Élevée"]
    values = [
        nb_ports,
        nb_vulns,
        gravites["Faible"],
        gravites["Moyenne"],
        gravites["Élevée"]
    ]

    plt.figure(figsize=(7, 4))
    plt.bar(labels, values)
    plt.title("Synthèse du scan")
    plt.ylabel("Nombre")
    plt.xticks(rotation=20)
    plt.tight_layout()
    plt.savefig(chart_path)
    plt.close()

    def add_page_number(canvas, doc):
        page_num = canvas.getPageNumber()
        canvas.setFont("Helvetica", 9)
        canvas.drawRightString(19 * cm, 1.2 * cm, f"Page {page_num}")

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=22,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#1f2937"),
        spaceAfter=20
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.HexColor("#2563eb"),
        spaceBefore=15,
        spaceAfter=10
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        spaceAfter=8
    )

    code_style = ParagraphStyle(
        "CodeStyle",
        parent=styles["Code"],
        fontSize=7,
        leading=9,
        backColor=colors.HexColor("#f3f4f6"),
        borderColor=colors.HexColor("#d1d5db"),
        borderWidth=0.5,
        borderPadding=5,
        spaceAfter=5
    )

    story = []

    story.append(Spacer(1, 5 * cm))
    story.append(Paragraph("Rapport d'analyse automatisée de sécurité réseau et web", title_style))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph("Scanner automatisé de vulnérabilités web et réseau", subtitle_style))
    story.append(Spacer(1, 1 * cm))
    story.append(Paragraph(
        f"Date de génération : {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}",
        normal_style
    ))
    story.append(Paragraph("Projet PST - Cybersécurité", normal_style))
    story.append(PageBreak())

    story.append(Paragraph("Sommaire", title_style))
    story.append(Spacer(1, 12))
    story.append(Paragraph("1. Résumé exécutif", normal_style))
    story.append(Paragraph("2. Synthèse technique", normal_style))
    story.append(Paragraph("3. Vulnérabilités détectées", normal_style))
    story.append(Paragraph("4. Score de sécurité et niveau de gravité", normal_style))
    story.append(Paragraph("5. Graphique de synthèse", normal_style))
    story.append(Paragraph("6. Recommandations pour les développeurs", normal_style))
    story.append(Paragraph("7. Conclusion", normal_style))
    story.append(Paragraph("8. Annexe : résultats techniques bruts", normal_style))
    story.append(PageBreak())

    story.append(Paragraph("1. Résumé exécutif", subtitle_style))
    story.append(Paragraph(
        "Ce rapport présente les résultats d’une analyse automatisée de sécurité réalisée sur une cible réseau et web autorisée. "
        "L’objectif est d’identifier les services exposés, les vulnérabilités potentielles, les mauvaises configurations "
        "et les risques de sécurité détectables automatiquement.",
        normal_style
    ))

    story.append(Paragraph("2. Synthèse technique", subtitle_style))
    story.append(Paragraph(
        f"Nombre de ports ouverts détectés : <b>{nb_ports}</b><br/>"
        f"Nombre de points de sécurité identifiés : <b>{nb_vulns}</b>",
        normal_style
    ))

    story.append(Paragraph("3. Vulnérabilités détectées", subtitle_style))
    for line in ai_analysis.split("\n"):
        line = line.strip()
        if line:
            story.append(Paragraph(html.escape(line), normal_style))

    story.append(Paragraph("4. Score de sécurité et niveau de gravité", subtitle_style))
    story.append(Paragraph(
        f"<b>Score estimé :</b> {score}/100<br/>"
        f"<b>Niveau global :</b> {niveau}<br/><br/>"
        "Barème utilisé :<br/>"
        "• 90 à 100 : sécurisé<br/>"
        "• 70 à 89 : acceptable<br/>"
        "• 50 à 69 : vulnérable<br/>"
        "• Moins de 50 : critique",
        normal_style
    ))

    story.append(Paragraph("5. Graphique de synthèse", subtitle_style))
    story.append(Paragraph(
        "Le graphique suivant résume le nombre de ports ouverts, le nombre de vulnérabilités détectées "
        "et leur répartition par niveau de gravité.",
        normal_style
    ))
    story.append(Image(chart_path, width=15 * cm, height=8 * cm))

    story.append(Paragraph("6. Recommandations pour les développeurs", subtitle_style))
    story.append(Paragraph(
        "• Fermer ou restreindre les ports non nécessaires.<br/>"
        "• Limiter l’exposition de MySQL au réseau local uniquement.<br/>"
        "• Ajouter les en-têtes de sécurité HTTP manquants.<br/>"
        "• Protéger les pages sensibles comme les pages de connexion.<br/>"
        "• Mettre en place HTTPS si le site est utilisé hors environnement local.<br/>"
        "• Mettre à jour régulièrement Apache, PHP, MySQL et les dépendances associées.<br/>"
        "• Relancer régulièrement les scans après correction.",
        normal_style
    ))

    story.append(Paragraph("7. Conclusion", subtitle_style))
    story.append(Paragraph(
        "Le scan met en évidence plusieurs points d’attention liés à la configuration du serveur web. "
        "Dans un cadre pédagogique, ces résultats permettent de comprendre les risques liés aux services exposés "
        "et aux mauvaises configurations. Dans un contexte professionnel, les corrections recommandées devraient "
        "être appliquées avant toute mise en production.",
        normal_style
    ))

    story.append(PageBreak())

    story.append(Paragraph("8. Annexe : résultats techniques bruts", subtitle_style))
    story.append(Paragraph(
        "Cette annexe contient les sorties originales des outils Nmap, Nikto et SSLScan. "
        "Elle sert de preuve technique, tandis que les sections précédentes présentent l’analyse interprétée.",
        normal_style
    ))

    for line in raw_results.split("\n"):
        line = line.strip()
        if line:
            story.append(Paragraph(html.escape(line), code_style))

    doc.build(story, onFirstPage=add_page_number, onLaterPages=add_page_number)

    return send_file(
        pdf_path,
        as_attachment=True,
        download_name="rapport_scan_vulnerabilites_web.pdf",
        mimetype="application/pdf"
    )


if __name__ == "__main__":
    app.run(debug=True)
root@Ubuntu:/var/www/html/mon-site/scanner-auto#
