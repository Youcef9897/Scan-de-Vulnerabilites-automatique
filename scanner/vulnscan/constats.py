"""Transformation des résultats en constats rédigés en français.

Chaque constat a : une gravité, une preuve (outil et ligne observée),
une recommandation concrète et un état de vérification.
"""
import re
from dataclasses import dataclass, field, asdict

from .ecoute import locale_uniquement

GRAVITES = ["Élevée", "Moyenne", "Faible", "Info"]

CONFIRME = "Confirmé"
NON_CONFIRME = "Non confirmé"
FAUX_POSITIF = "Faux positif probable"
NON_VERIFIABLE = "À vérifier"


@dataclass
class Constat:
    titre: str
    gravite: str
    categorie: str
    description: str
    recommandation: str
    preuves: list = field(default_factory=list)
    sources: list = field(default_factory=list)
    verification: str = CONFIRME
    reference: str = ""
    code: str = ""

    def en_dict(self):
        return asdict(self)


def _baisser(gravite: str) -> str:
    i = GRAVITES.index(gravite)
    return GRAVITES[min(i + 1, len(GRAVITES) - 1)]


# ---------------------------------------------------------------- Réseau (Nmap)

SERVICES_RESEAU = {
    23: ("Telnet", "Élevée",
         "Telnet transmet les identifiants et les échanges en clair.",
         "Désactiver Telnet et utiliser SSH à la place."),
    21: ("FTP", "Moyenne",
         "FTP transmet les identifiants en clair.",
         "Désactiver FTP ou le remplacer par SFTP."),
    3389: ("bureau à distance (RDP)", "Moyenne",
           "Le bureau à distance exposé est une cible fréquente d'attaques par force brute.",
           "Ne pas exposer RDP directement : passer par un VPN et activer l'authentification réseau (NLA)."),
    3306: ("base de données MySQL/MariaDB", "Élevée",
           "Une base de données joignable depuis le réseau peut être attaquée directement (force brute, failles du serveur).",
           "Limiter l'écoute à 127.0.0.1 (paramètre bind-address de MySQL/MariaDB) et bloquer le port 3306 au pare-feu."),
    5432: ("base de données PostgreSQL", "Élevée",
           "Une base de données joignable depuis le réseau peut être attaquée directement.",
           "Limiter l'écoute à 127.0.0.1 (listen_addresses) et bloquer le port 5432 au pare-feu."),
    631: ("service d'impression CUPS", "Faible",
          "Un service d'impression n'a pas d'utilité sur un serveur web et augmente la surface d'attaque.",
          "Désactiver le service s'il n'est pas utilisé : systemctl disable --now cups"),
    25: ("serveur de messagerie SMTP", "Faible",
         "Un serveur de messagerie mal configuré peut servir de relais de spam.",
         "Vérifier qu'il n'accepte pas le relais ouvert, ou le désactiver s'il est inutile."),
    22: ("accès à distance SSH", "Info",
         "SSH est normal sur un serveur administré, à condition d'être bien configuré.",
         "Autoriser uniquement l'authentification par clé et interdire la connexion directe en root."),
}


def constats_reseau(cible, ports, ecoutes=None) -> list:
    """`ecoutes` : {port: {adresses d'écoute}} lu sur la machine quand la cible est locale (voir ecoute.py)."""
    resultats = []
    ouverts = [p for p in ports if p.etat == "open"]
    for p in ouverts:
        if p.numero not in SERVICES_RESEAU:
            continue
        nom, gravite, desc, reco = SERVICES_RESEAU[p.numero]
        verification = CONFIRME
        titre = f"Port {p.numero} ouvert : {nom}"
        preuves = []
        adresses = (ecoutes or {}).get(p.numero) if cible.est_locale else None
        if adresses and locale_uniquement(adresses):
            # Preuve directe : le service n'écoute que sur la machine elle-même.
            titre = f"Port {p.numero} en écoute locale uniquement : {nom}"
            gravite = "Info"
            desc = ("Ce service n'écoute que sur l'adresse locale de la machine : il n'est pas joignable "
                    "depuis le réseau. C'est la configuration recommandée.")
            reco = "Aucune action : conserver cette écoute limitée à l'adresse locale."
            preuves = [f"ss : écoute sur {', '.join(sorted(adresses))}:{p.numero}"]
        elif adresses:
            desc += (" Le service écoute sur une adresse joignable depuis le réseau "
                     "(sauf si un pare-feu le bloque).")
            preuves = [f"ss : écoute sur {', '.join(sorted(adresses))}:{p.numero}"]
        elif cible.est_locale and gravite != "Info":
            gravite = _baisser(gravite)
            verification = NON_VERIFIABLE
            desc += (" Le scan a été lancé depuis la machine elle-même : ce port n'est peut-être pas "
                     "joignable depuis le réseau. À revérifier depuis une autre machine.")
        version = f" ({p.version})" if p.version else ""
        resultats.append(Constat(
            titre=titre,
            gravite=gravite, categorie="Réseau", description=desc, recommandation=reco,
            preuves=[f"Nmap : {p.numero}/{p.protocole} open {p.service}{version}"] + preuves,
            sources=["Nmap"] + (["ss"] if preuves else []), verification=verification,
            reference="OWASP ASVS V14 — Configuration",
        ))
    return resultats


def constats_cve(ports, ecoutes=None, cible=None) -> list:
    """Un constat par service dont la version annoncée correspond à des CVE publiées."""
    resultats = []
    for p in ports:
        if p.etat != "open" or not p.cves:
            continue
        maxi = p.cves[0]["cvss"]
        # Constat fondé sur le seul numéro de version : un cran en dessous de la gravité CVSS.
        gravite = "Moyenne" if maxi >= 7 else "Faible" if maxi >= 4 else "Info"
        adresses = (ecoutes or {}).get(p.numero) if (cible is not None and cible.est_locale) else None
        locale = bool(adresses) and locale_uniquement(adresses)
        if locale:
            gravite = "Info"          # service injoignable depuis le réseau : à mettre à jour, sans urgence
        produit = p.version or p.service
        resultats.append(Constat(
            titre=f"{len(p.cves)} CVE connue(s) pour {produit} (port {p.numero})",
            gravite=gravite, categorie="Mises à jour",
            description=f"La version annoncée par le service correspond à {len(p.cves)} vulnérabilité(s) publiée(s), "
                        f"avec un score CVSS maximal de {maxi}. Ce constat repose uniquement sur le numéro de version : "
                        "sur Debian et Ubuntu, les correctifs de sécurité sont souvent appliqués sans changer ce numéro, "
                        "d'où l'état « À vérifier ».",
            recommandation=("Le service n'écoute que sur l'adresse locale : il n'est pas attaquable depuis le réseau. "
                            if locale else "")
                           + "Mettre le paquet à jour (apt update && apt upgrade), puis contrôler les CVE les plus graves "
                           "sur le suivi de sécurité de la distribution (par exemple ubuntu.com/security/CVE-AAAA-NNNN).",
            preuves=[f"vulners : {c['id']} (CVSS {c['cvss']}) — https://nvd.nist.gov/vuln/detail/{c['id']}"
                     for c in p.cves[:5]]
                    + ([f"… et {len(p.cves) - 5} autre(s)"] if len(p.cves) > 5 else []),
            sources=["Nmap (vulners)"], verification=NON_VERIFIABLE,
            reference="OWASP Top 10 A06 — Composants vulnérables et obsolètes"))
    return resultats


TITRE_LISTAGE = "Listage du contenu d'un dossier"


def constats_chemins(ch) -> list:
    """Constats tirés du contrôle des chemins sensibles (voir chemins.py). Tous sont reproduits par une requête."""
    if not ch:
        return []
    r = []
    if ch.get("secrets"):
        r.append(Constat(
            titre="Fichier de secrets ou de données téléchargeable",
            gravite="Élevée", categorie="Divulgation d'informations",
            description="Des fichiers qui contiennent habituellement des mots de passe, des clés ou des données "
                        "(configuration, dépôt Git, export de base, archive) peuvent être téléchargés sans authentification.",
            recommandation="Retirer ces fichiers du dossier servi par le serveur web, puis changer tout secret qu'ils contenaient.",
            preuves=[f"GET {e['chemin']} → {e['origine']}" for e in ch["secrets"][:10]],
            sources=["Chemins sensibles"], reference="OWASP WSTG — Review Old Backup and Unreferenced Files"))
    if ch.get("sources"):
        r.append(Constat(
            titre="Code source ou copie de sauvegarde téléchargeable",
            gravite="Moyenne", categorie="Divulgation d'informations",
            description="Du code source, des scripts ou des copies de sauvegarde sont servis tels quels : un attaquant "
                        "peut les lire pour comprendre le fonctionnement interne et y chercher des failles ou des secrets.",
            recommandation="Sortir ces fichiers du dossier public du serveur web (par exemple hors de /var/www/html) "
                           "et supprimer les copies de sauvegarde (.bak, .old).",
            preuves=[f"GET {e['chemin']} → {e['origine']}" for e in ch["sources"][:10]],
            sources=["Chemins sensibles"], reference="OWASP WSTG — Review Old Backup and Unreferenced Files"))
    if ch.get("listages"):
        r.append(Constat(
            titre=TITRE_LISTAGE,
            gravite="Moyenne", categorie="Configuration",
            description="Le contenu d'un dossier est affiché : des fichiers non prévus pour le public peuvent être découverts.",
            recommandation="Désactiver le listage : « Options -Indexes » dans la configuration Apache.",
            preuves=[f"GET {d} → page « Index of »" for d in ch["listages"][:10]],
            sources=["Chemins sensibles"], reference="OWASP WSTG — Configuration and Deployment Management"))
    if ch.get("admin"):
        r.append(Constat(
            titre="Zone d'administration joignable",
            gravite="Faible", categorie="Contrôle d'accès",
            description="Un dossier d'administration répond sans filtrage par adresse. Le contrôle ne dit pas si une "
                        "authentification le protège : c'est à vérifier à la main.",
            recommandation="Restreindre l'accès (adresse IP ou authentification forte) et limiter les tentatives de connexion.",
            preuves=[f"GET {d} → code 200" for d in ch["admin"]],
            sources=["Chemins sensibles"], verification=NON_VERIFIABLE,
            reference="OWASP WSTG — Enumerate Infrastructure and Application Admin Interfaces"))
    return r


def _constat_etag(lignes, obs) -> Constat:
    """Nikto annonce une fuite d'inode dès qu'il voit un ETag. On regarde le nombre de champs :
    3 champs = inode-taille-date (fuite réelle, anciens Apache) ; 2 champs = taille-date (pas d'inode)."""
    champs = None
    for l in lignes:
        m = re.search(r"fields:\s*((?:0x[0-9a-f]+\s*)+)", l, re.I)
        if m:
            champs = len(m.group(1).split())
        elif re.search(r"inode:\s*\S+", l, re.I):
            champs = 3
    entete = next((v for k, v in (obs.get("entetes") or {}).items() if k.lower() == "etag"), "")
    if entete:
        # Apache ajoute « -gzip » ou « -br » quand la page est compressée : ce n'est pas un champ de l'ETag.
        valeur = re.sub(r"-(gzip|br|deflate|zstd)$", "", entete.strip().removeprefix("W/").strip('"'))
        champs = len(valeur.split("-"))
    preuves = [f"Nikto : {l}" for l in lignes] + ([f"Vérification : ETag = {entete}"] if entete else [])
    if champs is not None and champs < 3:
        return Constat(
            titre="Fuite d'inode par l'en-tête ETag signalée par Nikto",
            gravite="Info", categorie="Divulgation d'informations",
            description=f"L'ETag observé n'a que {champs} champ(s) (taille et date du fichier) : il ne contient pas de "
                        "numéro d'inode. Depuis Apache 2.4, l'inode n'est plus inclus par défaut ; cette alerte de Nikto "
                        "vise les anciennes versions.",
            recommandation="Aucune action nécessaire.",
            preuves=preuves, sources=["Nikto"] + (["Vérification"] if entete else []), verification=FAUX_POSITIF,
            reference="OWASP WSTG — Configuration and Deployment Management")
    return Constat(
        titre="Informations internes divulguées par l'en-tête ETag",
        gravite="Faible", categorie="Divulgation d'informations",
        description="L'en-tête ETag contient des informations internes au serveur (numéro d'inode).",
        recommandation="Sous Apache : « FileETag MTime Size ».",
        preuves=preuves, sources=["Nikto"] + (["Vérification"] if entete else []),
        verification=CONFIRME if champs else NON_VERIFIABLE,
        reference="OWASP WSTG — Configuration and Deployment Management")


# ---------------------------------------------------------------- Web (vérification + Nikto)

def _lignes(nikto, motif):
    return [l for l in nikto["constats"] if re.search(motif, l, re.I)]


# Nikto 2.1.5 signale comme « inhabituel » tout en-tête qu'il ne connaît pas, y compris les en-têtes de sécurité
# récents. Leur présence est une bonne nouvelle : ces lignes ne doivent donner aucun constat.
ENTETE_DE_SECURITE_PRESENT = re.compile(
    r"Uncommon header '(x-frame-options|x-content-type-options|content-security-policy|referrer-policy|"
    r"permissions-policy|strict-transport-security|cross-origin-[a-z-]+)' found", re.I)

COOKIES_SESSION = re.compile(r"(sess|sid|jsession|phpsessid|token|auth)", re.I)


def constats_web(cible, nikto, obs, ports) -> list:
    r = []
    nikto = {**nikto, "constats": [l for l in nikto["constats"] if not ENTETE_DE_SECURITE_PRESENT.search(l)]}
    https = cible.schema == "https"

    # HTTPS
    if not https:
        preuves = ["Vérification : le site répond en HTTP"]
        p443 = next((p for p in ports if p.numero == 443), None)
        if p443:
            preuves.append(f"Nmap : 443/tcp {p443.etat}")
        if not obs.get("https_disponible"):
            r.append(Constat(
                titre="Site disponible uniquement en HTTP (pas de HTTPS)",
                gravite="Moyenne", categorie="Chiffrement",
                description="Les échanges (y compris les identifiants saisis dans un formulaire) circulent en clair "
                            "et peuvent être lus ou modifiés sur le réseau.",
                recommandation="Activer HTTPS (certificat Let's Encrypt en production, auto-signé en lab), "
                               "puis rediriger tout le trafic HTTP vers HTTPS.",
                preuves=preuves, sources=["Vérification", "Nmap"], reference="OWASP Top 10 A02 — Défaillances cryptographiques"))
        elif not obs.get("redirige_vers_https"):
            r.append(Constat(
                titre="HTTP ne redirige pas vers HTTPS",
                gravite="Faible", categorie="Chiffrement",
                description="HTTPS existe, mais un visiteur qui tape l'adresse en HTTP reste sur une connexion non chiffrée.",
                recommandation="Ajouter une redirection permanente (301) de HTTP vers HTTPS.",
                preuves=preuves, sources=["Vérification"], reference="OWASP Top 10 A02"))

    # Protection contre le clickjacking
    lignes_xfo = _lignes(nikto, r"X-Frame-Options")
    if not obs.get("protection_cadres", True) or lignes_xfo:
        confirme = not obs.get("protection_cadres", True)
        r.append(Constat(
            titre="Pas de protection contre le « clickjacking »",
            gravite="Moyenne" if confirme else "Faible", categorie="En-têtes HTTP",
            description="Le site peut être affiché dans un cadre (iframe) sur un site malveillant, qui pousse "
                        "l'utilisateur à cliquer sans le savoir sur des boutons du vrai site.",
            recommandation="Ajouter l'en-tête « X-Frame-Options: DENY » (ou « Content-Security-Policy: frame-ancestors 'none' »). "
                           "Sous Apache : Header always set X-Frame-Options \"DENY\" (module headers).",
            preuves=(["Vérification : aucun en-tête X-Frame-Options ni frame-ancestors"] if confirme else [])
                    + [f"Nikto : {l}" for l in lignes_xfo],
            sources=(["Vérification"] if confirme else []) + (["Nikto"] if lignes_xfo else []),
            verification=CONFIRME if confirme else NON_CONFIRME,
            reference="OWASP — Clickjacking Defense Cheat Sheet"))

    absents = obs.get("entetes_absents", [])
    lignes_xcto = _lignes(nikto, r"X-Content-Type-Options")
    if "X-Content-Type-Options" in absents:
        r.append(Constat(
            titre="En-tête X-Content-Type-Options absent",
            gravite="Faible", categorie="En-têtes HTTP",
            description="Le navigateur peut « deviner » le type d'un fichier et exécuter comme script un contenu qui n'en est pas un.",
            recommandation="Ajouter l'en-tête « X-Content-Type-Options: nosniff ».",
            preuves=["Vérification : en-tête absent de la réponse"] + [f"Nikto : {l}" for l in lignes_xcto],
            sources=["Vérification"] + (["Nikto"] if lignes_xcto else []),
            reference="OWASP Secure Headers Project"))
    if "Content-Security-Policy" in absents:
        r.append(Constat(
            titre="Pas de politique de sécurité du contenu (CSP)",
            gravite="Faible", categorie="En-têtes HTTP",
            description="Sans CSP, une éventuelle faille d'injection de script (XSS) a plus d'impact, car le navigateur "
                        "exécute tout script présent dans la page.",
            recommandation="Définir un en-tête Content-Security-Policy, en commençant par « default-src 'self' » puis en l'ajustant.",
            preuves=["Vérification : en-tête Content-Security-Policy absent"], sources=["Vérification"],
            reference="OWASP — Content Security Policy Cheat Sheet"))
    # HSTS : contrôlé sur la réponse HTTPS du site, même quand l'adresse analysée est en HTTP.
    hsts_absent = (obs["hsts_present"] is False) if "hsts_present" in obs \
        else (https and "Strict-Transport-Security" in absents)
    if hsts_absent:
        r.append(Constat(
            titre="HSTS non activé",
            gravite="Faible", categorie="En-têtes HTTP",
            description="Sans HSTS, un attaquant sur le réseau peut forcer une première connexion en HTTP non chiffré.",
            recommandation="Ajouter « Strict-Transport-Security: max-age=31536000; includeSubDomains ».",
            preuves=["Vérification : en-tête Strict-Transport-Security absent"], sources=["Vérification"],
            reference="OWASP — HTTP Strict Transport Security Cheat Sheet"))
    autres = [h for h in ("Referrer-Policy", "Permissions-Policy") if h in absents]
    if autres:
        r.append(Constat(
            titre="En-têtes de confidentialité recommandés absents",
            gravite="Info", categorie="En-têtes HTTP",
            description="Ces en-têtes limitent les informations transmises aux autres sites et l'accès aux fonctions du navigateur.",
            recommandation="Ajouter « Referrer-Policy: strict-origin-when-cross-origin » et un en-tête Permissions-Policy adapté.",
            preuves=[f"Vérification : {', '.join(autres)} absent(s)"], sources=["Vérification"],
            reference="OWASP Secure Headers Project"))

    # Version du serveur affichée
    banniere = obs.get("serveur") or nikto.get("banniere", "")
    if banniere and re.search(r"\d", banniere):
        r.append(Constat(
            titre="Version du serveur web affichée",
            gravite="Faible", categorie="Divulgation d'informations",
            description=f"Le serveur annonce son logiciel et sa version (« {banniere} »). Un attaquant peut ainsi "
                        "chercher directement les failles connues de cette version.",
            recommandation="Sous Apache : « ServerTokens Prod » et « ServerSignature Off » "
                           "(fichier /etc/apache2/conf-available/security.conf), puis systemctl reload apache2.",
            preuves=[f"Vérification : en-tête Server = {banniere}"] if obs.get("serveur") else [f"Nikto : Server: {banniere}"],
            sources=["Vérification"] if obs.get("serveur") else ["Nikto"],
            reference="OWASP WSTG — Fingerprint Web Server"))
    if obs.get("powered_by") and re.search(r"\d", obs["powered_by"]):
        r.append(Constat(
            titre="Version de PHP affichée",
            gravite="Faible", categorie="Divulgation d'informations",
            description=f"L'en-tête X-Powered-By révèle la technologie et sa version (« {obs['powered_by']} »).",
            recommandation="Dans php.ini : « expose_php = Off », puis redémarrer le service web.",
            preuves=[f"Vérification : X-Powered-By = {obs['powered_by']}"], sources=["Vérification"],
            reference="OWASP WSTG — Fingerprint Web Application Framework"))

    # Cookies
    vus = set()
    for c in obs.get("cookies", []):
        manques = []
        if not c["httponly"]:
            manques.append("HttpOnly")
        if https and not c["secure"]:
            manques.append("Secure")
        if not c["samesite"]:
            manques.append("SameSite")
        if not manques:
            continue
        vus.add(c["nom"].lower())
        session = bool(COOKIES_SESSION.search(c["nom"]))
        grave = "Moyenne" if session and ("HttpOnly" in manques or "Secure" in manques) else "Faible"
        lignes = [l for l in _lignes(nikto, r"cookie") if c["nom"].lower() in l.lower()]
        r.append(Constat(
            titre=f"Cookie « {c['nom']} » sans protection ({', '.join(manques)})",
            gravite=grave, categorie="Session",
            description=("Ce cookie de session peut être volé par un script malveillant (faille XSS) "
                         "ou envoyé sur une connexion non protégée." if session else
                         "Ce cookie n'a pas tous les attributs de sécurité recommandés."),
            recommandation="Poser le cookie avec les attributs HttpOnly, Secure (en HTTPS) et SameSite=Lax. "
                           "En PHP : session.cookie_httponly = 1, session.cookie_secure = 1, session.cookie_samesite = Lax.",
            preuves=[f"Vérification : Set-Cookie: {c['brut'][:120]}"] + [f"Nikto : {l}" for l in lignes],
            sources=["Vérification"] + (["Nikto"] if lignes else []),
            reference="OWASP — Session Management Cheat Sheet"))
    for l in _lignes(nikto, r"cookie .+ created without"):
        m = re.search(r"cookie (\S+) created", l, re.I)
        nom = m.group(1) if m else "?"
        if nom.lower() in vus:
            continue
        vus.add(nom.lower())
        r.append(Constat(
            titre=f"Cookie « {nom} » sans attribut HttpOnly (signalé par Nikto)",
            gravite="Faible", categorie="Session",
            description="Nikto a vu ce cookie sur une autre page du site que celle analysée directement : "
                        "la vérification n'a pas pu le reproduire sur l'adresse scannée.",
            recommandation="Vérifier la page qui pose ce cookie et ajouter HttpOnly, Secure et SameSite.",
            preuves=[f"Nikto : {l}"], sources=["Nikto"], verification=NON_CONFIRME,
            reference="OWASP — Session Management Cheat Sheet"))

    # Méthodes HTTP
    if obs.get("trace_active"):
        r.append(Constat(
            titre="Méthode TRACE activée",
            gravite="Moyenne", categorie="Configuration",
            description="TRACE renvoie la requête reçue : combinée à une faille XSS, elle peut exposer des cookies (attaque XST).",
            recommandation="Sous Apache : « TraceEnable Off ».",
            preuves=["Vérification : la requête TRACE est acceptée (code 200)"], sources=["Vérification"],
            reference="OWASP WSTG — Test HTTP Methods"))
    for l in _lignes(nikto, r"DEBUG HTTP verb"):
        if obs.get("debug_accepte"):
            etat, grav, desc = CONFIRME, "Moyenne", "Le serveur accepte la méthode DEBUG, qui peut révéler des informations de débogage."
        elif obs.get("debug_code") == 200:
            etat, grav = FAUX_POSITIF, "Info"
            desc = ("Le serveur répond 200 à DEBUG, mais avec sa page normale et non la réponse « OK » du débogage "
                    "à distance d'ASP.NET : l'application (PHP par exemple) répond simplement à toutes les méthodes. "
                    "Aucune information de débogage n'est exposée.")
        else:
            etat, grav = FAUX_POSITIF, "Info"
            desc = (f"La vérification directe montre que la méthode DEBUG est refusée (code {obs.get('debug_code')}). "
                    "Cette alerte concerne surtout les serveurs IIS : sur Apache, c'est presque toujours un faux positif.")
        r.append(Constat(
            titre="Méthode DEBUG signalée par Nikto",
            gravite=grav, categorie="Configuration", description=desc,
            recommandation="Aucune action si la méthode est refusée ; sinon, la désactiver dans la configuration du serveur.",
            preuves=[f"Nikto : {l}", f"Vérification : DEBUG (Command: stop-debug) → code {obs.get('debug_code')}"
                     + (", réponse « OK » du débogage" if obs.get("debug_accepte")
                        else ", page normale du site" if obs.get("debug_code") == 200 else "")],
            sources=["Nikto", "Vérification"], verification=etat,
            reference="OWASP WSTG — Test HTTP Methods"))
    methodes = obs.get("methodes_annoncees", "")
    for l in _lignes(nikto, r"Allowed HTTP Methods:"):
        methodes = methodes or l.split(":", 1)[1]
    dangereuses = [m for m in ("PUT", "DELETE", "PATCH") if re.search(rf"\b{m}\b", methodes or "", re.I)]
    if dangereuses:
        r.append(Constat(
            titre=f"Méthodes HTTP sensibles annoncées ({', '.join(dangereuses)})",
            gravite="Moyenne", categorie="Configuration",
            description="Ces méthodes permettent de déposer ou de supprimer des fichiers si le serveur les autorise réellement.",
            recommandation="Limiter les méthodes à GET, POST et HEAD (directive <LimitExcept> sous Apache).",
            preuves=[f"Méthodes annoncées : {methodes.strip()}"], sources=["Vérification", "Nikto"],
            verification=NON_VERIFIABLE, reference="OWASP WSTG — Test HTTP Methods"))

    # Autres constats Nikto connus
    regles_nikto = [
        (r"directory indexing", "Listage du contenu d'un dossier", "Moyenne", "Configuration",
         "Le contenu d'un dossier est affiché : des fichiers non prévus pour le public peuvent être découverts.",
         "Désactiver le listage : « Options -Indexes » dans la configuration Apache."),
        (r"appears to be outdated", "Version du serveur web obsolète", "Moyenne", "Mises à jour",
         "Le logiciel serveur n'est plus à jour et peut contenir des failles corrigées depuis.",
         "Mettre à jour le serveur : apt update && apt upgrade."),
        (r"phpinfo", "Page phpinfo() accessible", "Moyenne", "Divulgation d'informations",
         "La page phpinfo() révèle la configuration complète de PHP et du serveur.",
         "Supprimer ce fichier du site."),
        (r"admin(istration)? (login|section|page)", "Page d'administration accessible", "Moyenne", "Contrôle d'accès",
         "Une page d'administration est joignable : elle peut être visée par des attaques par force brute.",
         "Restreindre l'accès (par adresse IP ou authentification forte) et limiter les tentatives de connexion."),
        (r"default file|/icons/README", "Fichier par défaut du serveur présent", "Faible", "Configuration",
         "Des fichiers d'exemple installés avec le serveur sont accessibles et confirment le logiciel utilisé.",
         "Supprimer ou bloquer l'accès aux fichiers par défaut (par exemple le dossier /icons/)."),
        (r"X-XSS-Protection", "En-tête X-XSS-Protection absent", "Info", "En-têtes HTTP",
         "Cet en-tête est obsolète et ignoré par les navigateurs récents : son absence n'est pas un risque. "
         "La vraie protection est la politique CSP (voir le constat correspondant).",
         "Aucune action nécessaire ; privilégier Content-Security-Policy."),
        (r"Multiple index files", "Plusieurs pages d'accueil possibles détectées", "Info", "Configuration",
         "Nikto a obtenu une réponse pour plusieurs noms de page d'accueil ; c'est souvent un comportement normal du serveur.",
         "Aucune action nécessaire si ces pages n'existent pas réellement."),
    ]
    lignes_etag = _lignes(nikto, r"ETags")
    if lignes_etag:
        r.append(_constat_etag(lignes_etag, obs))
    deja = re.compile(r"(X-Frame-Options|X-Content-Type-Options|cookie .+ created without|DEBUG HTTP verb|Allowed HTTP Methods|ETags)", re.I)
    for ligne in nikto["constats"]:
        if deja.search(ligne):
            continue
        for motif, titre, grav, cat, desc, reco in regles_nikto:
            if re.search(motif, ligne, re.I):
                existant = next((c for c in r if c.titre == titre), None)
                if existant:
                    existant.preuves.append(f"Nikto : {ligne}")
                else:
                    r.append(Constat(titre=titre, gravite=grav, categorie=cat, description=desc,
                                     recommandation=reco, preuves=[f"Nikto : {ligne}"], sources=["Nikto"],
                                     verification=NON_VERIFIABLE,
                                     reference="OWASP WSTG — Configuration and Deployment Management"))
                break
        else:
            r.append(Constat(
                titre="Observation de Nikto à examiner",
                gravite="Info", categorie="À examiner",
                description="Nikto a signalé cet élément, qui n'est pas classé automatiquement : il doit être lu et vérifié à la main.",
                recommandation="Lire la ligne de preuve et vérifier si elle s'applique à ce site.",
                preuves=[f"Nikto : {ligne}"], sources=["Nikto"], verification=NON_VERIFIABLE))
    return r


# ---------------------------------------------------------------- Chiffrement (SSLScan)

def _constat_certificat(ssl, obs, cible) -> Constat:
    """Le certificat n'est pas accepté par un navigateur : le constat dépend de la raison et de la cible."""
    raison = obs.get("certificat_raison") or ("auto-signé" if ssl.get("auto_signe") else "")
    preuves = ["Vérification : le certificat est refusé par la vérification d'un navigateur"
               + (f" ({obs['certificat_detail']})" if obs.get("certificat_detail") else "")]
    if ssl.get("certificat_expire_le"):
        preuves.append(f"SSLScan : Not valid after: {ssl['certificat_expire_le']}")
    commun = dict(categorie="Chiffrement", preuves=preuves, sources=["Vérification", "SSLScan"],
                  reference="OWASP Top 10 A02 — Défaillances cryptographiques")
    if raison in ("expiré", "pas encore valide"):
        return Constat(
            titre="Certificat expiré" if raison == "expiré" else "Certificat pas encore valide", gravite="Moyenne",
            description="Les dates de validité du certificat ne couvrent pas la date du jour : les visiteurs "
                        "voient une alerte de sécurité et prennent l'habitude de l'ignorer.",
            recommandation="Renouveler le certificat et automatiser son renouvellement (par exemple avec certbot).",
            **commun)
    if raison == "nom différent":
        return Constat(
            titre="Certificat émis pour un autre nom que le site", gravite="Moyenne",
            description="Le certificat ne correspond pas au nom utilisé pour joindre le site : le navigateur "
                        "ne peut pas garantir qu'il parle au bon serveur.",
            recommandation="Générer un certificat dont le nom (champ subjectAltName) correspond à l'adresse du site.",
            **commun)
    if raison in ("auto-signé", "autorité inconnue") and cible is not None and cible.est_privee:
        # Cible de lab : aucune autorité publique ne délivre de certificat pour localhost ou une adresse privée.
        # Le chiffrement fonctionne, mais l'identité du serveur n'est pas garantie : le point reste compté, en Faible.
        return Constat(
            titre="Certificat auto-signé (acceptable en lab, à remplacer en production)", gravite="Faible",
            description="Les échanges sont chiffrés, mais le certificat n'est signé par aucune autorité reconnue : "
                        "le navigateur affiche une alerte et ne peut pas distinguer le vrai serveur d'un intermédiaire. "
                        "Sur une adresse locale ou privée, aucune autorité publique ne peut délivrer de certificat : "
                        "c'est le maximum possible en lab.",
            recommandation="En production, utiliser un certificat délivré par une autorité reconnue "
                           "(par exemple Let's Encrypt avec certbot). En lab, une autorité interne (mkcert) "
                           "installée sur les postes supprime l'alerte.",
            **commun)
    return Constat(
        titre="Certificat non reconnu par les navigateurs", gravite="Moyenne",
        description="Le certificat est auto-signé ou signé par une autorité inconnue : les visiteurs voient une "
                    "alerte, et une interception devient plus difficile à repérer.",
        recommandation="Utiliser un certificat délivré par une autorité reconnue (par exemple Let's Encrypt).",
        **commun)


def constats_tls(ssl, obs, cible=None) -> list:
    r = []
    prot = ssl.get("protocoles", {})
    anciens = [p for p in ("SSLv2", "SSLv3") if prot.get(p)]
    if anciens:
        r.append(Constat(
            titre=f"Protocoles obsolètes et cassés activés ({', '.join(anciens)})", gravite="Élevée", categorie="Chiffrement",
            description="Ces protocoles ont des failles connues (par exemple POODLE) qui permettent de déchiffrer les échanges.",
            recommandation="Les désactiver : « SSLProtocol -all +TLSv1.2 +TLSv1.3 » sous Apache.",
            preuves=[f"SSLScan : {p} enabled" for p in anciens], sources=["SSLScan"],
            reference="ANSSI — Recommandations de sécurité relatives à TLS"))
    vieux = [p for p in ("TLSv1.0", "TLSv1.1") if prot.get(p)]
    if vieux:
        r.append(Constat(
            titre=f"Versions anciennes de TLS activées ({', '.join(vieux)})", gravite="Moyenne", categorie="Chiffrement",
            description="TLS 1.0 et 1.1 sont dépréciés et ne doivent plus être proposés.",
            recommandation="N'autoriser que TLS 1.2 et TLS 1.3.",
            preuves=[f"SSLScan : {p} enabled" for p in vieux], sources=["SSLScan"],
            reference="ANSSI — Recommandations de sécurité relatives à TLS"))
    if ssl.get("chiffrements_faibles"):
        r.append(Constat(
            titre="Suites de chiffrement faibles acceptées", gravite="Moyenne", categorie="Chiffrement",
            description="Le serveur accepte des algorithmes de chiffrement considérés comme faibles.",
            recommandation="Restreindre les suites de chiffrement à des suites modernes (par exemple le profil « intermediate » de Mozilla).",
            preuves=[f"SSLScan : {c}" for c in ssl["chiffrements_faibles"][:8]], sources=["SSLScan"],
            reference="ANSSI — Recommandations de sécurité relatives à TLS"))
    if ssl.get("taille_cle_rsa") and ssl["taille_cle_rsa"] < 2048:
        r.append(Constat(
            titre=f"Clé RSA trop courte ({ssl['taille_cle_rsa']} bits)", gravite="Moyenne", categorie="Chiffrement",
            description="Une clé de moins de 2048 bits n'offre plus une protection suffisante.",
            recommandation="Générer un nouveau certificat avec une clé RSA d'au moins 2048 bits (ou une clé ECDSA).",
            preuves=[f"SSLScan : RSA Key Strength: {ssl['taille_cle_rsa']}"], sources=["SSLScan"],
            reference="ANSSI — Recommandations de sécurité relatives à TLS"))
    if obs.get("certificat_valide") is False:
        r.append(_constat_certificat(ssl, obs, cible))
    return r


# ---------------------------------------------------------------- ZAP passif (étape S4-B)

def _preuves_zap(alerte, limite=5) -> list:
    lignes = []
    for i in alerte["instances"][:limite]:
        detail = "; ".join(x for x in ((f"paramètre : {i['param']}" if i["param"] else ""),
                                       (f"preuve : {i['preuve']}" if i["preuve"] else "")) if x)
        lignes.append(f"ZAP : {alerte['nom']} — {i['methode']} {i['uri']}" + (f" ({detail})" if detail else ""))
    reste = len(alerte["instances"]) - limite
    if reste > 0:
        lignes.append(f"ZAP : … et {reste} autre(s) page(s)")
    return lignes


def _completer(existant, alerte):
    """ZAP a vu un problème déjà trouvé par la plateforme : il ajoute sa preuve, sans second constat."""
    if "ZAP" not in existant.sources:
        existant.sources.append("ZAP")
    pages = sorted({i["uri"] for i in alerte["instances"]})
    existant.preuves.append(f"ZAP : {alerte['nom']} — vu sur {len(pages)} page(s) : " + ", ".join(pages[:3])
                            + (" …" if len(pages) > 3 else ""))


def _gravite_zap(fiche, alerte) -> tuple:
    """Gravité et état de vérification d'un constat qui ne vient que de ZAP."""
    from .zap import CONFIANCE_FAIBLE, RISQUES
    gravite = (fiche or {}).get("gravite") or RISQUES[alerte["risque"]]
    sure = alerte["confiance"] > CONFIANCE_FAIBLE
    if fiche and fiche["factuel"] and sure:
        return gravite, CONFIRME
    if not sure or fiche is None:
        gravite = _baisser(gravite)        # indice peu sûr, ou règle sans fiche : un cran en dessous
    return gravite, NON_VERIFIABLE


def constats_zap(alertes, existants) -> list:
    """Constats tirés des alertes passives de ZAP, sans doublon avec `existants` (complétés sur place)."""
    from .regles_zap import fiche as fiche_de
    nouveaux = []

    def chercher(motif):
        return next((c for c in existants + nouveaux if re.search(motif, c.titre, re.I)), None)

    for a in alertes:
        f = fiche_de(a)
        if f and f["par_cookie"]:
            par_nom = {}
            for i in a["instances"]:
                par_nom.setdefault(i["param"] or "?", []).append(i)
            for nom, instances in par_nom.items():
                partie = {**a, "instances": instances}
                deja = chercher(rf"^cookie « {re.escape(nom)} »")
                if deja:
                    _completer(deja, partie)
                    continue
                gravite, etat = _gravite_zap(f, partie)
                nouveaux.append(Constat(
                    titre=f"Cookie « {nom} » {f['titre']} (vu par ZAP)", gravite=gravite, categorie=f["categorie"],
                    description=f["description"] + " ZAP l'a vu sur une autre page que celle analysée directement.",
                    recommandation=f["recommandation"], preuves=_preuves_zap(partie), sources=["ZAP"],
                    verification=etat, reference=f["reference"]))
            continue
        if f:
            deja = chercher(f["doublon"]) if f["doublon"] else None
            deja = deja or next((c for c in nouveaux if c.titre == f["titre"]), None)
            if deja:
                _completer(deja, a)
                continue
            gravite, etat = _gravite_zap(f, a)
            nouveaux.append(Constat(
                titre=f["titre"], gravite=gravite, categorie=f["categorie"], description=f["description"],
                recommandation=f["recommandation"], preuves=_preuves_zap(a), sources=["ZAP"],
                verification=etat, reference=f["reference"]))
            continue
        gravite, etat = _gravite_zap(None, a)
        nouveaux.append(Constat(
            titre=f"ZAP : {a['nom']}", gravite=gravite, categorie="À examiner",
            description="ZAP a signalé cette alerte, qui n'a pas encore de fiche en français dans la plateforme : "
                        "elle doit être lue et vérifiée à la main. Description d'origine (en anglais) : "
                        + (a["description"][:400] or "non fournie."),
            recommandation="Conseil de ZAP (en anglais) : " + (a["solution"][:400] or "non fourni."),
            preuves=_preuves_zap(a), sources=["ZAP"], verification=etat,
            reference=(f"CWE-{a['cwe']} — " if a["cwe"] > 0 else "") + f"règle ZAP {a['ref']}"))
    return nouveaux


# ---------------------------------------------------------------- Assemblage

def construire(cible, ports, nikto, ssl, obs, ecoutes=None, chemins=None, zap=None) -> list:
    tous = (constats_reseau(cible, ports, ecoutes) + constats_cve(ports, ecoutes, cible) + constats_chemins(chemins)
            + constats_web(cible, nikto, obs, ports) + constats_tls(ssl, obs, cible))
    if zap:
        tous += constats_zap(zap, tous)
    # Un listage vu à la fois par notre contrôle et par Nikto ne fait qu'un seul constat.
    listages = [c for c in tous if c.titre == TITRE_LISTAGE]
    if len(listages) > 1:
        garde = listages[0]
        for autre in listages[1:]:
            garde.preuves += autre.preuves
            garde.sources += [s for s in autre.sources if s not in garde.sources]
            tous.remove(autre)
    ordre_verif = {CONFIRME: 0, NON_VERIFIABLE: 1, NON_CONFIRME: 2, FAUX_POSITIF: 3}
    tous.sort(key=lambda c: (GRAVITES.index(c.gravite), ordre_verif.get(c.verification, 9), c.titre))
    for i, c in enumerate(tous, 1):
        c.code = f"C{i:02d}"
    return tous
