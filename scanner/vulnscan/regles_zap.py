"""Fiches en français des alertes passives de ZAP (étape S4-B).

Une alerte de ZAP porte un numéro de règle (« pluginid », par exemple 10020) et parfois un numéro plus précis
(« alertRef », par exemple 10020-1). La fiche est cherchée d'abord par alertRef, puis par pluginid.
Les numéros viennent de la liste officielle : https://www.zaproxy.org/docs/alerts/

Champs d'une fiche :
  titre, gravite (None = reprendre le niveau de risque de ZAP), categorie, description, recommandation, reference
  doublon : motif cherché dans le titre des constats déjà trouvés par la plateforme. S'il correspond,
            ZAP ne crée pas de second constat : il ajoute sa preuve au constat existant.
  factuel : True si l'alerte décrit un fait lu dans la réponse du site (en-tête absent, cookie sans attribut).
            Sinon c'est un indice que ZAP ne peut pas trancher seul : le constat reste « À vérifier ».
  par_cookie : True si l'alerte vise un cookie précis (un constat par cookie).
"""

# Alertes d'information qui ne décrivent pas une faiblesse : elles ne deviennent pas des constats.
IGNOREES = {
    "10049": "Mise en cache du contenu",
    "10050": "Réponse servie depuis un cache",
    "10109": "Application web moderne détectée",
    "10111": "Requête d'authentification repérée",
    "10112": "Réponse de gestion de session repérée",
    "10113": "Requête de vérification repérée",
    "10116": "ZAP n'est pas à jour",
    "90005": "En-têtes Sec-Fetch-* absents de la requête",
}

_OWASP_ENTETES = "OWASP — HTTP Headers Cheat Sheet"
_OWASP_SESSION = "OWASP — Session Management Cheat Sheet"
_RECO_COOKIE = ("Poser le cookie avec les attributs HttpOnly, Secure (en HTTPS) et SameSite=Lax. "
                "En PHP : session.cookie_httponly = 1, session.cookie_secure = 1, session.cookie_samesite = Lax.")


def _f(titre, gravite, categorie, description, recommandation, reference="", doublon=None, factuel=False,
       par_cookie=False):
    return {"titre": titre, "gravite": gravite, "categorie": categorie, "description": description,
            "recommandation": recommandation, "reference": reference, "doublon": doublon, "factuel": factuel,
            "par_cookie": par_cookie}


FICHES = {
    # ------------------------------------------------------------ En-têtes HTTP (déjà contrôlés par la plateforme)
    "10020": _f("Pas de protection contre le « clickjacking »", "Moyenne", "En-têtes HTTP",
                "Des pages peuvent être affichées dans un cadre (iframe) sur un site malveillant, qui pousse "
                "l'utilisateur à cliquer sans le savoir sur des boutons du vrai site.",
                "Ajouter l'en-tête « X-Frame-Options: DENY » (ou « Content-Security-Policy: frame-ancestors 'none' ») "
                "sur toutes les pages. Sous Apache : Header always set X-Frame-Options \"DENY\" (module headers).",
                "OWASP — Clickjacking Defense Cheat Sheet", doublon=r"clickjacking", factuel=True),
    "10021": _f("En-tête X-Content-Type-Options absent", "Faible", "En-têtes HTTP",
                "Sans cet en-tête, le navigateur peut deviner le type d'un fichier et exécuter comme un script "
                "un fichier qui n'en est pas un.",
                "Ajouter l'en-tête « X-Content-Type-Options: nosniff » sur toutes les réponses.",
                _OWASP_ENTETES, doublon=r"x-content-type-options", factuel=True),
    "10038": _f("Pas de politique de sécurité du contenu (CSP)", "Faible", "En-têtes HTTP",
                "Sans politique CSP, le navigateur exécute tout script présent dans la page, y compris un script "
                "injecté par une faille XSS.",
                "Définir un en-tête Content-Security-Policy, en commençant par « default-src 'self' » puis en l'ajustant.",
                "OWASP — Content Security Policy Cheat Sheet", doublon=r"politique de sécurité du contenu",
                factuel=True),
    "10055": _f("Politique de sécurité du contenu (CSP) trop permissive", "Faible", "En-têtes HTTP",
                "Une politique CSP existe, mais elle autorise des sources trop larges (joker, « unsafe-inline », "
                "« unsafe-eval ») ou oublie une directive : elle protège moins bien contre les scripts injectés.",
                "Resserrer la politique : retirer « unsafe-inline » et « unsafe-eval », remplacer les jokers par la "
                "liste des domaines réellement utilisés, et définir « form-action » et « frame-ancestors ».",
                "OWASP — Content Security Policy Cheat Sheet", factuel=True),
    "10035": _f("HSTS non activé", "Faible", "En-têtes HTTP",
                "Sans l'en-tête Strict-Transport-Security (ou s'il est mal écrit), le navigateur peut encore "
                "joindre le site en HTTP, ce qui permet une interception.",
                "En HTTPS, ajouter « Strict-Transport-Security: max-age=31536000; includeSubDomains ».",
                _OWASP_ENTETES, doublon=r"hsts", factuel=True),
    "10063": _f("En-têtes de confidentialité recommandés absents", "Info", "En-têtes HTTP",
                "L'en-tête Permissions-Policy, qui limite l'accès des pages à la caméra, au micro ou à la position, "
                "n'est pas défini.",
                "Ajouter un en-tête Permissions-Policy adapté, par exemple "
                "« geolocation=(), camera=(), microphone=() ».",
                _OWASP_ENTETES, doublon=r"en-têtes de confidentialité", factuel=True),
    "90004": _f("Isolation entre sites incomplète (en-têtes Cross-Origin-*)", "Info", "En-têtes HTTP",
                "Les en-têtes Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy ou Cross-Origin-Opener-Policy "
                "ne sont pas définis. Ils renforcent l'isolation du site dans le navigateur.",
                "Ajouter « Cross-Origin-Opener-Policy: same-origin » et « Cross-Origin-Resource-Policy: same-origin » "
                "si le site ne partage pas ses ressources avec d'autres sites.",
                _OWASP_ENTETES, factuel=True),

    # ------------------------------------------------------------ Divulgation d'informations
    "10036-1": _f("Logiciel serveur annoncé (sans numéro de version)", "Info", "Divulgation d'informations",
                  "L'en-tête Server donne le nom du logiciel serveur, sans sa version. C'est le réglage recommandé "
                  "quand l'en-tête ne peut pas être retiré.",
                  "Aucune action nécessaire.", "OWASP WSTG — Fingerprint Web Server", factuel=True),
    "10036": _f("Version du serveur web affichée", "Faible", "Divulgation d'informations",
                "Le serveur annonce son logiciel et sa version. Un attaquant peut ainsi chercher directement "
                "les failles connues de cette version.",
                "Sous Apache : « ServerTokens Prod » et « ServerSignature Off » "
                "(fichier /etc/apache2/conf-available/security.conf), puis systemctl reload apache2.",
                "OWASP WSTG — Fingerprint Web Server", doublon=r"version du serveur web affichée", factuel=True),
    "10037": _f("Technologie du site annoncée (en-tête X-Powered-By)", "Faible", "Divulgation d'informations",
                "L'en-tête X-Powered-By révèle la technologie du site (par exemple PHP et sa version).",
                "En PHP : « expose_php = Off » dans php.ini. Sinon, retirer l'en-tête dans la configuration du serveur.",
                "OWASP WSTG — Fingerprint Web Application Framework", doublon=r"version de php affichée",
                factuel=True),
    "10009": _f("Version du serveur visible dans une page d'erreur", "Faible", "Divulgation d'informations",
                "Une page d'erreur affiche le nom et la version du logiciel serveur.",
                "Sous Apache : « ServerSignature Off » et « ServerTokens Prod », ou des pages d'erreur personnalisées.",
                "OWASP WSTG — Fingerprint Web Server", factuel=True),
    "10023": _f("Message d'erreur de débogage affiché", "Faible", "Divulgation d'informations",
                "Une page contient un message d'erreur technique qui renseigne sur le fonctionnement interne du site.",
                "Désactiver l'affichage des erreurs en production (en PHP : display_errors = Off) et les écrire "
                "dans un journal.", "OWASP WSTG — Testing for Improper Error Handling"),
    "90022": _f("Message d'erreur de l'application affiché", "Moyenne", "Divulgation d'informations",
                "Une page affiche une erreur de l'application (erreur PHP ou SQL, trace d'exécution). Ces messages "
                "révèlent des chemins, des requêtes ou des noms de tables utiles à un attaquant.",
                "Désactiver l'affichage des erreurs (en PHP : display_errors = Off), afficher une page d'erreur "
                "neutre et écrire le détail dans un journal.", "OWASP WSTG — Testing for Improper Error Handling"),
    "110009": _f("Chemin interne du serveur visible dans une page", "Faible", "Divulgation d'informations",
                 "Une page affiche un chemin complet du serveur (par exemple /var/www/…).",
                 "Désactiver l'affichage des erreurs et retirer les chemins internes des pages.",
                 "OWASP WSTG — Testing for Improper Error Handling"),
    "10027": _f("Commentaires à relire dans le code des pages", "Info", "Divulgation d'informations",
                "Le code des pages contient des commentaires avec des mots comme « TODO », « admin » ou « password ». "
                "Ils peuvent donner des indications à un attaquant.",
                "Relire ces commentaires et retirer ceux qui décrivent le fonctionnement interne.",
                "OWASP WSTG — Review Webpage Content for Information Leakage"),
    "10024": _f("Information sensible dans une adresse (URL)", "Faible", "Divulgation d'informations",
                "Une adresse contient une information sensible (mot de passe, jeton, identifiant). Les adresses "
                "sont enregistrées dans l'historique du navigateur et dans les journaux du serveur.",
                "Envoyer ces informations dans le corps d'une requête POST, jamais dans l'adresse.",
                "OWASP Top 10 A02 — Défaillances cryptographiques"),
    "10025": _f("Information sensible transmise par l'en-tête Referer", "Faible", "Divulgation d'informations",
                "Une adresse contenant une information sensible est transmise à un autre site par l'en-tête Referer.",
                "Ne pas mettre d'information sensible dans les adresses et ajouter « Referrer-Policy: "
                "strict-origin-when-cross-origin ».", _OWASP_ENTETES),
    "10096": _f("Horodatage visible dans une page", "Info", "Divulgation d'informations",
                "ZAP a repéré un nombre qui ressemble à une date au format Unix. C'est très souvent un faux positif "
                "(un simple nombre dans une feuille de style ou un script).",
                "Vérifier la valeur citée en preuve ; aucune action si ce n'est pas une date sensible.", ""),
    "2": _f("Adresse IP privée visible dans une page", "Faible", "Divulgation d'informations",
            "Une page contient une adresse IP interne (10.x, 172.16.x ou 192.168.x), qui renseigne sur le réseau.",
            "Retirer les adresses internes des pages et des en-têtes.",
            "OWASP WSTG — Review Webpage Content for Information Leakage"),
    "10099": _f("Code source PHP visible dans une page", "Moyenne", "Divulgation d'informations",
                "Une réponse du site contient du code PHP non exécuté : le serveur l'envoie tel quel au visiteur.",
                "Vérifier que PHP est bien activé pour ces fichiers et retirer les copies de fichiers sources du site.",
                "OWASP WSTG — Review Old Backup and Unreferenced Files"),
    "10097": _f("Empreinte de mot de passe (hash) visible dans une page", None, "Divulgation d'informations",
                "Une page contient une chaîne qui ressemble à l'empreinte (hash) d'un mot de passe.",
                "Retirer cette valeur de la page et changer le mot de passe concerné.",
                "OWASP Top 10 A02 — Défaillances cryptographiques"),
    "10062": _f("Données personnelles visibles dans une page", None, "Divulgation d'informations",
                "Une page contient une donnée qui ressemble à une donnée personnelle sensible "
                "(par exemple un numéro de carte bancaire).",
                "Vérifier la valeur citée en preuve et la retirer ou la masquer si elle est réelle.",
                "OWASP Top 10 A02 — Défaillances cryptographiques"),

    # ------------------------------------------------------------ Session et cookies
    "10010": _f("sans attribut HttpOnly", "Faible", "Session",
                "Ce cookie peut être lu par un script de la page : une faille XSS suffirait à le voler.",
                _RECO_COOKIE, _OWASP_SESSION, factuel=True, par_cookie=True),
    "10011": _f("sans attribut Secure", "Faible", "Session",
                "Ce cookie peut être envoyé sur une connexion HTTP non chiffrée.",
                _RECO_COOKIE, _OWASP_SESSION, factuel=True, par_cookie=True),
    "10054": _f("sans attribut SameSite correct", "Faible", "Session",
                "Ce cookie est envoyé avec les requêtes venant d'autres sites, ce qui facilite les attaques CSRF.",
                _RECO_COOKIE, _OWASP_SESSION, factuel=True, par_cookie=True),
    "3": _f("Identifiant de session dans l'adresse (URL)", "Moyenne", "Session",
            "L'identifiant de session apparaît dans l'adresse des pages : il peut fuiter par l'historique, "
            "les journaux ou l'en-tête Referer.",
            "Transmettre l'identifiant de session uniquement dans un cookie (en PHP : session.use_only_cookies = 1).",
            _OWASP_SESSION),
    "10202": _f("Formulaire sans jeton anti-CSRF", "Moyenne", "Session",
                "Un formulaire ne contient aucun jeton anti-CSRF connu. Un site malveillant pourrait faire envoyer "
                "ce formulaire par un visiteur connecté, à son insu. À confirmer à la main : un formulaire de simple "
                "recherche n'est pas concerné.",
                "Ajouter un jeton aléatoire, propre à la session, dans chaque formulaire qui modifie des données, "
                "et le vérifier côté serveur. Compléter avec des cookies SameSite.",
                "OWASP — Cross-Site Request Forgery Prevention Cheat Sheet"),
    "10105": _f("Authentification faible (identifiants peu protégés)", "Moyenne", "Session",
                "Le site utilise une authentification HTTP de type Basic ou Digest, ou transmet des identifiants "
                "sans chiffrement.",
                "Passer le site en HTTPS et utiliser un formulaire de connexion avec une session protégée.",
                "OWASP Top 10 A07 — Identification et authentification de mauvaise qualité"),

    # ------------------------------------------------------------ Contenu des pages
    "10003": _f("Bibliothèque JavaScript vulnérable", "Moyenne", "Mises à jour",
                "Le site charge une bibliothèque JavaScript dont la version a des failles connues.",
                "Mettre à jour la bibliothèque citée en preuve vers sa dernière version.",
                "OWASP Top 10 A06 — Composants vulnérables et obsolètes"),
    "90003": _f("Scripts externes chargés sans contrôle d'intégrité (SRI)", "Faible", "Contenu des pages",
                "Des scripts ou des feuilles de style viennent d'un autre site sans attribut « integrity ». "
                "Si cet autre site est compromis, le code modifié s'exécute sur les pages.",
                "Ajouter les attributs « integrity » et « crossorigin » aux balises concernées, ou héberger "
                "ces fichiers sur le site.", "OWASP — Third Party JavaScript Management Cheat Sheet", factuel=True),
    "10098": _f("Partage entre origines (CORS) trop ouvert", "Moyenne", "Configuration",
                "Le serveur autorise n'importe quel site à lire ses réponses (Access-Control-Allow-Origin: *).",
                "Limiter Access-Control-Allow-Origin aux sites qui en ont réellement besoin.",
                "OWASP WSTG — Testing Cross Origin Resource Sharing", factuel=True),
    "10040": _f("Page HTTPS avec du contenu chargé en HTTP", "Faible", "Chiffrement",
                "Une page en HTTPS charge des éléments en HTTP : ils peuvent être modifiés pendant le transport.",
                "Charger tous les éléments en HTTPS.", "OWASP Top 10 A02 — Défaillances cryptographiques",
                factuel=True),
    "10041": _f("Formulaire d'une page HTTP envoyé vers HTTPS", "Moyenne", "Chiffrement",
                "Le formulaire est affiché en HTTP : il peut être modifié avant l'envoi pour détourner les données.",
                "Servir aussi la page du formulaire en HTTPS.", "OWASP Top 10 A02 — Défaillances cryptographiques",
                factuel=True),
    "10042": _f("Formulaire d'une page HTTPS envoyé en HTTP", "Moyenne", "Chiffrement",
                "Les données du formulaire partent sans chiffrement.",
                "Envoyer le formulaire vers une adresse HTTPS.", "OWASP Top 10 A02 — Défaillances cryptographiques",
                factuel=True),
    "10108": _f("Lien ouvrant un nouvel onglet sans protection (tabnabbing)", "Faible", "Contenu des pages",
                "Un lien avec target=\"_blank\" permet à la page ouverte de remplacer la page d'origine.",
                "Ajouter rel=\"noopener noreferrer\" aux liens qui ouvrent un nouvel onglet.",
                "OWASP — HTML5 Security Cheat Sheet", factuel=True),
    "10110": _f("Fonctions JavaScript à risque utilisées", "Info", "Contenu des pages",
                "Le code des pages utilise des fonctions comme eval() ou innerHTML, souvent à l'origine de failles XSS.",
                "Vérifier que ces fonctions ne reçoivent jamais de données venant de l'utilisateur.",
                "OWASP — DOM based XSS Prevention Cheat Sheet"),
    "10031": _f("Paramètre repris dans la page (piste de XSS à tester)", "Info", "Contenu des pages",
                "Une valeur envoyée par l'utilisateur est reprise dans le code de la page. Ce n'est pas une faille "
                "prouvée, mais un endroit à tester à la main (injection de script).",
                "Tester ce paramètre à la main et échapper les valeurs affichées (en PHP : htmlspecialchars).",
                "OWASP — Cross Site Scripting Prevention Cheat Sheet"),
    "10043": _f("Paramètre repris dans un événement JavaScript (piste de XSS à tester)", "Info", "Contenu des pages",
                "Une valeur envoyée par l'utilisateur est reprise dans un attribut d'événement (onclick, onload…).",
                "Tester ce paramètre à la main et ne jamais placer de données de l'utilisateur dans du JavaScript.",
                "OWASP — Cross Site Scripting Prevention Cheat Sheet"),
    "10028": _f("Redirection possible vers un autre site", None, "Contenu des pages",
                "Un paramètre de la requête semble décider de l'adresse de redirection : un lien piégé pourrait "
                "envoyer le visiteur vers un site malveillant en passant par le vrai site.",
                "Ne rediriger que vers une liste d'adresses connues, jamais vers une adresse reçue en paramètre.",
                "OWASP — Unvalidated Redirects and Forwards Cheat Sheet"),

    # ------------------------------------------------------------ Divers
    "10033": _f("Listage du contenu d'un dossier", "Moyenne", "Configuration",
                "Le contenu d'un dossier est affiché : des fichiers non prévus pour le public peuvent être découverts.",
                "Désactiver le listage : « Options -Indexes » dans la configuration Apache.",
                "OWASP WSTG — Configuration and Deployment Management", doublon=r"listage du contenu d'un dossier",
                factuel=True),
    "20020": _f("Version du serveur avec des failles connues (signalée par ZAP)", "Faible", "Mises à jour",
                "D'après son numéro de version, le serveur ou PHP a des failles publiées. Sur Debian et Ubuntu, "
                "les correctifs sont souvent appliqués sans changer ce numéro.",
                "Mettre le paquet à jour (apt update && apt upgrade) et contrôler les CVE sur le suivi de sécurité "
                "de la distribution.", "OWASP Top 10 A06 — Composants vulnérables et obsolètes",
                doublon=r"cve connue\(s\) pour .*(apache|php)"),
    "10015": _f("Directives de cache à revoir", "Info", "Configuration",
                "L'en-tête Cache-Control n'interdit pas la mise en cache. C'est normal pour des pages publiques ; "
                "c'est à corriger pour les pages qui affichent des données personnelles.",
                "Pour les pages privées : « Cache-Control: no-store ».", _OWASP_ENTETES),
    "10019": _f("Réponse sans en-tête Content-Type", "Info", "Configuration",
                "Une réponse n'indique pas son type de contenu : le navigateur doit le deviner.",
                "Configurer le serveur pour envoyer un Content-Type sur chaque réponse.", _OWASP_ENTETES,
                factuel=True),
}


def fiche(alerte: dict):
    """Fiche d'une alerte (cherchée par alertRef puis par pluginid), ou None si elle n'est pas connue."""
    return FICHES.get(alerte.get("ref", "")) or FICHES.get(alerte.get("plugin", ""))
