"""Réglages du scanner.

Chaque valeur peut être changée sans toucher au code, avec une variable
d'environnement du même nom, par exemple :

    CIBLES_AUTORISEES="localhost,192.168.56.0/24" python3 app.py
"""
import os
from pathlib import Path

DOSSIER_BASE = Path(__file__).resolve().parent.parent
DOSSIER_SCANS = Path(os.environ.get("DOSSIER_SCANS", DOSSIER_BASE / "scans"))

# Liste blanche : seules ces cibles peuvent être scannées.
# Noms d'hôte exacts, adresses IP ou réseaux (notation CIDR), séparés par des virgules.
CIBLES_AUTORISEES = [
    c.strip()
    for c in os.environ.get("CIBLES_AUTORISEES", "localhost,127.0.0.1,192.168.56.0/24").split(",")
    if c.strip()
]

# Ports vérifiés par Nmap (services web, bases de données, administration à distance).
NMAP_PORTS = os.environ.get("NMAP_PORTS", "21,22,23,25,80,443,631,3306,3389,5432,8080,8443")

# Durées maximales, en secondes.
DUREE_MAX_NMAP = int(os.environ.get("DUREE_MAX_NMAP", "120"))
DUREE_MAX_NIKTO = int(os.environ.get("DUREE_MAX_NIKTO", "240"))
DUREE_MAX_SSLSCAN = int(os.environ.get("DUREE_MAX_SSLSCAN", "90"))
DUREE_MAX_HTTP = int(os.environ.get("DUREE_MAX_HTTP", "8"))

# Résumé rédigé par l'IA locale (Ollama). IA_ACTIVE=0 pour s'en passer.
IA_ACTIVE = os.environ.get("IA_ACTIVE", "1") == "1"
IA_URL = os.environ.get("IA_URL", "http://localhost:11434/api/generate")
IA_MODELE = os.environ.get("IA_MODELE", "mistral")
IA_DUREE_MAX = int(os.environ.get("IA_DUREE_MAX", "120"))
IA_LONGUEUR_MAX = int(os.environ.get("IA_LONGUEUR_MAX", "260"))  # en jetons (≈ mots)

# Serveur web de la plateforme : uniquement sur la machine locale par défaut.
HOTE_ECOUTE = os.environ.get("HOTE_ECOUTE", "127.0.0.1")
PORT_ECOUTE = int(os.environ.get("PORT_ECOUTE", "5000"))
