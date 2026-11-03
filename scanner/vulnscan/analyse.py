"""Lecture des sorties des outils : on transforme du texte brut en données structurées."""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Port:
    numero: int
    protocole: str
    etat: str        # open, closed, filtered
    service: str
    version: str     # produit + version, par exemple « Apache httpd 2.4.52 (Ubuntu) »

    def en_dict(self):
        return asdict(self)


def lire_nmap_xml(fichier: Path) -> list:
    """Liste des ports à partir du fichier XML de Nmap (vide si absent ou illisible)."""
    if not fichier.exists():
        return []
    try:
        racine = ET.parse(fichier).getroot()
    except ET.ParseError:
        return []
    ports = []
    for p in racine.iter("port"):
        etat = p.find("state")
        svc = p.find("service")
        version = ""
        nom = ""
        if svc is not None:
            nom = svc.get("name", "")
            version = " ".join(x for x in (svc.get("product"), svc.get("version"),
                                           f"({svc.get('extrainfo')})" if svc.get("extrainfo") else None) if x)
        ports.append(Port(
            numero=int(p.get("portid")),
            protocole=p.get("protocol", "tcp"),
            etat=etat.get("state", "") if etat is not None else "",
            service=nom,
            version=version,
        ))
    return sorted(ports, key=lambda x: x.numero)


# Lignes de Nikto qui décrivent le déroulement du scan, pas un constat.
_NIKTO_META = re.compile(
    r"^\+ (Target (IP|Hostname|Port)|Start Time|End Time|\d+ host\(s\) tested|\d+ items checked|"
    r"No CGI Directories found|SSL Info|Ciphers|Issuer|Subject|Root page / redirects)", re.I)


def lire_nikto(sortie: str) -> dict:
    """Retourne la bannière du serveur, les lignes de constats et les informations de déroulement."""
    banniere = ""
    constats = []
    elements_testes = None
    for ligne in sortie.splitlines():
        l = ligne.strip()
        if not l.startswith("+ "):
            continue
        m = re.match(r"^\+ Server:\s*(.+)$", l)
        if m:
            banniere = m.group(1).strip()
            continue
        m = re.match(r"^\+ (\d+) items checked", l)
        if m:
            elements_testes = int(m.group(1))
            continue
        if _NIKTO_META.match(l) or l.startswith("+ ERROR"):
            continue
        constats.append(l[2:].strip())
    return {"banniere": banniere, "constats": constats, "elements_testes": elements_testes}


def lire_sslscan(sortie: str) -> dict:
    """Protocoles activés, suites de chiffrement faibles et état du certificat."""
    protocoles = {}
    for m in re.finditer(r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)",
                         sortie, re.M | re.I):
        protocoles[m.group(1)] = m.group(2).lower() == "enabled"
    faibles = sorted({m.group(1) for m in re.finditer(
        r"^(?:Accepted|Preferred)\s+\S+\s+\d+\s+bits\s+(\S*(?:RC4|DES|NULL|EXP|MD5|anon)\S*)", sortie, re.M)})
    expire = None
    m = re.search(r"Not valid after:\s*(.+)", sortie)
    if m:
        expire = m.group(1).strip()
    cle = None
    m = re.search(r"RSA Key Strength:\s*(\d+)", sortie)
    if m:
        cle = int(m.group(1))
    auto_signe = bool(re.search(r"self[- ]signed", sortie, re.I))
    return {"protocoles": protocoles, "chiffrements_faibles": faibles,
            "certificat_expire_le": expire, "taille_cle_rsa": cle, "auto_signe": auto_signe}
