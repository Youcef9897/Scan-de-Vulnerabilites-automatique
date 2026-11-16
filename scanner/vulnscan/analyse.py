"""Lecture des sorties des outils : on transforme du texte brut en données structurées."""
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict, field
from pathlib import Path


@dataclass
class Port:
    numero: int
    protocole: str
    etat: str        # open, closed, filtered
    service: str
    version: str     # produit + version, par exemple « Apache httpd 2.4.52 (Ubuntu) »
    cves: list = field(default_factory=list)   # [{"id": "CVE-…", "cvss": 9.8}], du score le plus haut au plus bas

    def en_dict(self):
        return asdict(self)


def lire_cves(port_xml) -> list:
    """CVE trouvées par le script « vulners » de Nmap pour un port, sans doublon, triées par score CVSS."""
    script = next((s for s in port_xml.iter("script") if s.get("id") == "vulners"), None)
    if script is None:
        return []
    trouvees = {}
    for table in script.iter("table"):
        champs = {e.get("key"): (e.text or "").strip() for e in table.findall("elem")}
        ident = champs.get("id", "")
        if not ident.startswith("CVE-"):
            continue                  # les autres lignes sont des références d'exploits, pas des CVE
        try:
            cvss = float(champs.get("cvss", ""))
        except ValueError:
            continue
        trouvees[ident] = max(cvss, trouvees.get(ident, 0.0))
    if not trouvees:                  # anciennes versions du script : seulement du texte
        for ident, cvss in re.findall(r"(CVE-\d{4}-\d+)\s+(\d+(?:\.\d+)?)", script.get("output", "")):
            trouvees[ident] = max(float(cvss), trouvees.get(ident, 0.0))
    return [{"id": i, "cvss": c} for i, c in sorted(trouvees.items(), key=lambda x: (-x[1], x[0]))]


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
                                           f"({svc.get('extrainfo').strip('()')})" if svc.get("extrainfo") else None) if x)
        ports.append(Port(
            numero=int(p.get("portid")),
            protocole=p.get("protocol", "tcp"),
            etat=etat.get("state", "") if etat is not None else "",
            service=nom,
            version=version,
            cves=lire_cves(p),
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
