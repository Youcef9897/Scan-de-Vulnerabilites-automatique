"""Validation de la cible : format, liste blanche, accessibilité."""
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from . import config


class CibleRefusee(Exception):
    """La cible ne peut pas être scannée (message en français pour l'utilisateur)."""


@dataclass
class Cible:
    url: str            # URL complète, par exemple http://localhost/mon-site/
    schema: str         # http ou https
    hote: str           # nom d'hôte ou adresse IP
    port: int
    adresses: list = field(default_factory=list)  # adresses IP résolues

    @property
    def est_locale(self) -> bool:
        """Vrai si la cible est la machine elle-même (127.0.0.1, ::1)."""
        return bool(self.adresses) and all(ipaddress.ip_address(a).is_loopback for a in self.adresses)


def _resoudre(hote: str) -> list:
    try:
        infos = socket.getaddrinfo(hote, None)
    except socket.gaierror:
        raise CibleRefusee(f"Le nom « {hote} » est introuvable (DNS).")
    return sorted({i[4][0] for i in infos})


def est_autorisee(hote: str, adresses: list, liste_blanche=None) -> bool:
    """Vrai si le nom d'hôte, ou toutes ses adresses IP, figurent dans la liste blanche."""
    liste_blanche = config.CIBLES_AUTORISEES if liste_blanche is None else liste_blanche
    reseaux, noms = [], set()
    for entree in liste_blanche:
        try:
            reseaux.append(ipaddress.ip_network(entree, strict=False))
        except ValueError:
            noms.add(entree.lower())
    if hote.lower() in noms:
        return True
    if not adresses:
        return False
    return all(any(ipaddress.ip_address(a) in r for r in reseaux) for a in adresses)


def preparer_cible(saisie: str, liste_blanche=None, verifier_acces: bool = True) -> Cible:
    """Transforme la saisie de l'utilisateur en cible validée, ou lève CibleRefusee."""
    saisie = (saisie or "").strip()
    if not saisie:
        raise CibleRefusee("Indique une adresse à analyser.")
    if not saisie.startswith(("http://", "https://")):
        saisie = "http://" + saisie

    p = urlparse(saisie)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise CibleRefusee("Adresse invalide : utilise par exemple http://localhost/mon-site/")
    hote = p.hostname
    port = p.port or (443 if p.scheme == "https" else 80)
    adresses = _resoudre(hote)

    if not est_autorisee(hote, adresses, liste_blanche):
        raise CibleRefusee(
            f"La cible « {hote} » n'est pas dans la liste des cibles autorisées. "
            "Pour des raisons légales, seules les machines dont tu as l'autorisation peuvent être scannées."
        )

    url = f"{p.scheme}://{p.netloc}{p.path or '/'}"
    if p.query:
        url += "?" + p.query

    if verifier_acces:
        try:
            requests.get(url, timeout=config.DUREE_MAX_HTTP, allow_redirects=True, verify=False)
        except requests.RequestException:
            raise CibleRefusee(f"Le site {url} ne répond pas.")

    return Cible(url=url, schema=p.scheme, hote=hote, port=port, adresses=adresses)
