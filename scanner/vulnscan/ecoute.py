"""Services en écoute sur la machine locale.

Quand la cible est la machine elle-même (localhost), Nmap voit « ouvert » un
service qui n'écoute pourtant que sur 127.0.0.1 et qui est donc injoignable
depuis le réseau. La commande `ss` donne l'adresse d'écoute réelle : elle permet
de trancher au lieu de laisser le constat « À vérifier ».
"""
import ipaddress
import shutil
import subprocess


def lire_ss(sortie: str) -> dict:
    """Transforme la sortie de `ss -H -tln` en {port: {adresses d'écoute}}."""
    ecoutes = {}
    for ligne in sortie.splitlines():
        champs = ligne.split()
        if len(champs) < 4 or champs[0] != "LISTEN":
            continue
        adresse, _, port = champs[3].rpartition(":")
        if not port.isdigit():
            continue
        adresse = adresse.strip("[]").split("%")[0]       # [::1] → ::1 ; 127.0.0.53%lo → 127.0.0.53
        ecoutes.setdefault(int(port), set()).add(adresse or "*")
    return ecoutes


def ecoutes_locales():
    """{port: {adresses}} pour cette machine, ou None si `ss` est indisponible."""
    if shutil.which("ss") is None:
        return None
    try:
        proc = subprocess.run(["ss", "-H", "-tln"], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return lire_ss(proc.stdout)


def locale_uniquement(adresses) -> bool:
    """Vrai si toutes les adresses d'écoute sont des adresses de bouclage (127.x.x.x, ::1)."""
    if not adresses:
        return False
    for a in adresses:
        try:
            if not ipaddress.ip_address(a).is_loopback:
                return False
        except ValueError:            # « * », « 0.0.0.0 » mal formé… : considéré comme exposé
            return False
    return True
