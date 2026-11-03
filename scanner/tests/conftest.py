"""Outils de test : un faux site qui imite l'Apache de la VM, et de faux Nmap/Nikto/SSLScan."""
import os
import stat
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DONNEES = Path(__file__).resolve().parent / "donnees"


class FauxApache(BaseHTTPRequestHandler):
    """Répond comme le site de la VM : Server avec version, cookie PHPSESSID sans HttpOnly,
    pas d'en-têtes de sécurité, DEBUG et TRACE refusés."""
    server_version = "Apache/2.4.52 (Ubuntu)"
    sys_version = ""

    def log_message(self, *args):
        pass

    def do_GET(self):
        corps = b"<html><body>Boutique de test</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "PHPSESSID=abc123; path=/")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, HEAD")
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture
def faux_site():
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), FauxApache)
    t = threading.Thread(target=serveur.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{serveur.server_address[1]}/mon-site/"
    serveur.shutdown()


def _script(dossier: Path, nom: str, contenu: str):
    f = dossier / nom
    f.write_text("#!/bin/sh\n" + contenu)
    f.chmod(f.stat().st_mode | stat.S_IEXEC)


@pytest.fixture
def faux_outils(tmp_path, monkeypatch):
    """Place de faux nmap / nikto / sslscan en tête du PATH (durées : 2 s, 3 s, 1 s)."""
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    _script(bin_, "nmap", f"""
if [ "$1" = "--version" ]; then echo "Nmap version 7.80 ( https://nmap.org )"; exit 0; fi
sleep 2
while [ $# -gt 0 ]; do if [ "$1" = "-oX" ]; then cp "{DONNEES}/nmap_vm.xml" "$2"; fi; shift; done
cat "{DONNEES}/nmap_vm.txt"
""")
    _script(bin_, "nikto", f"""
if [ "$1" = "-Version" ]; then echo "Nikto v2.1.5"; exit 0; fi
sleep 3
cat "{DONNEES}/nikto_vm.txt"
""")
    _script(bin_, "sslscan", f"""
if [ "$1" = "--version" ]; then echo "2.0.11-static"; exit 0; fi
sleep 1
cat "{DONNEES}/sslscan_exemple.txt"
""")
    monkeypatch.setenv("PATH", f"{bin_}{os.pathsep}{os.environ['PATH']}")
    return bin_
