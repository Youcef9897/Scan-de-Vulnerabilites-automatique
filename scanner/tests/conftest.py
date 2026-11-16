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


class FauxSiteFragile(BaseHTTPRequestHandler):
    """Imite le site de la VM tel qu'il est vraiment : listage de dossiers activé,
    code source et copie de sauvegarde téléchargeables, 404 pour le reste."""
    server_version = "Apache/2.4.52 (Ubuntu)"
    sys_version = ""
    PAGES = {
        "/mon-site/": ("text/html", '<html><head><link rel="stylesheet" href="assets/css/style.css"></head>'
                                    '<body><a href="login.html">Espace Pro</a><img src="assets/img/jean1.jpg"></body></html>'),
        "/mon-site/login.html": ("text/html", "<html><body>Login</body></html>"),
        "/mon-site/assets/": ("text/html", '<html><head><title>Index of /mon-site/assets</title></head><body>'
                                           '<a href="?C=N;O=D">Name</a><a href="/mon-site/">Parent Directory</a>'
                                           '<a href="css/">css/</a><a href="img/">img/</a></body></html>'),
        "/mon-site/assets/img/": ("text/html", '<html><head><title>Index of /mon-site/assets/img</title></head>'
                                               '<body><a href="jean1.jpg">jean1.jpg</a></body></html>'),
        "/mon-site/assets/css/": ("text/html", '<html><head><title>Index of /mon-site/assets/css</title></head>'
                                               '<body><a href="style.css">style.css</a></body></html>'),
        "/mon-site/scanner-auto/": ("text/html", '<html><head><title>Index of /mon-site/scanner-auto</title></head><body>'
                                                 '<a href="app.py">app.py</a><a href="app.py.bak">app.py.bak</a>'
                                                 '<a href="templates/">templates/</a></body></html>'),
        "/mon-site/scanner-auto/app.py": ("text/x-python", "from flask import Flask"),
        "/mon-site/scanner-auto/app.py.bak": ("application/octet-stream", "from flask import Flask"),
        "/mon-site/login.html.bak": ("application/octet-stream", "<html>ancienne page</html>"),
        "/mon-site/admin/": ("text/html", "<html><body>Administration</body></html>"),
        "/hors-perimetre/secret.env": ("text/plain", "MOT=1"),
    }
    demandes = []

    def log_message(self, *args):
        pass

    def do_GET(self):
        type(self).demandes.append(self.path)
        if self.path in self.PAGES:
            genre, texte = self.PAGES[self.path]
            corps = texte.encode()
            self.send_response(200)
            self.send_header("Content-Type", genre)
        else:
            corps = b"<html><body>404 Not Found</body></html>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)


@pytest.fixture
def site_fragile():
    FauxSiteFragile.demandes = []
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), FauxSiteFragile)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{serveur.server_address[1]}/mon-site/"
    serveur.shutdown()
