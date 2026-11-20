"""La méthode DEBUG n'est confirmée que si le serveur donne la vraie réponse du débogage ASP.NET.

Constat de la boutique NetStock Lab (20/11) : PHP répond 200 à DEBUG avec sa page normale,
ce que l'ancienne vérification prenait pour une faille (−8 points à tort).
"""
import threading
from http.server import ThreadingHTTPServer

from conftest import FauxApache
from vulnscan import constats, verification
from vulnscan.cible import preparer_cible

NIKTO = {"constats": ["DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com for details."]}


class FauxPhp(FauxApache):
    """Comme une application PHP : toute méthode inconnue reçoit la page normale."""
    def do_DEBUG(self):
        self.do_GET()


class FauxIisDebug(FauxApache):
    """Comme ASP.NET avec le débogage à distance actif."""
    def do_DEBUG(self):
        corps = b"OK" if self.headers.get("Command") == "stop-debug" else b"<html>page</html>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(corps)))
        self.end_headers()
        self.wfile.write(corps)


def _observer(handler):
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=serveur.serve_forever, daemon=True).start()
    try:
        cible = preparer_cible(f"http://127.0.0.1:{serveur.server_address[1]}/", liste_blanche=["127.0.0.1"])
        return cible, verification.verifier(cible)
    finally:
        serveur.shutdown()


def _constat_debug(cible, obs):
    return next(c for c in constats.constats_web(cible, NIKTO, obs, []) if c.titre == "Méthode DEBUG signalée par Nikto")


def test_php_qui_repond_200_a_debug_est_un_faux_positif():
    cible, obs = _observer(FauxPhp)
    assert obs["debug_code"] == 200 and obs["debug_accepte"] is False
    c = _constat_debug(cible, obs)
    assert c.verification == constats.FAUX_POSITIF and c.gravite == "Info"
    assert "page normale" in c.description and "page normale du site" in c.preuves[1]


def test_vrai_debogage_asp_net_reste_confirme():
    cible, obs = _observer(FauxIisDebug)
    assert obs["debug_accepte"] is True
    c = _constat_debug(cible, obs)
    assert c.verification == constats.CONFIRME and c.gravite == "Moyenne"
    assert "réponse « OK »" in c.preuves[1]


def test_le_rapport_rappelle_ce_que_l_analyse_ne_couvre_pas():
    from vulnscan import score
    s = score.calculer([])
    assert "injection SQL" in s["perimetre"] and "ne garantit pas" in s["perimetre"]
