"""
ScanAgent — collecte active.

Contrairement au ReconAgent, chaque fonction ici établit une connexion réelle
vers l'infrastructure de la cible. C'est pour ça que `run_active_scan` exige
un paramètre `authorized=True` explicite : ce module ne doit jamais être
invocable par accident sans que l'appelant ait confirmé que la vérification
de propriété (voir services/verification_service.py) a bien réussi. Ce n'est
pas une garantie suffisante à elle seule — le vrai garde-fou reste l'edge
conditionnelle de l'orchestrateur — mais une ligne de défense supplémentaire
ne coûte rien.

Toutes les requêtes sont volontairement prudentes : timeouts courts, pas de
répétition agressive, délai entre les tests de chemins sensibles.
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CONNECT_TIMEOUT = 1.5
HTTP_TIMEOUT = 10.0
MAX_WORKERS = 40
SENSITIVE_PATH_DELAY = 0.3  # secondes entre deux requêtes, pour ne pas marteler le serveur

# Sous-ensemble volontairement limité des ports les plus significatifs pour un
# audit web/infra classique — pas les 65535, ni même les 1000 du "top nmap",
# pour rester raisonnable en temps sur un MVP. Facile à étendre plus tard.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2375, 3000, 3306, 3389, 5000, 5432, 5900,
    5984, 6379, 8000, 8080, 8081, 8443, 8888, 9000, 9200, 27017,
]

WEAK_TLS_PROTOCOLS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
}

WEAK_CIPHER_PATTERNS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/config.php.bak",
    "/backup.zip",
    "/backup.sql",
    "/.aws/credentials",
    "/admin",
    "/phpinfo.php",
    "/.DS_Store",
    "/docker-compose.yml",
    "/id_rsa",
]


class UnauthorizedScanError(RuntimeError):
    """Levée si run_active_scan est appelé sans confirmation explicite d'autorisation."""


# --------------------------------------------------------------------------- #
# Scan de ports + banner grabbing
# --------------------------------------------------------------------------- #

def _resolve_host(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror as exc:
        logger.warning("Résolution impossible pour %s : %s", domain, exc)
        return None


def _grab_banner(ip: str, port: int) -> str | None:
    """Tente de lire ce que le service annonce à la connexion.

    Pour les ports HTTP courants, envoie une requête HEAD minimale pour
    provoquer une réponse — beaucoup de serveurs web ne parlent pas tant
    qu'on ne leur écrit rien.
    """
    try:
        with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as sock:
            sock.settimeout(CONNECT_TIMEOUT)
            if port in (80, 8000, 8080, 8888, 9000):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
            try:
                data = sock.recv(1024)
                return data.decode(errors="replace").strip() or None
            except (socket.timeout, ConnectionResetError):
                return None
    except (OSError, socket.timeout):
        return None


def scan_ports(domain: str, ports: list[int] | None = None) -> dict[str, Any]:
    """Scan TCP connect sur une liste de ports, avec banner grabbing sur les ports ouverts.

    Un scan "connect" (pas SYN) : plus lent qu'un scan SYN brut, mais ne
    nécessite aucun privilège root/administrateur et reste sans ambiguïté
    du point de vue du serveur cible (connexion TCP complète, comme un
    client normal).
    """
    ports = ports or COMMON_PORTS
    ip = _resolve_host(domain)
    if ip is None:
        return {"resolved": False, "ip": None, "open_ports": []}

    open_ports: list[dict[str, Any]] = []

    def _check(port: int) -> tuple[int, bool]:
        try:
            with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT):
                return port, True
        except (OSError, socket.timeout):
            return port, False

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_check, port): port for port in ports}
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                banner = _grab_banner(ip, port)
                open_ports.append({"port": port, "banner": banner})

    return {
        "resolved": True,
        "ip": ip,
        "open_ports": sorted(open_ports, key=lambda item: item["port"]),
    }


# --------------------------------------------------------------------------- #
# TLS / certificat
# --------------------------------------------------------------------------- #

def check_tls(domain: str, port: int = 443) -> dict[str, Any]:
    """Établit une vraie connexion TLS pour inspecter certificat, protocole et suite."""
    result: dict[str, Any] = {
        "reachable": False,
        "certificate": None,
        "protocol": None,
        "cipher": None,
        "weak_protocols_accepted": [],
        "weak_cipher": False,
        "issues": [],
    }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                result["reachable"] = True
                result["protocol"] = tls_sock.version()
                cipher_name, _, _ = tls_sock.cipher()
                result["cipher"] = cipher_name
                result["certificate"] = {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                    "not_before": cert.get("notBefore"),
                    "subject_alt_names": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"],
                }
                if any(pattern in cipher_name.upper() for pattern in WEAK_CIPHER_PATTERNS):
                    result["weak_cipher"] = True
                    result["issues"].append(f"Suite de chiffrement faible négociée : {cipher_name}")
    except (OSError, ssl.SSLError, socket.timeout) as exc:
        result["issues"].append(f"Connexion TLS impossible : {exc}")
        return result

    # Teste séparément si le serveur accepte encore TLS 1.0 / 1.1, obsolètes
    # et vulnérables — la connexion par défaut ci-dessus négocie déjà la
    # meilleure version disponible, donc on doit forcer une connexion basse
    # pour savoir si ces vieux protocoles sont encore acceptés.
    for label, tls_version in WEAK_TLS_PROTOCOLS.items():
        weak_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        weak_context.check_hostname = False
        weak_context.verify_mode = ssl.CERT_NONE
        weak_context.minimum_version = tls_version
        weak_context.maximum_version = tls_version
        try:
            with socket.create_connection((domain, port), timeout=CONNECT_TIMEOUT) as sock:
                with weak_context.wrap_socket(sock, server_hostname=domain):
                    result["weak_protocols_accepted"].append(label)
                    result["issues"].append(f"Le serveur accepte encore {label}, obsolète et vulnérable")
        except (OSError, ssl.SSLError, socket.timeout):
            pass  # rejeté, c'est le comportement souhaité

    return result


def check_hsts(domain: str) -> dict[str, Any]:
    """Vérifie la présence et la durée du header HSTS sur la page principale."""
    try:
        response = httpx.get(f"https://{domain}", timeout=HTTP_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"present": False, "issues": [f"Requête HTTPS impossible : {exc}"]}

    header = response.headers.get("Strict-Transport-Security")
    if not header:
        return {"present": False, "issues": ["Aucun header HSTS : le HTTPS n'est pas imposé"]}

    issues: list[str] = []
    max_age = 0
    for part in header.split(";"):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass

    if max_age < 15_552_000:  # 180 jours, seuil communément admis
        issues.append(f"max-age trop court ({max_age}s) : moins de 180 jours recommandés")
    if "includeSubDomains" not in header:
        issues.append("includeSubDomains absent : les sous-domaines ne sont pas protégés")

    return {"present": True, "header": header, "max_age": max_age, "issues": issues}


# --------------------------------------------------------------------------- #
# Headers de sécurité HTTP
# --------------------------------------------------------------------------- #

def _evaluate_csp(value: str) -> list[str]:
    """Une CSP mal configurée est presque aussi inutile qu'absente."""
    issues = []
    lowered = value.lower()
    if "unsafe-inline" in lowered:
        issues.append("'unsafe-inline' autorisé : neutralise une bonne partie de la protection XSS")
    if "unsafe-eval" in lowered:
        issues.append("'unsafe-eval' autorisé : permet l'exécution de code dynamique")
    if "default-src *" in lowered or "default-src: *" in lowered:
        issues.append("default-src * : politique trop permissive, équivaut presque à une absence de CSP")
    return issues


def check_cookie_security(response: httpx.Response) -> list[dict[str, Any]]:
    """Vérifie les drapeaux de sécurité sur chaque cookie posé par le serveur.

    Un cookie sans Secure/HttpOnly/SameSite n'est pas une vulnérabilité au sens
    CVE, mais une mauvaise configuration exploitable (vol de session via XSS,
    interception en clair, CSRF). C'est une catégorie à part de headers.
    """
    findings: list[dict[str, Any]] = []
    for raw_cookie in response.headers.get_list("set-cookie"):
        name = raw_cookie.split("=", 1)[0].strip()
        lowered = raw_cookie.lower()
        issues: list[str] = []

        if "secure" not in lowered:
            issues.append("Flag Secure absent : le cookie peut être transmis en clair sur HTTP")
        if "httponly" not in lowered:
            issues.append("Flag HttpOnly absent : accessible en JavaScript, exploitable via XSS")
        if "samesite" not in lowered:
            issues.append("Flag SameSite absent : vulnérable au CSRF via requêtes cross-site")
        elif "samesite=none" in lowered and "secure" not in lowered:
            issues.append("SameSite=None sans Secure : combinaison invalide, rejetée par les navigateurs modernes")

        if issues:
            findings.append({"cookie": name, "issues": issues})

    return findings


def check_security_headers(domain: str) -> dict[str, Any]:
    """Récupère la page principale et évalue la présence ET la qualité des headers clés,
    plus la sécurité des cookies posés.
    """
    try:
        response = httpx.get(f"https://{domain}", timeout=HTTP_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError as exc:
        return {"reachable": False, "issues": [f"Requête impossible : {exc}"]}

    headers = response.headers
    results: dict[str, Any] = {"reachable": True, "headers": {}, "cookies": check_cookie_security(response)}

    for header_name in SECURITY_HEADERS:
        value = headers.get(header_name)
        entry: dict[str, Any] = {"present": bool(value), "value": value, "issues": []}

        if value and header_name == "Content-Security-Policy":
            entry["issues"] = _evaluate_csp(value)
        elif value and header_name == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
            entry["issues"].append(f"Valeur inhabituelle : {value}")
        elif not value:
            entry["issues"].append("Absent")

        results["headers"][header_name] = entry

    return results


# --------------------------------------------------------------------------- #
# Fichiers/chemins sensibles
# --------------------------------------------------------------------------- #

def check_sensitive_paths(domain: str, paths: list[str] | None = None) -> list[dict[str, Any]]:
    """Teste une liste connue de chemins à risque, avec délai entre chaque requête.

    Ne flag que ce qui est vraiment accessible : un statut 200 sur un chemin
    connu pour ne jamais légitimement exister publiquement.
    """
    paths = paths or SENSITIVE_PATHS
    findings: list[dict[str, Any]] = []

    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=False) as client:
        for path in paths:
            url = f"https://{domain}{path}"
            try:
                response = client.get(url)
            except httpx.HTTPError as exc:
                logger.debug("Chemin %s injoignable : %s", url, exc)
                time.sleep(SENSITIVE_PATH_DELAY)
                continue

            if response.status_code == 200 and len(response.content) > 0:
                findings.append({
                    "path": path,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "confidence": "needs_manual_review",  # un 200 peut être une page custom, pas le vrai fichier
                })

            time.sleep(SENSITIVE_PATH_DELAY)

    return findings


# --------------------------------------------------------------------------- #
# Point d'entrée du ScanAgent
# --------------------------------------------------------------------------- #

def run_active_scan(domain: str, authorized: bool = False) -> dict[str, Any]:
    """Exécute le scan actif complet. Refuse de s'exécuter sans confirmation explicite.

    `authorized=True` doit être positionné par l'appelant (le node LangGraph)
    uniquement après lecture du statut de vérification en base — jamais par défaut.
    """
    if not authorized:
        raise UnauthorizedScanError(
            f"Scan actif refusé pour {domain} : autorisation non confirmée. "
            "La vérification de propriété doit réussir avant tout appel à run_active_scan."
        )

    domain = domain.strip().lower().removeprefix("www.")

    return {
        "domain": domain,
        "ports": scan_ports(domain),
        "tls": check_tls(domain),
        "hsts": check_hsts(domain),
        "security_headers": check_security_headers(domain),
        "sensitive_paths": check_sensitive_paths(domain),
    }