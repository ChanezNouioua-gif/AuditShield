"""
ReconAgent — collecte passive.

Toutes les fonctions de ce module interrogent uniquement des sources publiques
(Certificate Transparency, DNS, WHOIS). Aucune connexion n'est établie vers
l'infrastructure du client : pas de scan, pas de force brute, pas de requête HTTP
vers ses serveurs. Ces opérations ne nécessitent donc aucune autorisation préalable.

Tout ce qui touche activement la cible appartient au ScanAgent, en aval de la
vérification de propriété du domaine.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import dns.exception
import dns.resolver
import httpx

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"
HTTP_TIMEOUT = 20.0
DNS_TIMEOUT = 5.0
WHOIS_TIMEOUT = 8.0

# Selectors DKIM les plus répandus : DKIM ne peut pas être découvert sans
# connaître le selector, on teste donc une liste de valeurs courantes.
COMMON_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2",
    "mail", "dkim", "s1", "s2", "smtp", "zoho", "mandrill", "sendgrid",
]

# Empreintes de services cloud renvoyant une erreur caractéristique lorsque la
# ressource pointée n'existe plus : c'est le signal d'un dangling DNS exploitable.
TAKEOVER_FINGERPRINTS = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.azure.com": "Azure",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "pantheonsite.io": "Pantheon",
    "wpengine.com": "WP Engine",
    "shopify.com": "Shopify",
    "fastly.net": "Fastly",
    "readthedocs.io": "Read the Docs",
    "ghost.io": "Ghost",
    "surge.sh": "Surge",
}


def _build_resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT
    return resolver


def _query(domain: str, rdtype: str) -> list[str]:
    """Interroge le DNS et renvoie les réponses sous forme de texte.

    Renvoie une liste vide sur absence d'enregistrement ou erreur réseau :
    un domaine sans MX n'est pas une panne, c'est une information.
    """
    try:
        answers = _build_resolver().resolve(domain, rdtype)
        return [record.to_text().strip('"') for record in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        logger.debug("Échec résolution %s %s : %s", domain, rdtype, exc)
        return []


# --------------------------------------------------------------------------- #
# Sous-domaines
# --------------------------------------------------------------------------- #

def fetch_crtsh(domain: str) -> list[str]:
    """Extrait les sous-domaines depuis les logs de Certificate Transparency.

    Chaque certificat TLS émis est publié publiquement par design. Interroger
    crt.sh pour %.domain.com révèle donc les sous-domaines couverts par un
    certificat, y compris ceux qui ne sont liés nulle part publiquement.
    """
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        response = httpx.get(CRTSH_URL, params=params, timeout=HTTP_TIMEOUT)
        response.raise_for_status()
        entries = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        logger.warning("crt.sh indisponible pour %s : %s", domain, exc)
        return []

    found: set[str] = set()
    for entry in entries:
        # name_value peut contenir plusieurs noms séparés par des retours ligne
        for name in str(entry.get("name_value", "")).splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and _is_valid_hostname(name):
                found.add(name)

    return sorted(found)


def _is_valid_hostname(name: str) -> bool:
    if not name or len(name) > 253:
        return False
    return bool(re.fullmatch(r"[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?", name))


def resolve_subdomains(subdomains: list[str]) -> dict[str, list[str]]:
    """Résout chaque sous-domaine en adresses IP ou cibles CNAME.

    Note : il s'agit de lectures DNS, pas de connexions vers la cible.
    Un sous-domaine sans résolution est conservé avec une liste vide — c'est
    justement ce cas qui peut révéler un enregistrement en suspens.
    """
    results: dict[str, list[str]] = {}
    for sub in subdomains:
        records = _query(sub, "A") or _query(sub, "AAAA") or _query(sub, "CNAME")
        results[sub] = records
    return results


# --------------------------------------------------------------------------- #
# Enregistrements DNS
# --------------------------------------------------------------------------- #

def fetch_dns_records(domain: str) -> dict[str, list[str]]:
    """Récupère les enregistrements DNS principaux du domaine."""
    return {
        "A": _query(domain, "A"),
        "AAAA": _query(domain, "AAAA"),
        "NS": _query(domain, "NS"),
        "MX": _query(domain, "MX"),
        "TXT": _query(domain, "TXT"),
        "CNAME": _query(domain, "CNAME"),
        "SOA": _query(domain, "SOA"),
    }


def check_dangling_dns(subdomain_records: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Détecte les enregistrements DNS pointant vers une ressource cloud disparue.

    Un CNAME vers un service cloud dont la ressource a été supprimée permet à un
    tiers de réclamer ce nom et de prendre le contrôle du sous-domaine
    (subdomain takeover). On signale ici les candidats : la confirmation exige
    une requête vers le service, qui relève du ScanAgent.
    """
    candidates: list[dict[str, Any]] = []

    for sub, records in subdomain_records.items():
        for record in records:
            target = record.rstrip(".").lower()
            for fingerprint, provider in TAKEOVER_FINGERPRINTS.items():
                if target.endswith(fingerprint):
                    resolves = bool(_query(sub, "A") or _query(sub, "AAAA"))
                    candidates.append({
                        "subdomain": sub,
                        "cname_target": target,
                        "provider": provider,
                        "resolves": resolves,
                        # Un CNAME cloud qui ne résout plus est le cas classique
                        "suspicion": "high" if not resolves else "low",
                        "confidence": "needs_manual_review",
                    })
                    break

    return candidates


# --------------------------------------------------------------------------- #
# Sécurité email (lecture DNS uniquement)
# --------------------------------------------------------------------------- #

def check_spf(domain: str) -> dict[str, Any]:
    """Analyse l'enregistrement SPF, qui liste les serveurs autorisés à envoyer."""
    records = [r for r in _query(domain, "TXT") if r.lower().startswith("v=spf1")]

    if not records:
        return {"present": False, "issues": ["Aucun enregistrement SPF"]}
    if len(records) > 1:
        # Plusieurs SPF invalident la politique entière selon la RFC 7208
        return {"present": True, "record": records, "issues": ["Plusieurs enregistrements SPF (politique invalide)"]}

    record = records[0]
    issues: list[str] = []

    if "+all" in record:
        issues.append("Mécanisme +all : autorise n'importe quel serveur à usurper le domaine")
    elif "?all" in record:
        issues.append("Mécanisme ?all : politique neutre, sans effet réel")
    elif "~all" in record:
        issues.append("Mécanisme ~all (softfail) : les mails usurpés sont acceptés puis marqués")
    elif "-all" not in record:
        issues.append("Aucun mécanisme all terminal")

    if record.count("include:") > 10:
        issues.append("Plus de 10 lookups DNS probables : dépassement de la limite RFC")

    return {"present": True, "record": record, "issues": issues}


def check_dmarc(domain: str) -> dict[str, Any]:
    """Analyse la politique DMARC publiée sur _dmarc.domain."""
    records = [r for r in _query(f"_dmarc.{domain}", "TXT") if r.lower().startswith("v=dmarc1")]

    if not records:
        return {"present": False, "policy": None, "issues": ["Aucun enregistrement DMARC"]}

    record = records[0]
    tags = dict(
        part.strip().split("=", 1)
        for part in record.split(";")
        if "=" in part
    )
    policy = tags.get("p", "").lower()
    issues: list[str] = []

    if policy == "none":
        issues.append("Politique p=none : surveillance seule, aucun mail frauduleux bloqué")
    elif policy == "quarantine":
        issues.append("Politique p=quarantine : les mails usurpés arrivent en spam, pas bloqués")
    elif policy != "reject":
        issues.append(f"Politique inconnue ou absente : {policy or 'non définie'}")

    if not any(tags.get(k) for k in ("rua", "ruf")):
        issues.append("Aucune adresse de rapport : aucune visibilité sur les tentatives d'usurpation")

    if tags.get("pct") and tags["pct"] != "100":
        issues.append(f"Politique appliquée à {tags['pct']}% des mails seulement")

    return {"present": True, "record": record, "policy": policy, "tags": tags, "issues": issues}


def check_dkim(domain: str, selectors: list[str] | None = None) -> dict[str, Any]:
    """Cherche des clés DKIM en testant une liste de selectors courants.

    DKIM n'est pas énumérable : sans le selector, la clé reste introuvable.
    Une absence de résultat ne prouve donc pas que DKIM n'est pas configuré.
    """
    selectors = selectors or COMMON_DKIM_SELECTORS
    found: list[dict[str, str]] = []

    for selector in selectors:
        records = _query(f"{selector}._domainkey.{domain}", "TXT")
        for record in records:
            if "p=" in record:
                found.append({"selector": selector, "record": record})

    return {
        "found": bool(found),
        "selectors_found": found,
        "selectors_tested": len(selectors),
        "note": "Absence non concluante : le selector utilisé peut être personnalisé",
        "confidence": "confirmed" if found else "needs_manual_review",
    }


def check_email_security(domain: str) -> dict[str, Any]:
    """Regroupe SPF, DMARC et DKIM en un seul bloc de résultats."""
    return {
        "spf": check_spf(domain),
        "dmarc": check_dmarc(domain),
        "dkim": check_dkim(domain),
    }


# --------------------------------------------------------------------------- #
# WHOIS
# --------------------------------------------------------------------------- #

def fetch_whois(domain: str) -> dict[str, Any]:
    """Récupère les données WHOIS du domaine.

    Source peu fiable depuis le RGPD : les coordonnées sont souvent masquées.
    À traiter comme un complément d'information, jamais comme une base de décision.

    python-whois n'expose pas de paramètre de timeout : sans le forcer au niveau
    socket, un serveur WHOIS distant qui ne répond pas peut bloquer l'appel
    indéfiniment (fréquent sur les réseaux d'entreprise qui filtrent le port 43).
    """
    try:
        import socket

        import whois  # dépendance optionnelle : python-whois
    except ImportError:
        return {"available": False, "reason": "python-whois non installé"}

    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(WHOIS_TIMEOUT)
    try:
        data = whois.whois(domain)
    except Exception as exc:  # la lib lève des exceptions très variées
        logger.debug("WHOIS indisponible pour %s : %s", domain, exc)
        return {"available": False, "reason": str(exc)}
    finally:
        socket.setdefaulttimeout(previous_timeout)

    def _first(value: Any) -> Any:
        return value[0] if isinstance(value, list) and value else value

    return {
        "available": True,
        "registrar": data.get("registrar"),
        "creation_date": str(_first(data.get("creation_date")) or ""),
        "expiration_date": str(_first(data.get("expiration_date")) or ""),
        "name_servers": sorted({ns.lower() for ns in (data.get("name_servers") or [])}),
        "note": "Données souvent masquées (RGPD) — fiabilité partielle",
    }


# --------------------------------------------------------------------------- #
# Point d'entrée du ReconAgent
# --------------------------------------------------------------------------- #

def run_passive_recon(domain: str) -> dict[str, Any]:
    """Exécute la collecte passive complète pour un domaine.

    C'est cette fonction qu'appelle le node LangGraph du ReconAgent.
    """
    domain = domain.strip().lower().removeprefix("www.")

    subdomains = fetch_crtsh(domain)
    subdomain_records = resolve_subdomains(subdomains)

    return {
        "domain": domain,
        "subdomains": subdomains,
        "subdomain_count": len(subdomains),
        "subdomain_records": subdomain_records,
        "dns": fetch_dns_records(domain),
        "dangling_dns": check_dangling_dns(subdomain_records),
        "email_security": check_email_security(domain),
        "whois": fetch_whois(domain),
    }