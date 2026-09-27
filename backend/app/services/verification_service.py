"""
Service de vérification de propriété du domaine.

Contrôle, à la demande (endpoint /verify/{audit_id}/check), qu'un token
généré par le ReconAgent a bien été déposé par le client — soit en TXT DNS,
soit dans un fichier .well-known. C'est le garde-fou légal avant tout accès
actif (ScanAgent) : sans vérification positive, l'audit reste bloqué à l'état
recon_only, quelle que soit l'ancienneté de la demande.

Ce module ne fait qu'un contrôle ponctuel — pas de boucle d'attente, pas de
tâche de fond ici. Le client relance /check autant de fois qu'il le souhaite,
le temps de configurer son DNS ou son serveur.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import dns.exception
import dns.resolver
import httpx

logger = logging.getLogger(__name__)

DNS_TIMEOUT = 5.0
HTTP_TIMEOUT = 10.0
WELL_KNOWN_PATH = "/.well-known/auditshield-verify.txt"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _check_dns_txt(domain: str, expected_token: str) -> bool:
    """Vérifie la présence du token dans un enregistrement TXT sur
    _auditshield-verify.<domain>.
    """
    record_name = f"_auditshield-verify.{domain}"
    resolver = dns.resolver.Resolver()
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_TIMEOUT

    try:
        answers = resolver.resolve(record_name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return False
    except dns.exception.DNSException as exc:
        logger.warning("Vérification DNS TXT échouée pour %s : %s", record_name, exc)
        return False

    values = [record.to_text().strip('"') for record in answers]
    return expected_token in values


def _check_well_known(domain: str, expected_token: str) -> bool:
    """Vérifie la présence du token dans le fichier .well-known du domaine.

    Requête prudente et unique — pas de suivi de redirections vers un autre
    domaine, pour éviter qu'un tiers ne fasse valider un domaine qu'il ne
    possède pas via une redirection détournée.
    """
    url = f"https://{domain}{WELL_KNOWN_PATH}"
    try:
        response = httpx.get(url, timeout=HTTP_TIMEOUT, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.warning("Vérification .well-known échouée pour %s : %s", url, exc)
        return False

    if response.status_code != 200:
        return False

    return expected_token.strip() == response.text.strip()


def check_domain_ownership(domain: str, token: str, method: str) -> bool:
    """Point d'entrée unique du service : contrôle le token selon la méthode déclarée.

    `method` doit correspondre à ce qui a été stocké dans VerificationToken.method
    au moment de la génération (voir agents/recon/graph.py) — pas de bascule
    automatique vers l'autre méthode, pour rester cohérent avec le choix du client.
    """
    if method == "dns_txt":
        return _check_dns_txt(domain, token)
    if method == "well_known":
        return _check_well_known(domain, token)

    logger.error("Méthode de vérification inconnue : %s", method)
    return False


def is_expired(expires_at: datetime | None) -> bool:
    """Un token expiré ne doit plus être accepté même si le contrôle réussit,
    pour forcer un renouvellement si la demande d'audit traîne trop longtemps.

    SQLite ne conserve pas réellement le fuseau horaire malgré la colonne
    DateTime(timezone=True) : une valeur écrite en UTC aware revient naïve
    à la lecture. On la considère donc comme UTC si elle n'a pas de tzinfo,
    plutôt que de laisser la comparaison échouer.
    """
    if expires_at is None:
        return False
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return _now() > expires_at