"""
ReportAgent — scoring par catégorie.

Calcule un score sur 100 pour chaque catégorie (TLS/certificat, headers,
email, services exposés, vulnérabilités connues), puis un score global
pondéré. La logique part des `Finding` persistés en base, pas des résultats
bruts recon/scan — c'est la raison d'être de la table `Finding` plutôt qu'un
simple blob JSON : elle est déjà filtrable par catégorie et par confiance.

Principe du calcul : chaque catégorie part de 100 et perd des points selon la
sévérité des findings qui s'y rattachent. Un finding `needs_manual_review`
pèse moins qu'un finding `confirmed` — on ne punit pas un score sur une
hypothèse non vérifiée autant que sur un fait établi.
"""

from __future__ import annotations

from typing import Any

# Poids de chaque catégorie dans le score global. Les vulnérabilités connues
# et les services exposés pèsent plus lourd : ce sont les vecteurs d'attaque
# les plus directs, contrairement à un header de sécurité mal configuré qui
# demande un contexte d'exploitation supplémentaire.
CATEGORY_WEIGHTS = {
    "known_vulns": 0.30,
    "exposed_services": 0.20,
    "tls": 0.20,
    "headers": 0.15,
    "email": 0.15,
}

# Pénalité infligée au score de 100, par point de CVSS et par finding.
# Un finding confirmé pèse le double d'un finding à vérifier manuellement.
CONFIRMED_PENALTY_PER_CVSS_POINT = 4.0
NEEDS_REVIEW_PENALTY_PER_CVSS_POINT = 2.0

# Pénalité fixe pour un finding sans score CVSS (ex: port exposé, header absent)
CONFIRMED_FLAT_PENALTY = 15.0
NEEDS_REVIEW_FLAT_PENALTY = 7.0


def _penalty_for_finding(finding: dict[str, Any]) -> float:
    """Calcule la pénalité d'un finding individuel sur l'échelle 0-100."""
    confidence = finding.get("confidence", "needs_manual_review")
    severity = finding.get("severity")

    if severity is not None and severity > 0:
        per_point = (
            CONFIRMED_PENALTY_PER_CVSS_POINT
            if confidence == "confirmed"
            else NEEDS_REVIEW_PENALTY_PER_CVSS_POINT
        )
        return severity * per_point

    return CONFIRMED_FLAT_PENALTY if confidence == "confirmed" else NEEDS_REVIEW_FLAT_PENALTY


def score_category(findings: list[dict[str, Any]]) -> float:
    """Score d'une catégorie : 100 moins la somme des pénalités, plancher à 0."""
    score = 100.0
    for finding in findings:
        score -= _penalty_for_finding(finding)
    return max(0.0, round(score, 1))


def score_email_security(email_security: dict[str, Any] | None) -> float:
    """Catégorie 'email' : dérivée directement des résultats ReconAgent
    (SPF/DMARC/DKIM), puisqu'il n'y a pas de Finding dédié pour chaque
    sous-problème — chaque `issue` détectée coûte un nombre fixe de points.
    """
    if not email_security:
        return 100.0

    score = 100.0
    spf_issues = email_security.get("spf", {}).get("issues", [])
    dmarc_issues = email_security.get("dmarc", {}).get("issues", [])

    # SPF/DMARC absents sont les problèmes les plus graves pour cette catégorie
    if not email_security.get("spf", {}).get("present", True):
        score -= 25
    else:
        score -= 8 * len(spf_issues)

    if not email_security.get("dmarc", {}).get("present", True):
        score -= 25
    else:
        score -= 8 * len(dmarc_issues)

    return max(0.0, round(score, 1))


def score_tls(tls_result: dict[str, Any] | None, hsts_result: dict[str, Any] | None) -> float:
    """Catégorie 'tls' : dérivée des résultats bruts ScanAgent (protocoles
    faibles, suite de chiffrement, HSTS), en complément des Finding `known_vulns`
    qui eux concernent les CVE de version, pas la configuration TLS elle-même.
    """
    score = 100.0
    if not tls_result or not tls_result.get("reachable", False):
        return score  # pas de TLS testable n'est pas en soi un problème de score TLS

    if tls_result.get("weak_protocols_accepted"):
        score -= 20 * len(tls_result["weak_protocols_accepted"])
    if tls_result.get("weak_cipher"):
        score -= 15

    if hsts_result and not hsts_result.get("present", False):
        score -= 15
    elif hsts_result:
        score -= 5 * len(hsts_result.get("issues", []))

    return max(0.0, round(score, 1))


def score_headers(security_headers: dict[str, Any] | None) -> float:
    """Catégorie 'headers' : un header absent coûte plus cher qu'un header
    présent mais mal configuré — l'absence totale laisse zéro protection.
    """
    if not security_headers or not security_headers.get("reachable", False):
        return 100.0

    score = 100.0
    for entry in security_headers.get("headers", {}).values():
        if not entry.get("present"):
            score -= 10
        elif entry.get("issues"):
            score -= 5 * len(entry["issues"])

    for cookie_issue in security_headers.get("cookies", []):
        score -= 5 * len(cookie_issue.get("issues", []))

    return max(0.0, round(score, 1))


def compute_category_scores(
    findings: list[dict[str, Any]],
    scan_results: dict[str, Any] | None,
    recon_results: dict[str, Any] | None = None,
) -> dict[str, float]:
    """Calcule le score de chaque catégorie pour un audit.

    `findings` : les Finding persistés (convertis en dict), utilisés tels
    quels pour `known_vulns` et `exposed_services`.
    `scan_results` : la sortie brute de ScanAgent, pour dériver `tls` et `headers`.
    `recon_results` : la sortie brute de ReconAgent — c'est là, pas dans
    scan_results, que vit `email_security` (SPF/DMARC/DKIM sont des lectures
    DNS passives, donc du ressort du ReconAgent).
    """
    scan_results = scan_results or {}
    recon_results = recon_results or {}

    findings_by_category: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        findings_by_category.setdefault(finding["category"], []).append(finding)

    return {
        "known_vulns": score_category(findings_by_category.get("known_vulns", [])),
        "exposed_services": score_category(findings_by_category.get("exposed_services", [])),
        "tls": score_tls(scan_results.get("tls"), scan_results.get("hsts")),
        "headers": score_headers(scan_results.get("security_headers")),
        "email": score_email_security(recon_results.get("email_security")),
    }


def compute_global_score(category_scores: dict[str, float]) -> float:
    """Moyenne pondérée des scores par catégorie, selon CATEGORY_WEIGHTS."""
    total_weight = sum(CATEGORY_WEIGHTS.values())
    weighted_sum = sum(
        category_scores.get(category, 100.0) * weight
        for category, weight in CATEGORY_WEIGHTS.items()
    )
    return round(weighted_sum / total_weight, 1)