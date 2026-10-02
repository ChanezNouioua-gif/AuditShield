"""
TriageAgent — retrieval CVE + priorisation.

Prend les bannières brutes du ScanAgent (ex: "Apache/2.4.49 (Unix)"), en
extrait le produit et la version, interroge l'index ChromaDB construit par
ingest_cve.py, et ne retient que ce qui correspond réellement à la version
détectée — la similarité sémantique seule ne suffit pas à affirmer qu'une
CVE s'applique, elle sert à présélectionner les candidats plausibles.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import chromadb

from app.config import settings

logger = logging.getLogger(__name__)

COLLECTION_NAME = "cve_index"
TOP_K = 8

# Seuil de distance ChromaDB (plus petit = plus proche) en dessous duquel un
# candidat est considéré comme sémantiquement pertinent. Calibré empiriquement
# avec le modèle d'embedding par défaut (all-MiniLM-L6-v2) ; à réajuster si tu
# changes de modèle d'embedding.
MAX_SEMANTIC_DISTANCE = 1.1

# Ports à forte sensibilité par nature, indépendamment de toute CVE : les
# exposer publiquement est déjà une anomalie de configuration en soi.
HIGH_RISK_EXPOSED_PORTS = {
    3306: "MySQL/MariaDB exposé publiquement",
    5432: "PostgreSQL exposé publiquement",
    27017: "MongoDB exposé publiquement",
    6379: "Redis exposé publiquement (souvent sans authentification par défaut)",
    9200: "Elasticsearch exposé publiquement",
    5900: "VNC exposé publiquement",
    3389: "RDP exposé publiquement",
    445: "SMB exposé publiquement",
    23: "Telnet exposé publiquement (protocole non chiffré)",
}

# Quelques formats de bannière courants -> (produit, version)
# Volontairement limité à ce que scan/tools.py est susceptible de rencontrer ;
# à étendre au fur et à mesure que de nouvelles bannières apparaissent en test.
BANNER_PATTERNS = [
    re.compile(r"Apache/(?P<version>[\d.]+)", re.IGNORECASE),
    re.compile(r"nginx/(?P<version>[\d.]+)", re.IGNORECASE),
    re.compile(r"OpenSSH[_-](?P<version>[\d.]+\w*)", re.IGNORECASE),
    re.compile(r"(?P<product>MariaDB)[^\d]*(?P<version>[\d.]+)", re.IGNORECASE),
    re.compile(r"(?P<product>MySQL)[^\d]*(?P<version>[\d.]+)", re.IGNORECASE),
    re.compile(r"Microsoft-IIS/(?P<version>[\d.]+)", re.IGNORECASE),
]

BANNER_PRODUCT_NAMES = {
    "apache": "apache",
    "nginx": "nginx",
    "openssh": "openssh",
    "mariadb": "mariadb",
    "mysql": "mysql",
    "microsoft-iis": "iis",
}


def parse_banner(banner: str) -> dict[str, str] | None:
    """Extrait (produit, version) d'une bannière brute, si reconnue.

    Renvoie None si le format n'est pas reconnu — dans ce cas, le finding sera
    quand même créé plus loin, juste sans correspondance CVE automatique.
    """
    if not banner:
        return None

    for pattern in BANNER_PATTERNS:
        match = pattern.search(banner)
        if not match:
            continue

        groups = match.groupdict()
        version = groups.get("version", "")
        # Le nom du produit est soit capturé explicitement, soit déduit du nom du pattern
        product_raw = groups.get("product") or pattern.pattern.split("/")[0].split("[")[0]
        product_key = re.sub(r"[^a-zA-Z-]", "", product_raw).lower()
        product = BANNER_PRODUCT_NAMES.get(product_key, product_key)

        return {"product": product, "version": version, "raw_banner": banner}

    return None


def _version_explicitly_affected(document: str, version: str) -> bool:
    """Un $contains sur la version ne distingue pas "cette version est touchée"
    de "cette version corrige le problème" — ex: "OpenSSH before 7.4" veut dire
    que 7.4 est justement le correctif, pas la version vulnérable.

    Retourne False si la version n'apparaît que dans un contexte de ce type
    ("before X", "fixed in X"...) sans mention positive explicite ailleurs
    dans le texte (ex: "only affects 2.4.49").
    """
    escaped = re.escape(version)
    negative_patterns = [
        rf"\bbefore\s+(?:[\w.]+\s+)?{escaped}\b",
        rf"\bprior to\s+(?:[\w.]+\s+)?{escaped}\b",
        rf"\bearlier than\s+(?:[\w.]+\s+)?{escaped}\b",
        rf"\bfixed in\s+(?:[\w.]+\s+)?{escaped}\b",
        rf"\bupgrad\w*\s+to\s+(?:[\w.]+\s+)?{escaped}\b",
    ]
    has_negative = any(re.search(p, document, re.IGNORECASE) for p in negative_patterns)
    if not has_negative:
        return True  # aucune ambiguïté de ce type détectée

    positive_patterns = [
        rf"\baffects?\b[^.]{{0,60}}{escaped}\b",
        rf"\bonly affects\b[^.]{{0,60}}{escaped}\b",
        rf"\bin\b[^.]{{0,40}}{escaped}\b[^.]{{0,40}}\bvulnerab",
    ]
    return any(re.search(p, document, re.IGNORECASE) for p in positive_patterns)


def _format_matches(results: dict[str, Any], confirmed: bool) -> list[dict[str, Any]]:
    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    matches: list[dict[str, Any]] = []
    for document, metadata, distance in zip(documents, metadatas, distances):
        if not confirmed and distance > MAX_SEMANTIC_DISTANCE:
            continue  # trop éloigné sémantiquement pour être pertinent

        matches.append({
            "cve_id": metadata.get("cve_id"),
            "description": document,
            "cvss_score": metadata.get("cvss_score", 0.0),
            "semantic_distance": distance,
            "confidence": "confirmed" if confirmed else "needs_manual_review",
        })
    return matches


def query_cves(product: str, version: str, top_k: int = TOP_K) -> list[dict[str, Any]]:
    """Interroge ChromaDB pour un couple (produit, version) donné.

    Deux passes, dans cet ordre :
    1. Filtrage EXACT sur la présence littérale de la version dans le texte
       (`where_document`) — la similarité sémantique seule ne discrimine pas
       bien les numéros de version (pour un modèle d'embedding, "2.4.49" et
       "2.4.68" sont presque équivalents). Si cette passe trouve quelque
       chose, c'est fiable : confidence="confirmed" directement.
    2. Seulement si la passe 1 ne trouve rien, on retombe sur une recherche
       sémantique large — la version n'est peut-être mentionnée que via une
       plage ("2.4.0 à 2.4.68") plutôt que littéralement. Dans ce cas,
       confidence reste "needs_manual_review" : aucune preuve textuelle directe.
    """
    try:
        client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
        collection = client.get_collection(COLLECTION_NAME)
    except Exception as exc:
        logger.error("Collection ChromaDB indisponible : %s", exc)
        return []

    query_text = f"{product} {version} vulnerability"
    where_filter = {"product": product} if product else None

    if version:
        try:
            exact_results = collection.query(
                query_texts=[query_text],
                n_results=top_k,
                where=where_filter,
                where_document={"$contains": version},
            )
            exact_matches = _format_matches(exact_results, confirmed=True)
            exact_matches = [
                m for m in exact_matches if _version_explicitly_affected(m["description"], version)
            ]
            if exact_matches:
                exact_matches.sort(key=lambda m: -m["cvss_score"])
                return exact_matches
        except Exception as exc:
            logger.warning("Filtrage exact ChromaDB échoué pour %s %s : %s — repli sémantique", product, version, exc)

    try:
        semantic_results = collection.query(
            query_texts=[query_text],
            n_results=top_k,
            where=where_filter,
        )
    except Exception as exc:
        logger.error("Requête ChromaDB échouée pour %s %s : %s", product, version, exc)
        return []

    matches = _format_matches(semantic_results, confirmed=False)
    matches.sort(key=lambda m: -m["cvss_score"])
    return matches


def _business_priority(cvss_score: float, publicly_exposed: bool) -> int:
    """Priorité 1 (critique) à 5 (informatif) — pas juste le CVSS brut.

    Un score élevé compte plus s'il est exploitable depuis Internet, ce que ce
    pipeline suppose par défaut puisque ScanAgent scanne depuis l'extérieur :
    toute CVE retenue ici concerne déjà un service exposé publiquement.
    """
    if cvss_score >= 9.0:
        return 1
    if cvss_score >= 7.0:
        return 2
    if cvss_score >= 4.0:
        return 3
    if cvss_score > 0:
        return 4
    return 5


def triage_scan_results(scan_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Point d'entrée du TriageAgent : transforme les résultats bruts du ScanAgent
    en findings structurés, prêts à devenir des lignes `Finding` en base.
    """
    findings: list[dict[str, Any]] = []
    open_ports = scan_results.get("ports", {}).get("open_ports", [])

    for entry in open_ports:
        port = entry["port"]
        banner = entry.get("banner")

        # Risque d'exposition pur, indépendant de toute CVE
        if port in HIGH_RISK_EXPOSED_PORTS:
            findings.append({
                "category": "exposed_services",
                "title": HIGH_RISK_EXPOSED_PORTS[port],
                "description": f"Le port {port} est accessible publiquement. {HIGH_RISK_EXPOSED_PORTS[port]}.",
                "severity": None,
                "business_priority": 2,
                "confidence": "confirmed",
                "cve_id": None,
                "evidence": {"port": port, "banner": banner},
                "remediation": "Restreindre l'accès à ce port via pare-feu/VPN, ou le fermer s'il n'est pas nécessaire publiquement.",
            })

        parsed = parse_banner(banner) if banner else None
        if not parsed:
            continue

        matches = query_cves(parsed["product"], parsed["version"])
        for match in matches[:3]:  # on ne garde que les meilleurs candidats par service
            findings.append({
                "category": "known_vulns",
                "title": f"Vulnérabilité potentielle : {parsed['product']} {parsed['version']} ({match['cve_id']})",
                "description": match["description"],
                "severity": match["cvss_score"],
                "business_priority": _business_priority(match["cvss_score"], publicly_exposed=True),
                "confidence": match["confidence"],
                "cve_id": match["cve_id"],
                "evidence": {"port": port, "banner": banner, "semantic_distance": match["semantic_distance"]},
                "remediation": f"Mettre à jour {parsed['product']} vers une version corrigée, au-delà de {parsed['version']}.",
            })

    return findings