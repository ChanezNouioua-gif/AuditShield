"""
Ingestion des CVE dans ChromaDB — TriageAgent.

Ce script n'est PAS exécuté à chaque audit : c'est une tâche d'alimentation à
lancer une fois, puis périodiquement (ex. une fois par semaine) pour tenir la
base à jour. Le retrieval au moment de l'audit (agents/triage/tools.py, pas
encore écrit) ne fait qu'interroger ce qui a déjà été indexé ici.

Approche volontairement ciblée plutôt qu'exhaustive : la NVD dépasse 260 000
CVE et impose un rate limit sévère sans clé API (5 requêtes/30s). Aspirer toute
la base n'a pas de sens tant qu'on ne couvre qu'une poignée de technos par le
ScanAgent — on indexe donc par produit demandé (Apache, nginx, MySQL...),
et on étend la liste au fur et à mesure que ScanAgent détecte de nouvelles
technologies sur le terrain.

Usage :
    python -m app.agents.triage.ingest_cve --products apache nginx openssh mariadb
"""

from __future__ import annotations

import argparse
import logging
import time
from typing import Any

import chromadb
import httpx

from app.config import settings

logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000  # maximum autorisé par l'API NVD
MAX_CVES_PER_PRODUCT = 6000  # plafond de sécurité pour un produit très verbeux
REQUEST_DELAY = 6.5  # secondes ; NVD limite à 5 requêtes/30s sans clé API — on reste large
COLLECTION_NAME = "cve_index"

# keywordSearch="apache" matche TOUTE CVE mentionnant "apache" dans sa
# description — Apache Traffic Server, Tomcat, Struts, Spark... pas seulement
# le serveur web (httpd) que ScanAgent détecte. Ce mapping force une phrase
# assez précise pour cibler le bon produit, combinée à keywordExactMatch.
PRODUCT_SEARCH_TERMS = {
    "apache": "Apache HTTP Server",
    "nginx": "nginx",
    "openssh": "OpenSSH",
    "mariadb": "MariaDB",
    "mysql": "MySQL",
    "iis": "Microsoft IIS",
}


def _build_query_text(cve: dict[str, Any]) -> str:
    """Construit le texte qui sera embeddé — description + produit, pour que
    la similarité sémantique capture à la fois le sens de la faille et le
    contexte technique (nom du logiciel affecté).
    """
    descriptions = cve.get("descriptions", [])
    english = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    return english


def _extract_cvss_score(cve: dict[str, Any]) -> float | None:
    """Prend le score CVSS le plus récent disponible (v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


def fetch_cves_for_product(product: str, max_results: int = MAX_CVES_PER_PRODUCT) -> list[dict[str, Any]]:
    """Récupère TOUTES les CVE (paginées) dont la description mentionne le produit.

    L'API NVD renvoie les résultats du plus ancien au plus récent : ne lire que
    la première page reviendrait à n'indexer que les CVE des années 1990-2000,
    inutiles pour matcher des versions actuelles. On parcourt donc toutes les
    pages, avec le délai imposé entre deux requêtes.

    Recherche par mot-clé (`keywordSearch`), pas par CPE exact : un peu de bruit
    dans les résultats, que le retrieval sémantique filtrera ensuite.
    """
    collected: list[dict[str, Any]] = []
    start_index = 0

    search_term = PRODUCT_SEARCH_TERMS.get(product, product)

    while start_index < max_results:
        params = {
            "keywordSearch": search_term,
            "keywordExactMatch": "",  # force le match sur la phrase exacte, pas mot par mot
            "resultsPerPage": RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
        try:
            response = httpx.get(NVD_API_URL, params=params, timeout=60.0)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            logger.error("Échec récupération NVD pour '%s' (index %d) : %s", product, start_index, exc)
            break

        data = response.json()
        collected.extend(data.get("vulnerabilities", []))

        total = data.get("totalResults", 0)
        start_index += RESULTS_PER_PAGE
        if start_index >= total:
            break

        time.sleep(REQUEST_DELAY)  # rate limit NVD entre deux pages

    return collected


def ingest_products(products: list[str]) -> int:
    """Récupère et indexe les CVE pour chaque produit de la liste.

    Retourne le nombre total de CVE indexées (après dédoublonnage par ID).
    """
    client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
    collection = client.get_or_create_collection(COLLECTION_NAME)

    seen_ids: set[str] = set()
    total_indexed = 0

    for product in products:
        logger.info("Récupération des CVE pour '%s'...", product)
        raw_results = fetch_cves_for_product(product)

        documents: list[str] = []
        metadatas: list[dict[str, Any]] = []
        ids: list[str] = []

        for entry in raw_results:
            cve = entry.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id or cve_id in seen_ids:
                continue  # un même CVE peut ressortir pour plusieurs produits recherchés

            description = _build_query_text(cve)
            if not description:
                continue  # rien d'exploitable pour l'embedding sans description

            seen_ids.add(cve_id)
            documents.append(description)
            metadatas.append({
                "cve_id": cve_id,
                "product": product,
                "cvss_score": _extract_cvss_score(cve) or 0.0,
                "published": cve.get("published", ""),
            })
            ids.append(cve_id)

        if documents:
            collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
            total_indexed += len(documents)
            logger.info("'%s' : %d CVE indexées", product, len(documents))
        else:
            logger.warning("'%s' : aucune CVE exploitable trouvée", product)

        time.sleep(REQUEST_DELAY)  # respecte le rate limit NVD entre deux produits

    return total_indexed


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    parser = argparse.ArgumentParser(description="Ingère des CVE NVD dans ChromaDB par produit.")
    parser.add_argument(
        "--products", nargs="+", required=True,
        help="Liste de produits à indexer, ex. --products apache nginx openssh mariadb",
    )
    args = parser.parse_args()

    total = ingest_products(args.products)
    logger.info("Ingestion terminée : %d CVE indexées au total.", total)


if __name__ == "__main__":
    main()