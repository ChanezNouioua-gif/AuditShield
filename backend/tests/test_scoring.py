"""
Tests du scoring par catégorie (ReportAgent).

Ces tests ne touchent ni la base de données ni le réseau : ils valident la
logique de calcul pure, à partir de dictionnaires construits à la main.
"""

import pytest

from app.agents.report.scoring import (
    compute_category_scores,
    compute_global_score,
    score_category,
    score_email_security,
    score_headers,
    score_tls,
)


class TestScoreCategory:
    def test_no_findings_gives_perfect_score(self):
        assert score_category([]) == 100.0

    def test_confirmed_finding_penalizes_more_than_needs_review(self):
        confirmed = score_category([{"severity": 9.0, "confidence": "confirmed"}])
        needs_review = score_category([{"severity": 9.0, "confidence": "needs_manual_review"}])
        assert confirmed < needs_review

    def test_score_never_goes_below_zero(self):
        many_critical = [{"severity": 10.0, "confidence": "confirmed"} for _ in range(10)]
        assert score_category(many_critical) == 0.0

    def test_finding_without_severity_uses_flat_penalty(self):
        score = score_category([{"confidence": "confirmed", "severity": None}])
        assert 0.0 <= score < 100.0


class TestScoreEmailSecurity:
    def test_no_data_gives_perfect_score(self):
        assert score_email_security(None) == 100.0

    def test_missing_spf_and_dmarc_penalizes_heavily(self):
        result = score_email_security({
            "spf": {"present": False, "issues": []},
            "dmarc": {"present": False, "issues": []},
        })
        assert result == 50.0  # -25 SPF, -25 DMARC

    def test_present_but_with_issues_penalizes_less_than_absent(self):
        absent = score_email_security({
            "spf": {"present": False, "issues": []},
            "dmarc": {"present": True, "issues": []},
        })
        present_with_issues = score_email_security({
            "spf": {"present": True, "issues": ["Mécanisme ~all (softfail)"]},
            "dmarc": {"present": True, "issues": []},
        })
        assert present_with_issues > absent


class TestScoreTls:
    def test_unreachable_tls_is_not_penalized(self):
        """Pas de TLS testable n'est pas en soi un problème de score TLS."""
        assert score_tls({"reachable": False}, None) == 100.0

    def test_weak_protocol_accepted_penalizes(self):
        result = score_tls(
            {"reachable": True, "weak_protocols_accepted": ["TLSv1"], "weak_cipher": False},
            None,
        )
        assert result == 80.0

    def test_missing_hsts_penalizes(self):
        result = score_tls(
            {"reachable": True, "weak_protocols_accepted": [], "weak_cipher": False},
            {"present": False, "issues": []},
        )
        assert result == 85.0


class TestScoreHeaders:
    def test_unreachable_is_not_penalized(self):
        assert score_headers({"reachable": False}) == 100.0

    def test_absent_header_penalizes_more_than_misconfigured(self):
        absent = score_headers({
            "reachable": True,
            "headers": {"X-Frame-Options": {"present": False, "issues": ["Absent"]}},
        })
        misconfigured = score_headers({
            "reachable": True,
            "headers": {"X-Frame-Options": {"present": True, "issues": ["Valeur inhabituelle"]}},
        })
        assert absent < misconfigured

    def test_cookie_issues_penalize(self):
        result = score_headers({
            "reachable": True,
            "headers": {},
            "cookies": [{"cookie": "session", "issues": ["Flag Secure absent", "Flag HttpOnly absent"]}],
        })
        assert result == 90.0  # -5 par issue, 2 issues


class TestComputeCategoryScores:
    def test_known_vulns_and_exposed_services_come_from_findings(self):
        findings = [
            {"category": "known_vulns", "severity": 9.8, "confidence": "confirmed"},
            {"category": "exposed_services", "severity": None, "confidence": "confirmed"},
        ]
        scores = compute_category_scores(findings, scan_results={}, recon_results={})
        assert scores["known_vulns"] < 100.0
        assert scores["exposed_services"] < 100.0

    def test_email_comes_from_recon_not_scan(self):
        """Régression : email_security vit dans recon_results, pas scan_results —
        une erreur déjà commise une fois dans ce projet.
        """
        recon_results = {
            "email_security": {
                "spf": {"present": False, "issues": []},
                "dmarc": {"present": False, "issues": []},
            }
        }
        scores = compute_category_scores([], scan_results={}, recon_results=recon_results)
        assert scores["email"] == 50.0

    def test_empty_everything_gives_perfect_scores(self):
        scores = compute_category_scores([], scan_results={}, recon_results={})
        assert all(score == 100.0 for score in scores.values())


class TestComputeGlobalScore:
    def test_all_perfect_scores_gives_100(self):
        scores = {"known_vulns": 100.0, "exposed_services": 100.0, "tls": 100.0, "headers": 100.0, "email": 100.0}
        assert compute_global_score(scores) == 100.0

    def test_known_vulns_weighs_more_than_email(self):
        """known_vulns a un poids de 0.30 contre 0.15 pour email : une baisse
        sur known_vulns doit impacter le score global plus fortement.
        """
        base = {"known_vulns": 100.0, "exposed_services": 100.0, "tls": 100.0, "headers": 100.0, "email": 100.0}

        low_vulns = {**base, "known_vulns": 0.0}
        low_email = {**base, "email": 0.0}

        assert compute_global_score(low_vulns) < compute_global_score(low_email)

    def test_missing_category_defaults_to_100(self):
        """Une catégorie absente du dict ne doit pas faire planter le calcul."""
        assert compute_global_score({"known_vulns": 50.0}) > 0