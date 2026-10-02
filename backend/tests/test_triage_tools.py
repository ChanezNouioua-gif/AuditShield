"""
Tests des fonctions pures du TriageAgent : parsing de bannière et détection
du contexte "before/fixed in" qui nous a fait corriger deux faux positifs
réels pendant le développement (Apache Traffic Server, OpenSSH "before 7.4").
"""

from app.agents.triage.tools import _version_explicitly_affected, parse_banner


class TestParseBanner:
    def test_apache_banner(self):
        result = parse_banner("HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)")
        assert result == {"product": "apache", "version": "2.4.49", "raw_banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)"}

    def test_openssh_banner(self):
        result = parse_banner("SSH-2.0-OpenSSH_7.4")
        assert result["product"] == "openssh"
        assert result["version"] == "7.4"

    def test_nginx_banner(self):
        result = parse_banner("nginx/1.18.0")
        assert result["product"] == "nginx"
        assert result["version"] == "1.18.0"

    def test_unrecognized_banner_returns_none(self):
        assert parse_banner("some-unknown-service/3.1") is None

    def test_empty_banner_returns_none(self):
        assert parse_banner("") is None
        assert parse_banner(None) is None


class TestVersionExplicitlyAffected:
    def test_direct_affects_statement_confirms(self):
        text = "This issue only affects Apache 2.4.49 and not earlier versions."
        assert _version_explicitly_affected(text, "2.4.49") is True

    def test_before_pattern_without_positive_mention_rejects(self):
        """Régression directe du bug trouvé en développement : 'OpenSSH before 7.4'
        veut dire que 7.4 CORRIGE le problème, pas qu'il en est affecté.
        """
        text = "sshd in OpenSSH before 7.4 does not ensure that a bounds check is enforced."
        assert _version_explicitly_affected(text, "7.4") is False

    def test_before_pattern_with_explicit_positive_mention_still_confirms(self):
        text = "Vulnerability before 7.4. This issue affects OpenSSH 7.4 specifically in some configurations."
        assert _version_explicitly_affected(text, "7.4") is True

    def test_no_version_mention_pattern_defaults_to_true(self):
        """Pas d'ambiguïté before/fixed-in détectée -> aucune raison de rejeter."""
        text = "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49."
        assert _version_explicitly_affected(text, "2.4.49") is True

    def test_fixed_in_pattern_rejects(self):
        text = "The issue was fixed in 2.4.50 and does not affect later releases."
        assert _version_explicitly_affected(text, "2.4.50") is False