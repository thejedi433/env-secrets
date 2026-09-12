"""Tests for scanner module."""
import pytest
from pathlib import Path
from env_secrets import scanner


class TestScanContent:
    """Test secret pattern detection."""

    def test_detect_github_pat_classic(self):
        """Detect classic GitHub PAT."""
        content = "TOKEN=ghp_1234567890abcdef1234567890abcdef1234"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "GitHub PAT (classic)"
        assert findings[0][1].startswith("ghp_")

    def test_detect_github_pat_fine_grained(self):
        """Detect fine-grained GitHub PAT."""
        content = "TOKEN=github_pat_12345678901234567890"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "GitHub PAT (fine-grained)"
        assert findings[0][1].startswith("github_pat_")

    def test_detect_aws_access_key(self):
        """Detect AWS Access Key ID."""
        content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "AWS Access Key ID"
        assert findings[0][1].startswith("AKIA")

    def test_detect_aws_secret_key(self):
        """Detect AWS Secret Key."""
        content = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "AWS Secret Key"
        assert "aws_secret_access_key" in findings[0][1].lower()

    def test_detect_openai_key(self):
        """Detect OpenAI API key."""
        content = "OPENAI_API_KEY=sk-1234567890abcdef1234567890abcdef"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "OpenAI/Stripe API Key"
        assert findings[0][1].startswith("sk-")

    def test_detect_stripe_live_key(self):
        """Detect Stripe live key."""
        # Build key dynamically to avoid triggering GitHub secret scanner
        content = "STRIPE_KEY=" + "sk_" + "live_xxxxxxxxxxxxxxxxxxxxxxxx"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "Stripe Live Key"
        assert findings[0][1].startswith("sk_live_")

    def test_detect_hardcoded_password(self):
        """Detect hardcoded password."""
        content = "password=mysecretpassword123"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "Hardcoded password"
        assert "password" in findings[0][1].lower()

    def test_detect_api_key_generic(self):
        """Detect generic API key."""
        content = "api_key=abcdefghijklmnop1234"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "API key/secret"
        assert "api_key" in findings[0][1].lower()

    def test_detect_private_key(self):
        """Detect PEM private key."""
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "Private key block"
        assert "-----BEGIN" in findings[0][1]

    def test_detect_jwt_token(self):
        """Detect JWT token."""
        content = "token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        findings = scanner.scan_content(content)
        assert len(findings) == 1
        assert findings[0][0] == "JWT token"
        assert findings[0][1].startswith("eyJ")

    def test_no_secrets_found(self):
        """Return empty list when no secrets detected."""
        content = "DATABASE_URL=postgres://localhost/db\nDEBUG=true"
        findings = scanner.scan_content(content)
        assert len(findings) == 0

    def test_multiple_secrets(self):
        """Detect multiple secrets in same content."""
        content = """
TOKEN=ghp_1234567890abcdef1234567890abcdef1234
AWS_KEY=AKIAIOSFODNN7EXAMPLE
password=supersecretpassword123
        """
        findings = scanner.scan_content(content)
        assert len(findings) == 3
        patterns = [f[0] for f in findings]
        assert "GitHub PAT (classic)" in patterns
        assert "AWS Access Key ID" in patterns
        assert "Hardcoded password" in patterns


class TestScanFile:
    """Test file scanning."""

    def test_scan_file_with_secrets(self, tmp_path):
        """Scan file containing secrets."""
        test_file = tmp_path / ".env"
        test_file.write_text("TOKEN=ghp_1234567890abcdef1234567890abcdef1234")
        
        findings = scanner.scan_file(test_file)
        assert len(findings) == 1
        assert findings[0][0] == "GitHub PAT (classic)"

    def test_scan_file_no_secrets(self, tmp_path):
        """Scan clean file."""
        test_file = tmp_path / ".env"
        test_file.write_text("DATABASE_URL=postgres://localhost/db")
        
        findings = scanner.scan_file(test_file)
        assert len(findings) == 0

    def test_scan_nonexistent_file(self, tmp_path):
        """Handle nonexistent file gracefully."""
        test_file = tmp_path / "nonexistent.env"
        
        findings = scanner.scan_file(test_file)
        assert len(findings) == 0


class TestScanGitHistory:
    """Test git history scanning."""

    def test_scan_empty_repo(self, tmp_path):
        """Scan repo with no commits."""
        findings = scanner.scan_git_history(tmp_path)
        assert len(findings) == 0

    def test_scan_repo_with_secret_in_history(self, tmp_path):
        """Scan repo that has secrets in git history."""
        import subprocess
        
        # Initialize git repo
        subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, capture_output=True)
        
        # Create and commit file with secret
        env_file = tmp_path / "config.py"
        env_file.write_text("TOKEN=ghp_1234567890abcdef1234567890abcdef1234")
        subprocess.run(["git", "add", "config.py"], cwd=tmp_path, capture_output=True)
        subprocess.run(["git", "commit", "-m", "Add config"], cwd=tmp_path, capture_output=True)
        
        # Scan history
        findings = scanner.scan_git_history(tmp_path)
        assert len(findings) > 0
        assert findings[0]["pattern"] == "GitHub PAT (classic)"
        assert findings[0]["file"] == "config.py"

    def test_scan_non_git_directory(self, tmp_path):
        """Scan directory without git."""
        findings = scanner.scan_git_history(tmp_path)
        assert len(findings) == 0
