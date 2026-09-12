"""
Secret detection patterns and scanner
"""
import re
import subprocess
from typing import List, Dict, Tuple
from pathlib import Path


# Secret patterns to detect
SECRET_PATTERNS = [
    # GitHub tokens
    (r"ghp_[A-Za-z0-9_]{36,}", "GitHub PAT (classic)"),
    (r"github_pat_[A-Za-z0-9_]{12,}", "GitHub PAT (fine-grained)"),
    
    # AWS keys
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}", "AWS Secret Key"),
    
    # API keys (common prefixes)
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI/Stripe API Key"),
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe Live Key"),
    
    # Generic secrets
    (r"(?:password|passwd|pwd)\s*=\s*[^\s]{8,}", "Hardcoded password"),
    (r"(?:secret|api_key|apikey)\s*=\s*[A-Za-z0-9]{16,}", "API key/secret"),
    
    # Private keys
    (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "Private key block"),
    
    # JWT tokens (typical format)
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JWT token"),
]


def scan_content(content: str) -> List[Tuple[str, str]]:
    """
    Scan content for secrets.
    
    Returns list of (pattern_name, matched_text) tuples.
    """
    findings = []
    for pattern, name in SECRET_PATTERNS:
        matches = re.finditer(pattern, content, re.IGNORECASE)
        for match in matches:
            # Extract just the secret part, not the full context
            secret = match.group(0)
            findings.append((name, secret))
    return findings


def scan_file(filepath: Path) -> List[Tuple[str, str]]:
    """Scan a file for secrets."""
    try:
        content = filepath.read_text()
        return scan_content(content)
    except Exception as e:
        return []


def scan_git_history(repo_path: Path = None) -> List[Dict]:
    """
    Scan git history for secrets.
    
    Returns list of {commit, file, line, pattern, secret} dicts.
    """
    if repo_path is None:
        repo_path = Path.cwd()
    
    findings = []
    
    try:
        # Get all commits
        result = subprocess.run(
            ["git", "log", "--all", "--full-history", "--format=%H", "--", ".env", "*.env", "*.env.*", "config.py", "settings.py"],
            cwd=repo_path,
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return []
        
        commits = result.stdout.strip().split("\n")
        
        for commit_hash in commits:
            if not commit_hash:
                continue
            
            # Get files changed in this commit
            result = subprocess.run(
                ["git", "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit_hash],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            
            if result.returncode != 0:
                continue
            
            files = result.stdout.strip().split("\n")
            
            for filepath in files:
                if not filepath:
                    continue
                
                # Check if it's an env file or config
                if any(ext in filepath.lower() for ext in [".env", "config", "settings"]):
                    try:
                        # Get file content at this commit
                        result = subprocess.run(
                            ["git", "show", f"{commit_hash}:{filepath}"],
                            cwd=repo_path,
                            capture_output=True,
                            text=True
                        )
                        
                        if result.returncode == 0:
                            content = result.stdout
                            secrets = scan_content(content)
                            
                            for pattern_name, secret in secrets:
                                findings.append({
                                    "commit": commit_hash[:8],
                                    "file": filepath,
                                    "pattern": pattern_name,
                                    "secret": secret[:20] + "..." if len(secret) > 20 else secret
                                })
                    except Exception:
                        continue
    
    except Exception:
        return []
    
    return findings
