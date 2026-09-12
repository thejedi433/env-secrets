"""
CLI interface for env-secrets
"""
import click
from pathlib import Path
from . import crypto, scanner


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """Encrypt/decrypt .env files and scan for secrets."""
    pass


@cli.command()
@click.option("--env", "env_path", type=click.Path(), default=".env",
              help="Path to .env file")
@click.option("--key", "key_path", type=click.Path(), default=".env.age.key",
              help="Path to store age identity (private key)")
@click.option("--out", "enc_path", type=click.Path(), default=".env.age",
              help="Path for encrypted output")
def init(env_path: str, key_path: str, enc_path: str):
    """Initialize env-secrets: generate key and encrypt .env if it exists."""
    try:
        result = crypto.init_env_secrets(
            Path(env_path),
            Path(key_path),
            Path(enc_path)
        )
        
        click.echo(f"✓ Generated age identity: {result['key_path']}")
        click.echo(f"  Public key: {result['recipient']}")
        
        if result['encrypted']:
            click.echo(f"✓ Encrypted {env_path} → {enc_path}")
        else:
            click.echo(f"  No {env_path} found (you can encrypt later with 'env-secrets encrypt')")
        
        click.echo("\n⚠️  Important: Add .env.age.key to .gitignore!")
        click.echo("   Add .env to .gitignore if not already there")
        click.echo("   Commit .env.age (it's safe to version)")
        
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        raise SystemExit(1)


@cli.command()
@click.option("--env", "env_path", type=click.Path(), default=".env",
              help="Path to .env file")
@click.option("--key", "key_path", type=click.Path(), default=".env.age.key",
              help="Path to age identity")
@click.option("--out", "enc_path", type=click.Path(), default=".env.age",
              help="Path for encrypted output")
def encrypt(env_path: str, key_path: str, enc_path: str):
    """Encrypt .env file to .env.age."""
    try:
        result = crypto.encrypt_file(
            Path(env_path),
            Path(enc_path),
            Path(key_path)
        )
        click.echo(f"✓ Encrypted {env_path} → {result}")
    except FileNotFoundError as e:
        click.echo(f"✗ {e}", err=True)
        click.echo("  Run 'env-secrets init' first to generate a key")
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        raise SystemExit(1)


@cli.command()
@click.option("--env", "env_path", type=click.Path(), default=".env",
              help="Path to output .env file")
@click.option("--key", "key_path", type=click.Path(), default=".env.age.key",
              help="Path to age identity")
@click.option("--out", "enc_path", type=click.Path(), default=".env.age",
              help="Path to encrypted file")
def decrypt(env_path: str, key_path: str, enc_path: str):
    """Decrypt .env.age file to .env."""
    try:
        result = crypto.decrypt_file(
            Path(enc_path),
            Path(env_path),
            Path(key_path)
        )
        click.echo(f"✓ Decrypted {enc_path} → {result}")
    except FileNotFoundError as e:
        click.echo(f"✗ {e}", err=True)
        click.echo("  Make sure .env.age exists and run 'env-secrets init' to generate a key")
        raise SystemExit(1)
    except Exception as e:
        click.echo(f"✗ Error: {e}", err=True)
        raise SystemExit(1)


@cli.command()
@click.option("--path", "repo_path", type=click.Path(exists=True), default=".",
              help="Path to git repository")
def scan(repo_path: str):
    """Scan git history for secrets in .env files."""
    click.echo("Scanning git history for secrets...")
    click.echo()
    
    findings = scanner.scan_git_history(Path(repo_path))
    
    if not findings:
        click.echo("✓ No secrets found in git history")
        return
    
    click.echo(f"⚠️  Found {len(findings)} potential secret(s):\n")
    
    for finding in findings:
        click.echo(f"  Commit: {finding['commit']}")
        click.echo(f"  File:   {finding['file']}")
        click.echo(f"  Type:   {finding['pattern']}")
        click.echo(f"  Value:  {finding['secret']}")
        click.echo()
    
    click.echo("⚠️  These secrets are in git history and should be rotated!")
    click.echo("   Consider using 'git filter-branch' or BFG Repo-Cleaner to remove them.")


@cli.command()
def prepush():
    """Scan staged changes for secrets (for git pre-push hook)."""
    try:
        import subprocess
        
        # Get staged files
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return
        
        files = result.stdout.strip().split("\n")
        
        if not files or files == [""]:
            return
        
        findings = []
        for filepath in files:
            if not filepath:
                continue
            
            path = Path(filepath)
            if path.exists() and path.is_file():
                secrets = scanner.scan_file(path)
                for pattern_name, secret in secrets:
                    findings.append({
                        "file": filepath,
                        "pattern": pattern_name,
                        "secret": secret[:20] + "..." if len(secret) > 20 else secret
                    })
        
        if not findings:
            return  # Clean, no output
        
        click.echo("⚠️  Potential secrets detected in staged files:\n", err=True)
        for finding in findings:
            click.echo(f"  {finding['file']}: {finding['pattern']}", err=True)
            click.echo(f"    {finding['secret']}", err=True)
        
        click.echo("\nRefusing to push. Remove secrets or use --no-verify to skip.", err=True)
        raise SystemExit(1)
        
    except SystemExit:
        raise
    except Exception:
        # Don't block push on scan errors
        pass


def main():
    """Entry point."""
    cli()


if __name__ == "__main__":
    main()
