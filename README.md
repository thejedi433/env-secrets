# env-secrets

Encrypt/decrypt `.env` files with [age](https://age-encryption.org/) encryption, and scan for uncommitted secrets before pushing.

## Features

- **Encrypt/decrypt `.env` files** — commit `.env.age` safely, keep `.env.age.key` out of git
- **Scan git history** for leaked secrets in `.env` and config files
- **Pre-push hook** to block pushes containing secrets

## Install

```bash
pip install env-secrets
```

## Quick Start

```bash
# Initialize — generates age identity, encrypts .env if it exists
env-secrets init

# Add .env.age.key to .gitignore (the key, NOT the encrypted file)
echo ".env.age.key" >> .gitignore

# Later, decrypt when you need to edit
env-secrets decrypt

# Re-encrypt after editing
env-secrets encrypt

# Scan git history for leaked secrets
env-secrets scan
```

## Commands

| Command | Description |
|---------|-------------|
| `env-secrets init` | Generate age identity key and encrypt `.env` if present |
| `env-secrets encrypt` | Encrypt `.env` → `.env.age` |
| `env-secrets decrypt` | Decrypt `.env.age` → `.env` |
| `env-secrets scan` | Scan git history for leaked secrets |
| `env-secrets prepush` | Check staged files for secrets (for git hooks) |

## Git Hook Integration

Add a pre-push hook to block pushes containing secrets:

```bash
# In .git/hooks/pre-push:
#!/bin/sh
env-secrets prepush
```

## Detected Secret Patterns

- GitHub PATs (`ghp_*`, `github_pat_*`)
- AWS Access Keys (`AKIA*`)
- OpenAI/Stripe API keys (`sk-*`, `sk_live_*`)
- Hardcoded passwords
- Generic API keys/secrets
- PEM private keys
- JWT tokens

## License

MIT
