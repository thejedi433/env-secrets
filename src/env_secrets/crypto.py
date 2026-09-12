"""
age encryption/decryption for .env files
"""
from pathlib import Path
from typing import Optional
from pyrage import x25519, encrypt, decrypt


DEFAULT_KEY_FILE = ".env.age.key"
DEFAULT_ENV_FILE = ".env"
DEFAULT_ENC_FILE = ".env.age"


def generate_identity() -> x25519.Identity:
    """Generate a new age identity (private key)."""
    return x25519.Identity.generate()


def save_identity(identity: x25519.Identity, key_path: Path) -> None:
    """Save identity to file with secure permissions."""
    key_path.write_text(str(identity))
    # Set permissions to 600 (owner read/write only)
    key_path.chmod(0o600)


def load_identity(key_path: Path) -> x25519.Identity:
    """Load identity from file."""
    if not key_path.exists():
        raise FileNotFoundError(f"Identity file not found: {key_path}")
    
    key_data = key_path.read_text().strip()
    return x25519.Identity.from_str(key_data)


def encrypt_file(
    env_path: Path = None,
    enc_path: Path = None,
    key_path: Path = None
) -> Path:
    """
    Encrypt .env file to .env.age.
    
    Returns path to encrypted file.
    """
    if env_path is None:
        env_path = Path(DEFAULT_ENV_FILE)
    if enc_path is None:
        enc_path = Path(DEFAULT_ENC_FILE)
    if key_path is None:
        key_path = Path(DEFAULT_KEY_FILE)
    
    # Load identity
    identity = load_identity(key_path)
    recipient = identity.to_public()
    
    # Read plaintext
    if not env_path.exists():
        raise FileNotFoundError(f"File not found: {env_path}")
    
    plaintext = env_path.read_bytes()
    
    # Encrypt
    encrypted = encrypt(plaintext, [recipient])
    
    # Write encrypted file
    enc_path.write_bytes(encrypted)
    
    return enc_path


def decrypt_file(
    enc_path: Path = None,
    env_path: Path = None,
    key_path: Path = None
) -> Path:
    """
    Decrypt .env.age file to .env.
    
    Returns path to decrypted file.
    """
    if enc_path is None:
        enc_path = Path(DEFAULT_ENC_FILE)
    if env_path is None:
        env_path = Path(DEFAULT_ENV_FILE)
    if key_path is None:
        key_path = Path(DEFAULT_KEY_FILE)
    
    # Load identity
    identity = load_identity(key_path)
    
    # Read encrypted file
    if not enc_path.exists():
        raise FileNotFoundError(f"File not found: {enc_path}")
    
    encrypted = enc_path.read_bytes()
    
    # Decrypt
    decrypted = decrypt(encrypted, [identity])
    
    # Write plaintext
    env_path.write_bytes(decrypted)
    
    return env_path


def init_env_secrets(
    env_path: Path = None,
    key_path: Path = None,
    enc_path: Path = None
) -> dict:
    """
    Initialize env-secrets: generate key, encrypt .env if exists.
    
    Returns dict with paths.
    """
    if env_path is None:
        env_path = Path(DEFAULT_ENV_FILE)
    if key_path is None:
        key_path = Path(DEFAULT_KEY_FILE)
    if enc_path is None:
        enc_path = Path(DEFAULT_ENC_FILE)
    
    # Generate identity
    identity = generate_identity()
    save_identity(identity, key_path)
    
    # Encrypt if .env exists
    encrypted = False
    if env_path.exists():
        encrypt_file(env_path, enc_path, key_path)
        encrypted = True
    
    return {
        "identity": identity,
        "recipient": identity.to_public(),
        "key_path": key_path,
        "encrypted": encrypted
    }
