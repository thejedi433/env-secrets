"""Tests for crypto module."""
import pytest
from pathlib import Path
from env_secrets import crypto


class TestGenerateIdentity:
    """Test identity generation."""

    def test_generate_identity_returns_identity(self):
        """Generate identity returns valid identity object."""
        identity = crypto.generate_identity()
        assert identity is not None
        assert str(identity).startswith("AGE-SECRET-KEY-")

    def test_generate_identity_creates_unique_keys(self):
        """Each call generates unique identity."""
        identity1 = crypto.generate_identity()
        identity2 = crypto.generate_identity()
        assert str(identity1) != str(identity2)


class TestSaveLoadIdentity:
    """Test identity persistence."""

    def test_save_identity_creates_file(self, tmp_path):
        """Save identity creates file."""
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        
        crypto.save_identity(identity, key_path)
        
        assert key_path.exists()
        assert key_path.read_text().startswith("AGE-SECRET-KEY-")

    def test_save_identity_sets_permissions(self, tmp_path):
        """Save identity sets 600 permissions."""
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        
        crypto.save_identity(identity, key_path)
        
        # Check permissions (600 = owner read/write)
        import os
        mode = os.stat(key_path).st_mode & 0o777
        assert mode == 0o600

    def test_load_identity_reads_file(self, tmp_path):
        """Load identity reads from file."""
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        
        crypto.save_identity(identity, key_path)
        loaded = crypto.load_identity(key_path)
        
        assert str(loaded) == str(identity)

    def test_load_identity_missing_file(self, tmp_path):
        """Load identity raises error for missing file."""
        key_path = tmp_path / "nonexistent.key"
        
        with pytest.raises(FileNotFoundError):
            crypto.load_identity(key_path)


class TestEncryptDecrypt:
    """Test encryption/decryption."""

    def test_encrypt_creates_file(self, tmp_path):
        """Encrypt creates encrypted file."""
        # Setup
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        crypto.save_identity(identity, key_path)
        
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=secret123")
        
        enc_path = tmp_path / ".env.age"
        
        # Encrypt
        result = crypto.encrypt_file(env_path, enc_path, key_path)
        
        assert result == enc_path
        assert enc_path.exists()
        assert enc_path.read_bytes() != env_path.read_bytes()

    def test_encrypt_missing_key(self, tmp_path):
        """Encrypt raises error if key missing."""
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=secret123")
        
        key_path = tmp_path / "nonexistent.key"
        enc_path = tmp_path / ".env.age"
        
        with pytest.raises(FileNotFoundError):
            crypto.encrypt_file(env_path, enc_path, key_path)

    def test_encrypt_missing_env(self, tmp_path):
        """Encrypt raises error if .env missing."""
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        crypto.save_identity(identity, key_path)
        
        env_path = tmp_path / "nonexistent.env"
        enc_path = tmp_path / ".env.age"
        
        with pytest.raises(FileNotFoundError):
            crypto.encrypt_file(env_path, enc_path, key_path)

    def test_decrypt_creates_file(self, tmp_path):
        """Decrypt creates decrypted file."""
        # Setup
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        crypto.save_identity(identity, key_path)
        
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=secret123")
        
        enc_path = tmp_path / ".env.age"
        crypto.encrypt_file(env_path, enc_path, key_path)
        
        # Delete original
        env_path.unlink()
        
        # Decrypt
        decrypted_path = tmp_path / "decrypted.env"
        result = crypto.decrypt_file(enc_path, decrypted_path, key_path)
        
        assert result == decrypted_path
        assert decrypted_path.exists()
        assert decrypted_path.read_text() == "API_KEY=secret123"

    def test_decrypt_missing_key(self, tmp_path):
        """Decrypt raises error if key missing."""
        enc_path = tmp_path / ".env.age"
        enc_path.write_bytes(b"encrypted")
        
        key_path = tmp_path / "nonexistent.key"
        env_path = tmp_path / ".env"
        
        with pytest.raises(FileNotFoundError):
            crypto.decrypt_file(enc_path, env_path, key_path)

    def test_decrypt_missing_encrypted(self, tmp_path):
        """Decrypt raises error if encrypted file missing."""
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        crypto.save_identity(identity, key_path)
        
        enc_path = tmp_path / "nonexistent.age"
        env_path = tmp_path / ".env"
        
        with pytest.raises(FileNotFoundError):
            crypto.decrypt_file(enc_path, env_path, key_path)

    def test_roundtrip_encrypt_decrypt(self, tmp_path):
        """Encrypt then decrypt returns original."""
        # Setup
        identity = crypto.generate_identity()
        key_path = tmp_path / "test.key"
        crypto.save_identity(identity, key_path)
        
        env_path = tmp_path / ".env"
        original = "API_KEY=secret123\nDB_PASSWORD=hunter2"
        env_path.write_text(original)
        
        enc_path = tmp_path / ".env.age"
        crypto.encrypt_file(env_path, enc_path, key_path)
        
        # Delete original
        env_path.unlink()
        
        # Decrypt
        crypto.decrypt_file(enc_path, env_path, key_path)
        
        assert env_path.read_text() == original


class TestInitEnvSecrets:
    """Test initialization."""

    def test_init_creates_key(self, tmp_path):
        """Init creates key file."""
        key_path = tmp_path / "test.key"
        env_path = tmp_path / ".env"
        enc_path = tmp_path / ".env.age"
        
        result = crypto.init_env_secrets(env_path, key_path, enc_path)
        
        assert key_path.exists()
        assert result["identity"] is not None
        assert result["recipient"] is not None

    def test_init_encrypts_existing_env(self, tmp_path):
        """Init encrypts .env if it exists."""
        key_path = tmp_path / "test.key"
        env_path = tmp_path / ".env"
        env_path.write_text("API_KEY=secret123")
        enc_path = tmp_path / ".env.age"
        
        result = crypto.init_env_secrets(env_path, key_path, enc_path)
        
        assert result["encrypted"]
        assert enc_path.exists()

    def test_init_no_env_file(self, tmp_path):
        """Init without .env file."""
        key_path = tmp_path / "test.key"
        env_path = tmp_path / ".env"
        enc_path = tmp_path / ".env.age"
        
        result = crypto.init_env_secrets(env_path, key_path, enc_path)
        
        assert not result["encrypted"]
        assert not enc_path.exists()
