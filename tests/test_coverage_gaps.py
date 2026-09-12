"""Tests to achieve 100% coverage for env-secrets"""
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest
from click.testing import CliRunner

from env_secrets import cli, crypto, scanner


class TestCLIErrorHandling:
    """Test error handling paths in CLI"""

    def test_encrypt_generic_exception(self, tmp_path):
        """Test encrypt command catching generic exception"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Create .env and key
        Path(".env").write_text("TEST=value")
        identity = crypto.generate_identity()
        crypto.save_identity(identity, Path(".env.age.key"))
        
        # Mock encrypt_file to raise generic exception
        with patch('env_secrets.crypto.encrypt_file', side_effect=Exception("Generic error")):
            result = runner.invoke(cli.encrypt, ['--env', '.env', '--key', '.env.age.key', '--out', '.env.age'])
            assert result.exit_code == 1
            assert "Generic error" in result.output

    def test_decrypt_generic_exception(self, tmp_path):
        """Test decrypt command catching generic exception"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Create key and encrypted file
        identity = crypto.generate_identity()
        crypto.save_identity(identity, Path(".env.age.key"))
        Path(".env.age").write_bytes(b"encrypted")
        
        # Mock decrypt_file to raise generic exception
        with patch('env_secrets.crypto.decrypt_file', side_effect=Exception("Generic error")):
            result = runner.invoke(cli.decrypt, ['--env', '.env', '--key', '.env.age.key', '--out', '.env.age'])
            assert result.exit_code == 1
            assert "Generic error" in result.output

    def test_scan_with_multiple_secrets(self, tmp_path):
        """Test scan command with multiple secrets found"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Mock scanner.scan_git_history to return findings
        mock_findings = [
            {"commit": "abc123", "file": ".env", "pattern": "API_KEY", "secret": "secret123"},
            {"commit": "abc123", "file": ".env", "pattern": "AWS_SECRET", "secret": "aws_key"},
        ]
        
        with patch('env_secrets.scanner.scan_git_history', return_value=mock_findings):
            result = runner.invoke(cli.scan, ['--path', str(tmp_path)])
            assert result.exit_code == 0
            # Should show findings with formatting
            assert "Found 2 potential secret(s)" in result.output
            # Check for rotation warning
            assert "rotated" in result.output.lower()

    def test_scan_empty_git_log(self, tmp_path):
        """Test scan when git log returns empty"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Initialize empty git repo
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Create initial commit
        Path("README.md").write_text("test")
        subprocess.run(['git', 'add', 'README.md'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Initial'], cwd=tmp_path, capture_output=True)
        
        result = runner.invoke(cli.scan, ['--path', str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_diff_tree_fails(self, tmp_path):
        """Test scan when git diff-tree fails"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Initialize git repo
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Create a commit
        Path(".env").write_text("TEST=value")
        subprocess.run(['git', 'add', '.env'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add env'], cwd=tmp_path, capture_output=True)
        
        # Mock diff-tree to fail
        original_run = subprocess.run
        def mock_run(cmd, *args, **kwargs):
            if 'diff-tree' in cmd:
                return MagicMock(returncode=1, stdout='', stderr='error')
            return original_run(cmd, *args, **kwargs)
        
        with patch('subprocess.run', side_effect=mock_run):
            result = runner.invoke(cli.scan, ['--path', str(tmp_path)])
            assert result.exit_code == 0

    def test_prepush_with_staged_secrets(self, tmp_path):
        """Test prepush command with actual staged secrets"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Initialize git repo
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Create initial commit
        Path("README.md").write_text("test")
        subprocess.run(['git', 'add', 'README.md'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Initial'], cwd=tmp_path, capture_output=True)
        
        # Stage file with secret
        Path("config.py").write_text("API_KEY=***")
        subprocess.run(['git', 'add', 'config.py'], cwd=tmp_path, capture_output=True)
        
        # Mock scan_file to return secrets
        def mock_scan_file(path):
            if path.name == "config.py":
                return [("Hardcoded password", "mysecretpassword123")]
            return []
        
        with patch('env_secrets.cli.scanner.scan_file', side_effect=mock_scan_file):
            result = runner.invoke(cli.prepush)
            # Should detect secrets and exit with error
            assert result.exit_code == 1
            assert "Potential secrets" in result.stderr

    def test_prepush_no_staged_files(self, tmp_path):
        """Test prepush with no staged files"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Initialize git repo
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        result = runner.invoke(cli.prepush)
        assert result.exit_code == 0

    def test_prepush_git_diff_fails(self, tmp_path):
        """Test prepush when git diff fails"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        with patch('subprocess.run', side_effect=Exception("Git error")):
            result = runner.invoke(cli.prepush)
            assert result.exit_code == 0  # Should not crash


class TestCryptoDefaultParameters:
    """Test default parameter handling in crypto module"""

    def test_encrypt_with_all_defaults(self, tmp_path):
        """Test encrypt_file with all default parameters"""
        os.chdir(tmp_path)
        
        # Create .env and key
        Path(".env").write_text("TEST=value")
        identity = crypto.generate_identity()
        crypto.save_identity(identity, Path(".env.age.key"))
        
        # Call with all defaults (should use .env, .env.age, .env.age.key)
        result = crypto.encrypt_file()
        assert result == Path(".env.age")
        assert Path(".env.age").exists()

    def test_decrypt_with_all_defaults(self, tmp_path):
        """Test decrypt_file with all default parameters"""
        os.chdir(tmp_path)
        
        # Create encrypted file
        Path(".env").write_text("TEST=value")
        identity = crypto.generate_identity()
        crypto.save_identity(identity, Path(".env.age.key"))
        crypto.encrypt_file(Path(".env"), Path(".env.age"), Path(".env.age.key"))
        Path(".env").unlink()
        
        # Call with all defaults
        result = crypto.decrypt_file()
        assert result == Path(".env")
        assert Path(".env").exists()
        assert Path(".env").read_text() == "TEST=value"

    def test_init_env_secrets_with_all_defaults(self, tmp_path):
        """Test init_env_secrets with all default parameters"""
        os.chdir(tmp_path)
        
        # Create .env file
        Path(".env").write_text("TEST=value")
        
        # Call with all defaults
        result = crypto.init_env_secrets()
        assert Path(".env.age.key").exists()
        assert Path(".env.age").exists()
        assert result['key_path'] == Path(".env.age.key")
        assert result['encrypted'] is True

    def test_encrypt_with_partial_defaults(self, tmp_path):
        """Test encrypt_file with some default parameters"""
        os.chdir(tmp_path)
        
        Path(".env").write_text("TEST=value")
        identity = crypto.generate_identity()
        crypto.save_identity(identity, Path(".env.age.key"))
        
        # Call with only env_path specified (use defaults for key and enc)
        result = crypto.encrypt_file(env_path=Path(".env"))
        assert result == Path(".env.age")

    def test_decrypt_with_partial_defaults(self, tmp_path):
        """Test decrypt_file with some default parameters"""
        os.chdir(tmp_path)
        
        Path(".env").write_text("TEST=value")
        identity = crypto.generate_identity()
        crypto.save_identity(identity, Path(".env.age.key"))
        crypto.encrypt_file(Path(".env"), Path("custom.age"), Path(".env.age.key"))
        
        # Call with only enc_path specified
        result = crypto.decrypt_file(enc_path=Path("custom.age"))
        assert result == Path(".env")


class TestScannerDefaultParameters:
    """Test default parameter handling in scanner module"""

    def test_scan_git_history_with_default_path(self, tmp_path):
        """Test scan_git_history with default repo_path"""
        os.chdir(tmp_path)
        
        # Initialize git repo in current directory
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Create initial commit
        Path("README.md").write_text("test")
        subprocess.run(['git', 'add', 'README.md'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Initial'], cwd=tmp_path, capture_output=True)
        
        # Call with default path
        findings = scanner.scan_git_history()
        assert isinstance(findings, list)

    def test_scan_git_history_with_non_env_files(self, tmp_path):
        """Test scan_git_history skips non-env files"""
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Commit a non-env file
        Path("regular.txt").write_text("hello")
        subprocess.run(['git', 'add', 'regular.txt'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add regular file'], cwd=tmp_path, capture_output=True)
        
        findings = scanner.scan_git_history()
        assert findings == []

    def test_scan_git_history_with_env_file_no_secrets(self, tmp_path):
        """Test scan_git_history with .env file but no secrets"""
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Commit a clean .env file
        Path(".env").write_text("DATABASE_URL=localhost\nDEBUG=true")
        subprocess.run(['git', 'add', '.env'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add clean env'], cwd=tmp_path, capture_output=True)
        
        findings = scanner.scan_git_history()
        assert findings == []

    def test_scan_git_history_no_env_files(self, tmp_path):
        """Test scan_git_history with commits but no .env files"""
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Create commits without .env files
        Path("README.md").write_text("test")
        subprocess.run(['git', 'add', 'README.md'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Initial'], cwd=tmp_path, capture_output=True)
        
        Path("config.json").write_text('{"key": "value"}')
        subprocess.run(['git', 'add', 'config.json'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add config'], cwd=tmp_path, capture_output=True)
        
        findings = scanner.scan_git_history()
        assert findings == []

    def test_scan_git_history_empty_commit(self, tmp_path):
        """Test scan_git_history with commit that has no files"""
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Create initial commit
        Path("README.md").write_text("test")
        subprocess.run(['git', 'add', 'README.md'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Initial'], cwd=tmp_path, capture_output=True)
        
        # Create empty commit
        subprocess.run(['git', 'commit', '--allow-empty', '-m', 'Empty'], cwd=tmp_path, capture_output=True)
        
        findings = scanner.scan_git_history()
        assert isinstance(findings, list)


class TestMainFunction:
    """Test main entry point"""

    def test_main_cli_group(self):
        """Test that main CLI group is properly configured"""
        from env_secrets.cli import cli
        runner = CliRunner()
        result = runner.invoke(cli, ['--help'])
        assert result.exit_code == 0
        assert "env-secrets" in result.output.lower() or "Usage" in result.output

    def test_main_function(self):
        """Test the main() entry point"""
        from env_secrets.cli import main
        with patch('env_secrets.cli.cli') as mock_cli:
            main()
            mock_cli.assert_called_once()

    def test_prepush_skip_empty_filepath(self, tmp_path):
        """Test prepush skips empty filepath in git diff output"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        # Initialize git repo
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Mock git diff to return file list with empty line
        def mock_run(cmd, *args, **kwargs):
            if cmd[0] == 'git' and 'diff' in cmd:
                return MagicMock(returncode=0, stdout="\nfile1.py\nfile2.py\n")
            return MagicMock(returncode=1, stdout='')
        
        def mock_scan_file(path):
            return []  # No secrets
        
        with patch('subprocess.run', side_effect=mock_run), \
             patch('env_secrets.cli.scanner.scan_file', side_effect=mock_scan_file):
            result = runner.invoke(cli.prepush)
            # Should not fail, empty filepath was skipped
            assert result.exit_code == 0

    def test_prepush_empty_filepath_in_list(self, tmp_path):
        """Test prepush handles empty filepath in middle of file list (line 150)"""
        runner = CliRunner()
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Mock git diff to return file list with empty line in middle
        # "file1.py\n\nfile2.py" → strip → "file1.py\n\nfile2.py" → split → ["file1.py", "", "file2.py"]
        def mock_run(cmd, *args, **kwargs):
            if cmd[0] == 'git' and 'diff' in cmd:
                return MagicMock(returncode=0, stdout="file1.py\n\nfile2.py")
            return MagicMock(returncode=1, stdout='')
        
        def mock_scan_file(path):
            return []
        
        with patch('subprocess.run', side_effect=mock_run), \
             patch('env_secrets.cli.scanner.scan_file', side_effect=mock_scan_file):
            result = runner.invoke(cli.prepush)
            assert result.exit_code == 0


class TestScannerExceptionPaths:
    """Cover scanner exception paths (lines 105, 129-133)"""

    def test_scan_git_history_empty_filepath_in_diff_tree(self, tmp_path):
        """Test scan_git_history with empty filepath in diff-tree output (line 105)"""
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        Path("README.md").write_text("test")
        subprocess.run(['git', 'add', 'README.md'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Initial'], cwd=tmp_path, capture_output=True)
        
        # Mock diff-tree to return output with empty line in middle
        original_run = subprocess.run
        def mock_run(cmd, *args, **kwargs):
            if 'diff-tree' in cmd:
                return MagicMock(returncode=0, stdout=".env\n\nconfig.py\n")
            return original_run(cmd, *args, **kwargs)
        
        with patch('subprocess.run', side_effect=mock_run):
            findings = scanner.scan_git_history()
            assert isinstance(findings, list)

    def test_scan_git_history_exception_in_scan_content(self, tmp_path):
        """Test scan_git_history handles exception during scanning (lines 129-130)"""
        os.chdir(tmp_path)
        
        subprocess.run(['git', 'init'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], cwd=tmp_path, capture_output=True)
        
        # Commit a .env file with a secret
        Path(".env").write_text("API_KEY=***")
        subprocess.run(['git', 'add', '.env'], cwd=tmp_path, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add env'], cwd=tmp_path, capture_output=True)
        
        # Mock scan_content to raise exception (covers lines 129-130)
        with patch('env_secrets.scanner.scan_content', side_effect=Exception("Test error")):
            findings = scanner.scan_git_history()
            # Should continue past exception
            assert isinstance(findings, list)

    def test_scan_git_history_outer_exception(self, tmp_path):
        """Test scan_git_history handles outer exception (lines 132-133)"""
        os.chdir(tmp_path)
        
        # Mock git log to raise exception immediately (covers lines 132-133)
        with patch('subprocess.run', side_effect=Exception("Git not available")):
            findings = scanner.scan_git_history()
            assert findings == []

    def test_scan_git_history_with_empty_filepath(self, tmp_path):
        """Test scan_git_history skips empty filepaths and non-env files (lines 105, 108->103)."""
        os.chdir(tmp_path)
        subprocess.run(['git', 'init'], check=True, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], check=True, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], check=True, capture_output=True)
        
        # Create a commit with .env file
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=***")
        main_file = tmp_path / "main.py"
        main_file.write_text("print('hello')")
        subprocess.run(['git', 'add', '.env', 'main.py'], check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add files'], check=True, capture_output=True)
        
        # Mock diff-tree to return .env, empty line, and a non-env file (main.py)
        original_run = subprocess.run
        call_count = {'diff_tree': 0, 'show': 0}
        
        def mock_diff_tree(*args, **kwargs):
            if args[0] and 'diff-tree' in args[0]:
                call_count['diff_tree'] += 1
                # .env (matches), empty line (skipped), main.py (doesn't match -> 108->103)
                mock_result = type('MockResult', (), {
                    'stdout': '.env\n\nmain.py\n',
                    'returncode': 0,
                    'stderr': ''
                })()
                return mock_result
            elif args[0] and 'show' in args[0]:
                call_count['show'] += 1
                # For the .env file, return the secret content
                if '.env' in args[0][-1]:
                    return type('MockResult', (), {
                        'stdout': 'API_KEY=***',
                        'returncode': 0,
                        'stderr': ''
                    })()
                # For main.py, should not be called (filtered at line 108)
                return type('MockResult', (), {
                    'stdout': '',
                    'returncode': 0,
                    'stderr': ''
                })()
            return original_run(*args, **kwargs)
        
        with patch('subprocess.run', side_effect=mock_diff_tree):
            findings = scanner.scan_git_history()
            # Should process the .env file and skip empty + non-env file
            assert call_count['diff_tree'] > 0
            # main.py should not trigger git show
            assert call_count['show'] == 1  # only .env

    def test_scan_git_history_with_deleted_file(self, tmp_path):
        """Test scan_git_history handles deleted env files (line 118->103)."""
        os.chdir(tmp_path)
        subprocess.run(['git', 'init'], check=True, capture_output=True)
        subprocess.run(['git', 'config', 'user.email', 'test@example.com'], check=True, capture_output=True)
        subprocess.run(['git', 'config', 'user.name', 'Test'], check=True, capture_output=True)
        
        # Create initial commit with .env
        env_file = tmp_path / ".env"
        env_file.write_text("API_KEY=***")
        subprocess.run(['git', 'add', '.env'], check=True, capture_output=True)
        subprocess.run(['git', 'commit', '-m', 'Add .env'], check=True, capture_output=True)
        
        # Mock diff-tree and git show: git show returns non-zero (file deleted)
        original_run = subprocess.run
        def mock_run(*args, **kwargs):
            if args[0] and 'diff-tree' in args[0]:
                return type('MockResult', (), {
                    'stdout': '.env\n',
                    'returncode': 0,
                    'stderr': ''
                })()
            elif args[0] and 'show' in args[0]:
                # File was deleted at this commit
                return type('MockResult', (), {
                    'stdout': '',
                    'returncode': 1,
                    'stderr': 'fatal: path .env does not exist'
                })()
            return original_run(*args, **kwargs)
        
        with patch('subprocess.run', side_effect=mock_run):
            findings = scanner.scan_git_history()
            # Should not crash, deleted file is skipped
            assert findings == []
