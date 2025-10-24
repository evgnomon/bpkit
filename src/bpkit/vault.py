"""
GPG-based secret encryption/decryption utility.
Processes data in memory without temporary files.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path

from bpkit.config import blueprint_config

SECRETS_DIR = Path.home() / ".config" / "blueprint" / "secrets"


class GPGNotFoundError(FileNotFoundError):
    """Raised when gpg command is not found in system PATH."""

    def __init__(self) -> None:
        super().__init__("gpg command not found")


class GPGKeyNotConfiguredError(ValueError):
    """Raised when GPG key is not configured."""

    def __init__(self) -> None:
        super().__init__("GPG key not configured")


def get_gpg_path() -> str:
    """Get the full path to the gpg executable."""
    gpg_path = shutil.which("gpg")
    if not gpg_path:
        raise GPGNotFoundError
    return gpg_path


def user_gpg_key() -> str:
    """
    Retrieve the user's GPG key identifier from environment variable or use default.

    Returns:
        GPG key identifier as a string.
    """
    user_key = os.getenv("BP_GPG_KEY", blueprint_config.gpg.key)
    if not user_key:
        raise GPGKeyNotConfiguredError
    return user_key


def encrypt_file(filename: str, gpg_key: str) -> None:
    """
    Encrypt data from stdin using GPG and save to secrets directory.

    Args:
        filename: Name for the encrypted file (will add .asc extension)
        gpg_key: GPG key identifier for recipient
    """
    gpg_key = gpg_key or user_gpg_key()
    if not filename:
        print("Please provide a file to encrypt and the recipient's key identifier.")
        sys.exit(1)

    # Create secrets directory if it doesn't exist
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)

    # Read from stdin
    input_data = sys.stdin.buffer.read()

    # Encrypt using GPG (process in memory)
    try:
        gpg_path = get_gpg_path()
        # Safe: gpg_path from shutil.which, args are controlled, no shell execution
        result = subprocess.run(  # noqa: S603
            [gpg_path, "-e", "-r", gpg_key, "--armor"],
            input=input_data,
            capture_output=True,
            check=True,
        )

        # Write encrypted output to file
        output_path = SECRETS_DIR / f"{filename}.asc"
        output_path.write_bytes(result.stdout)
        print(f"Encrypted and saved to {output_path}")

    except subprocess.CalledProcessError as e:
        print(f"Encryption failed: {e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: gpg command not found. Please install GnuPG.", file=sys.stderr)
        sys.exit(1)


def decrypt_file(filename: str) -> None:
    """
    Decrypt a file from secrets directory and output to stdout.

    Args:
        filename: Name of the file to decrypt (without .asc extension)
    """
    if not filename:
        print("Please provide a file to decrypt.")
        sys.exit(1)

    # Remove any trailing .asc extension if provided
    filename = filename.rstrip(".asc")

    # Construct file path
    file_path = SECRETS_DIR / f"{filename}.asc"

    if not file_path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    # Read encrypted file
    encrypted_data = file_path.read_bytes()

    # Decrypt using GPG (process in memory)
    try:
        gpg_path = get_gpg_path()
        # Safe: gpg_path from shutil.which, args are controlled, no shell execution
        result = subprocess.run([gpg_path, "--quiet", "-d"], input=encrypted_data, capture_output=True, check=True)  # noqa: S603

        # Output decrypted data to stdout
        sys.stdout.buffer.write(result.stdout)

    except subprocess.CalledProcessError as e:
        print(f"Decryption failed: {e.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: gpg command not found. Please install GnuPG.", file=sys.stderr)
        sys.exit(1)
