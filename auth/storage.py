"""Storage backends for credentials and tokens.

Provides session-based and file-based storage with encryption,
plus a hybrid storage that allows per-API storage preference.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)


@dataclass
class StoredToken:
    """Token data structure for storage.

    Attributes:
        access_token: The access token string
        token_type: Token type (usually "Bearer")
        expires_in: Token lifetime in seconds (from when obtained)
        refresh_token: Optional refresh token
        scope: Space-separated scopes
        obtained_at: ISO timestamp when token was obtained
    """

    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    obtained_at: Optional[str] = None

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Check if token is expired with optional buffer.

        Args:
            buffer_seconds: Consider expired this many seconds before actual expiry

        Returns:
            True if token is expired or will expire within buffer_seconds
        """
        if not self.expires_in or not self.obtained_at:
            return False

        try:
            obtained = datetime.fromisoformat(self.obtained_at)
            elapsed = (datetime.now() - obtained).total_seconds()
            return elapsed >= (self.expires_in - buffer_seconds)
        except (ValueError, TypeError):
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StoredToken":
        """Create from dictionary."""
        return cls(
            access_token=data.get("access_token", ""),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token"),
            scope=data.get("scope"),
            obtained_at=data.get("obtained_at"),
        )


@dataclass
class StoredCredentials:
    """Credentials data structure for storage.

    Attributes:
        scheme_name: Name of the security scheme
        scheme_type: Type of scheme (apiKey, http, oauth2, etc.)
        values: Credential values (e.g., api_key, username, password, client_id)
        custom_headers: User-defined custom headers
    """

    scheme_name: str
    scheme_type: str
    values: Dict[str, str]
    custom_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StoredCredentials":
        """Create from dictionary."""
        return cls(
            scheme_name=data.get("scheme_name", ""),
            scheme_type=data.get("scheme_type", ""),
            values=data.get("values", {}),
            custom_headers=data.get("custom_headers", {}),
        )


class StorageBackend(ABC):
    """Abstract base class for credential and token storage."""

    @abstractmethod
    def save_credentials(self, api_id: str, credentials: StoredCredentials) -> None:
        """Save credentials for an API.

        Args:
            api_id: Unique identifier for the API
            credentials: Credentials to store
        """
        pass

    @abstractmethod
    def load_credentials(self, api_id: str) -> Optional[StoredCredentials]:
        """Load credentials for an API.

        Args:
            api_id: Unique identifier for the API

        Returns:
            Stored credentials or None if not found
        """
        pass

    @abstractmethod
    def save_token(self, api_id: str, token: StoredToken) -> None:
        """Save token for an API.

        Args:
            api_id: Unique identifier for the API
            token: Token to store
        """
        pass

    @abstractmethod
    def load_token(self, api_id: str) -> Optional[StoredToken]:
        """Load token for an API.

        Args:
            api_id: Unique identifier for the API

        Returns:
            Stored token or None if not found
        """
        pass

    @abstractmethod
    def delete_api(self, api_id: str) -> None:
        """Delete all data for an API.

        Args:
            api_id: Unique identifier for the API
        """
        pass

    @abstractmethod
    def list_apis(self) -> list[str]:
        """List all stored API IDs.

        Returns:
            List of API identifiers
        """
        pass


class SessionStorage(StorageBackend):
    """Flask session-based storage.

    Stores credentials and tokens in the Flask session.
    Data is cleared when the browser session ends.

    This is the more secure option as credentials are not
    persisted to disk.
    """

    def __init__(self, session_dict: Dict[str, Any]):
        """Initialize with Flask session dictionary.

        Args:
            session_dict: Flask session object or compatible dict
        """
        self._session = session_dict

    def _ensure_storage(self) -> None:
        """Ensure storage keys exist in session."""
        if "_auth_credentials" not in self._session:
            self._session["_auth_credentials"] = {}
        if "_auth_tokens" not in self._session:
            self._session["_auth_tokens"] = {}

    def save_credentials(self, api_id: str, credentials: StoredCredentials) -> None:
        self._ensure_storage()
        self._session["_auth_credentials"][api_id] = credentials.to_dict()

    def load_credentials(self, api_id: str) -> Optional[StoredCredentials]:
        self._ensure_storage()
        data = self._session["_auth_credentials"].get(api_id)
        if data:
            return StoredCredentials.from_dict(data)
        return None

    def save_token(self, api_id: str, token: StoredToken) -> None:
        self._ensure_storage()
        self._session["_auth_tokens"][api_id] = token.to_dict()

    def load_token(self, api_id: str) -> Optional[StoredToken]:
        self._ensure_storage()
        data = self._session["_auth_tokens"].get(api_id)
        if data:
            return StoredToken.from_dict(data)
        return None

    def delete_api(self, api_id: str) -> None:
        self._ensure_storage()
        self._session["_auth_credentials"].pop(api_id, None)
        self._session["_auth_tokens"].pop(api_id, None)

    def list_apis(self) -> list[str]:
        self._ensure_storage()
        cred_apis = set(self._session["_auth_credentials"].keys())
        token_apis = set(self._session["_auth_tokens"].keys())
        return list(cred_apis | token_apis)


class FileStorage(StorageBackend):
    """Encrypted file-based storage.

    Stores credentials and tokens in encrypted JSON files.
    Each API gets its own file in the storage directory.

    Encryption uses Fernet (AES-128-CBC) with a key derived
    from the provided encryption key (typically Flask secret_key).
    """

    def __init__(self, storage_dir: str, encryption_key: str):
        """Initialize file storage.

        Args:
            storage_dir: Directory path for storing files
            encryption_key: Key for encrypting/decrypting data
        """
        self._storage_dir = Path(storage_dir)
        self._fernet = self._create_fernet(encryption_key)
        self._ensure_directory()

    def _create_fernet(self, key: str) -> Fernet:
        """Create Fernet instance from arbitrary key string."""
        # Derive a 32-byte key using SHA-256, then base64 encode for Fernet
        derived = hashlib.sha256(key.encode()).digest()
        fernet_key = base64.urlsafe_b64encode(derived)
        return Fernet(fernet_key)

    def _ensure_directory(self) -> None:
        """Create storage directory if it doesn't exist."""
        self._storage_dir.mkdir(parents=True, exist_ok=True)

    def _get_file_path(self, api_id: str) -> Path:
        """Get file path for an API's data."""
        # Sanitize api_id for filesystem
        safe_id = hashlib.sha256(api_id.encode()).hexdigest()[:32]
        return self._storage_dir / f"{safe_id}.json.enc"

    def _read_data(self, api_id: str) -> Dict[str, Any]:
        """Read and decrypt data for an API."""
        file_path = self._get_file_path(api_id)
        if not file_path.exists():
            return {}

        try:
            encrypted = file_path.read_bytes()
            decrypted = self._fernet.decrypt(encrypted)
            return json.loads(decrypted.decode())
        except (InvalidToken, json.JSONDecodeError) as e:
            logger.error("Error reading storage file for %s: %s", api_id, e)
            return {}

    def _write_data(self, api_id: str, data: Dict[str, Any]) -> None:
        """Encrypt and write data for an API."""
        file_path = self._get_file_path(api_id)
        try:
            json_bytes = json.dumps(data).encode()
            encrypted = self._fernet.encrypt(json_bytes)
            file_path.write_bytes(encrypted)
        except Exception as e:
            logger.error("Error writing storage file for %s: %s", api_id, e)
            raise

    def save_credentials(self, api_id: str, credentials: StoredCredentials) -> None:
        data = self._read_data(api_id)
        data["credentials"] = credentials.to_dict()
        self._write_data(api_id, data)

    def load_credentials(self, api_id: str) -> Optional[StoredCredentials]:
        data = self._read_data(api_id)
        cred_data = data.get("credentials")
        if cred_data:
            return StoredCredentials.from_dict(cred_data)
        return None

    def save_token(self, api_id: str, token: StoredToken) -> None:
        data = self._read_data(api_id)
        data["token"] = token.to_dict()
        self._write_data(api_id, data)

    def load_token(self, api_id: str) -> Optional[StoredToken]:
        data = self._read_data(api_id)
        token_data = data.get("token")
        if token_data:
            return StoredToken.from_dict(token_data)
        return None

    def delete_api(self, api_id: str) -> None:
        file_path = self._get_file_path(api_id)
        if file_path.exists():
            file_path.unlink()

    def list_apis(self) -> list[str]:
        """List APIs by returning file names (hashed IDs).

        Note: This returns hashed IDs, not original API IDs,
        since we can't reverse the hash.
        """
        if not self._storage_dir.exists():
            return []
        return [f.stem.replace(".json", "") for f in self._storage_dir.glob("*.json.enc")]


class HybridStorage(StorageBackend):
    """Hybrid storage with per-API preference.

    Allows users to choose between session and file storage
    for each API independently. Preferences are stored in
    the session storage.
    """

    def __init__(self, session_storage: SessionStorage, file_storage: FileStorage):
        """Initialize hybrid storage.

        Args:
            session_storage: Session-based storage backend
            file_storage: File-based storage backend
        """
        self._session = session_storage
        self._file = file_storage

    def _get_preference(self, api_id: str) -> str:
        """Get storage preference for an API.

        Returns:
            'session' or 'file'
        """
        self._session._ensure_storage()
        prefs = self._session._session.get("_storage_preferences", {})
        return prefs.get(api_id, "session")

    def set_preference(self, api_id: str, use_file_storage: bool) -> None:
        """Set storage preference for an API.

        Args:
            api_id: Unique identifier for the API
            use_file_storage: True for file storage, False for session
        """
        self._session._ensure_storage()
        if "_storage_preferences" not in self._session._session:
            self._session._session["_storage_preferences"] = {}
        self._session._session["_storage_preferences"][api_id] = (
            "file" if use_file_storage else "session"
        )

    def _get_backend(self, api_id: str) -> StorageBackend:
        """Get the appropriate backend for an API."""
        if self._get_preference(api_id) == "file":
            return self._file
        return self._session

    def save_credentials(self, api_id: str, credentials: StoredCredentials) -> None:
        self._get_backend(api_id).save_credentials(api_id, credentials)

    def load_credentials(self, api_id: str) -> Optional[StoredCredentials]:
        return self._get_backend(api_id).load_credentials(api_id)

    def save_token(self, api_id: str, token: StoredToken) -> None:
        self._get_backend(api_id).save_token(api_id, token)

    def load_token(self, api_id: str) -> Optional[StoredToken]:
        return self._get_backend(api_id).load_token(api_id)

    def delete_api(self, api_id: str) -> None:
        # Delete from both backends to be safe
        self._session.delete_api(api_id)
        self._file.delete_api(api_id)
        # Remove preference
        if "_storage_preferences" in self._session._session:
            self._session._session["_storage_preferences"].pop(api_id, None)

    def list_apis(self) -> list[str]:
        # Combine APIs from both backends
        session_apis = set(self._session.list_apis())
        file_apis = set(self._file.list_apis())
        return list(session_apis | file_apis)


def generate_api_id(base_url: str, openapi_url: str) -> str:
    """Generate a unique API identifier from URLs.

    Args:
        base_url: Base URL of the API
        openapi_url: URL of the OpenAPI specification

    Returns:
        Unique identifier string (SHA-256 hash, truncated)
    """
    combined = f"{base_url}|{openapi_url}"
    return hashlib.sha256(combined.encode()).hexdigest()[:16]
