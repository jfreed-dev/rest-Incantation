"""Tests for auth.storage module."""

import tempfile
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from auth.storage import (
    FileStorage,
    HybridStorage,
    SessionStorage,
    StoredCredentials,
    StoredToken,
    generate_api_id,
)


class TestStoredToken:
    """Tests for StoredToken dataclass."""

    def test_create_token(self):
        token = StoredToken(
            access_token="test_token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="refresh_token",
            scope="read write",
            obtained_at=datetime.now().isoformat(),
        )

        assert token.access_token == "test_token"
        assert token.token_type == "Bearer"
        assert token.expires_in == 3600

    def test_token_defaults(self):
        token = StoredToken(access_token="test")

        assert token.token_type == "Bearer"
        assert token.expires_in is None
        assert token.refresh_token is None

    def test_is_expired_no_expiry(self):
        """Token without expiry info is never considered expired."""
        token = StoredToken(access_token="test")
        assert not token.is_expired()

    def test_is_expired_fresh_token(self):
        """Fresh token should not be expired."""
        token = StoredToken(
            access_token="test",
            expires_in=3600,
            obtained_at=datetime.now().isoformat(),
        )
        assert not token.is_expired()

    def test_is_expired_old_token(self):
        """Old token should be expired."""
        old_time = datetime.now() - timedelta(hours=2)
        token = StoredToken(
            access_token="test",
            expires_in=3600,
            obtained_at=old_time.isoformat(),
        )
        assert token.is_expired()

    def test_is_expired_with_buffer(self):
        """Token about to expire should be considered expired with buffer."""
        almost_expired = datetime.now() - timedelta(seconds=3550)
        token = StoredToken(
            access_token="test",
            expires_in=3600,
            obtained_at=almost_expired.isoformat(),
        )
        # Should be expired with 60 second buffer (default)
        assert token.is_expired(buffer_seconds=60)
        # Should not be expired with 0 buffer
        assert not token.is_expired(buffer_seconds=0)

    def test_to_dict(self):
        token = StoredToken(
            access_token="test",
            token_type="Bearer",
            expires_in=3600,
        )
        data = token.to_dict()

        assert data["access_token"] == "test"
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 3600
        # None values should not be included
        assert "refresh_token" not in data

    def test_from_dict(self):
        data = {
            "access_token": "test",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "refresh",
        }
        token = StoredToken.from_dict(data)

        assert token.access_token == "test"
        assert token.refresh_token == "refresh"


class TestStoredCredentials:
    """Tests for StoredCredentials dataclass."""

    def test_create_credentials(self):
        creds = StoredCredentials(
            scheme_name="ApiKeyAuth",
            scheme_type="apiKey",
            values={"api_key": "secret123"},
            custom_headers={"X-Custom": "value"},
        )

        assert creds.scheme_name == "ApiKeyAuth"
        assert creds.values["api_key"] == "secret123"
        assert creds.custom_headers["X-Custom"] == "value"

    def test_credentials_default_headers(self):
        creds = StoredCredentials(
            scheme_name="test",
            scheme_type="http",
            values={},
        )
        assert creds.custom_headers == {}

    def test_to_dict(self):
        creds = StoredCredentials(
            scheme_name="test",
            scheme_type="apiKey",
            values={"key": "value"},
        )
        data = creds.to_dict()

        assert data["scheme_name"] == "test"
        assert data["values"]["key"] == "value"

    def test_from_dict(self):
        data = {
            "scheme_name": "test",
            "scheme_type": "oauth2",
            "values": {"client_id": "abc"},
            "custom_headers": {"X-Header": "val"},
        }
        creds = StoredCredentials.from_dict(data)

        assert creds.scheme_name == "test"
        assert creds.values["client_id"] == "abc"


class TestSessionStorage:
    """Tests for SessionStorage backend."""

    @pytest.fixture
    def session_dict(self):
        """Mock Flask session as a plain dict."""
        return {}

    @pytest.fixture
    def storage(self, session_dict):
        return SessionStorage(session_dict)

    def test_save_and_load_credentials(self, storage):
        creds = StoredCredentials(
            scheme_name="ApiKey",
            scheme_type="apiKey",
            values={"key": "secret"},
        )
        storage.save_credentials("api1", creds)

        loaded = storage.load_credentials("api1")
        assert loaded is not None
        assert loaded.scheme_name == "ApiKey"
        assert loaded.values["key"] == "secret"

    def test_load_missing_credentials(self, storage):
        loaded = storage.load_credentials("nonexistent")
        assert loaded is None

    def test_save_and_load_token(self, storage):
        token = StoredToken(access_token="token123", expires_in=3600)
        storage.save_token("api1", token)

        loaded = storage.load_token("api1")
        assert loaded is not None
        assert loaded.access_token == "token123"

    def test_load_missing_token(self, storage):
        loaded = storage.load_token("nonexistent")
        assert loaded is None

    def test_delete_api(self, storage):
        creds = StoredCredentials("test", "apiKey", {})
        token = StoredToken("token")

        storage.save_credentials("api1", creds)
        storage.save_token("api1", token)
        storage.delete_api("api1")

        assert storage.load_credentials("api1") is None
        assert storage.load_token("api1") is None

    def test_list_apis(self, storage):
        storage.save_credentials("api1", StoredCredentials("test", "apiKey", {}))
        storage.save_token("api2", StoredToken("token"))

        apis = storage.list_apis()
        assert set(apis) == {"api1", "api2"}

    def test_list_apis_empty(self, storage):
        apis = storage.list_apis()
        assert apis == []

    def test_multiple_apis(self, storage):
        storage.save_credentials("api1", StoredCredentials("test1", "apiKey", {"k": "1"}))
        storage.save_credentials("api2", StoredCredentials("test2", "oauth2", {"k": "2"}))

        creds1 = storage.load_credentials("api1")
        creds2 = storage.load_credentials("api2")

        assert creds1.values["k"] == "1"
        assert creds2.values["k"] == "2"


class TestFileStorage:
    """Tests for FileStorage backend."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def storage(self, temp_dir):
        return FileStorage(temp_dir, "test-encryption-key")

    def test_save_and_load_credentials(self, storage):
        creds = StoredCredentials(
            scheme_name="ApiKey",
            scheme_type="apiKey",
            values={"key": "secret"},
        )
        storage.save_credentials("api1", creds)

        loaded = storage.load_credentials("api1")
        assert loaded is not None
        assert loaded.scheme_name == "ApiKey"
        assert loaded.values["key"] == "secret"

    def test_load_missing_credentials(self, storage):
        loaded = storage.load_credentials("nonexistent")
        assert loaded is None

    def test_save_and_load_token(self, storage):
        token = StoredToken(access_token="token123", expires_in=3600)
        storage.save_token("api1", token)

        loaded = storage.load_token("api1")
        assert loaded is not None
        assert loaded.access_token == "token123"

    def test_load_missing_token(self, storage):
        loaded = storage.load_token("nonexistent")
        assert loaded is None

    def test_delete_api(self, storage, temp_dir):
        creds = StoredCredentials("test", "apiKey", {})
        storage.save_credentials("api1", creds)

        # Verify file exists
        files = list(Path(temp_dir).glob("*.json.enc"))
        assert len(files) == 1

        storage.delete_api("api1")

        # Verify file is deleted
        files = list(Path(temp_dir).glob("*.json.enc"))
        assert len(files) == 0
        assert storage.load_credentials("api1") is None

    def test_encryption(self, temp_dir):
        """Verify data is actually encrypted on disk."""
        storage = FileStorage(temp_dir, "secret-key")
        creds = StoredCredentials("test", "apiKey", {"password": "super_secret"})
        storage.save_credentials("api1", creds)

        # Read raw file
        files = list(Path(temp_dir).glob("*.json.enc"))
        assert len(files) == 1
        raw_content = files[0].read_bytes()

        # Encrypted data should not contain plaintext
        assert b"super_secret" not in raw_content
        assert b"password" not in raw_content

    def test_different_encryption_keys(self, temp_dir):
        """Data encrypted with one key should not be readable with another."""
        storage1 = FileStorage(temp_dir, "key1")
        storage1.save_credentials("api1", StoredCredentials("test", "apiKey", {"k": "v"}))

        # Different key should not decrypt the data
        storage2 = FileStorage(temp_dir, "key2")
        loaded = storage2.load_credentials("api1")
        # Should return None or empty due to decryption failure
        assert loaded is None

    def test_directory_creation(self, temp_dir):
        """Storage should create nested directories."""
        nested_path = Path(temp_dir) / "nested" / "path"
        storage = FileStorage(str(nested_path), "key")

        assert nested_path.exists()

    def test_update_existing_data(self, storage):
        """Updating should preserve other fields."""
        storage.save_credentials("api1", StoredCredentials("test", "apiKey", {"k": "v"}))
        storage.save_token("api1", StoredToken("token1"))

        # Update credentials only
        storage.save_credentials("api1", StoredCredentials("test2", "oauth2", {"k": "v2"}))

        # Token should still be there
        token = storage.load_token("api1")
        assert token.access_token == "token1"

        # Credentials should be updated
        creds = storage.load_credentials("api1")
        assert creds.scheme_name == "test2"


class TestHybridStorage:
    """Tests for HybridStorage backend."""

    @pytest.fixture
    def session_dict(self):
        return {}

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def storage(self, session_dict, temp_dir):
        session = SessionStorage(session_dict)
        file = FileStorage(temp_dir, "key")
        return HybridStorage(session, file)

    def test_default_uses_session(self, storage, session_dict):
        """Default preference should be session storage."""
        creds = StoredCredentials("test", "apiKey", {"k": "v"})
        storage.save_credentials("api1", creds)

        # Should be in session
        assert "_auth_credentials" in session_dict
        assert "api1" in session_dict["_auth_credentials"]

    def test_set_file_preference(self, storage, temp_dir):
        """Setting file preference should use file storage."""
        storage.set_preference("api1", use_file_storage=True)

        creds = StoredCredentials("test", "apiKey", {"k": "v"})
        storage.save_credentials("api1", creds)

        # Should be in file
        files = list(Path(temp_dir).glob("*.json.enc"))
        assert len(files) == 1

    def test_mixed_preferences(self, storage, session_dict, temp_dir):
        """Different APIs can have different preferences."""
        storage.set_preference("api1", use_file_storage=False)
        storage.set_preference("api2", use_file_storage=True)

        storage.save_credentials("api1", StoredCredentials("test1", "apiKey", {}))
        storage.save_credentials("api2", StoredCredentials("test2", "oauth2", {}))

        # api1 in session, api2 in file
        assert "api1" in session_dict["_auth_credentials"]
        assert "api2" not in session_dict.get("_auth_credentials", {})
        assert len(list(Path(temp_dir).glob("*.json.enc"))) == 1

    def test_load_respects_preference(self, storage):
        """Load should use correct backend based on preference."""
        storage.set_preference("api1", use_file_storage=True)
        storage.save_credentials("api1", StoredCredentials("test", "apiKey", {"k": "v"}))

        loaded = storage.load_credentials("api1")
        assert loaded is not None
        assert loaded.values["k"] == "v"

    def test_delete_api_removes_from_both(self, storage, session_dict, temp_dir):
        """Delete should clean up both backends."""
        # Save to both backends manually
        storage.set_preference("api1", use_file_storage=False)
        storage.save_credentials("api1", StoredCredentials("test", "apiKey", {}))

        storage.set_preference("api1", use_file_storage=True)
        storage.save_credentials("api1", StoredCredentials("test", "apiKey", {}))

        storage.delete_api("api1")

        # Both should be empty
        assert storage.load_credentials("api1") is None
        assert len(list(Path(temp_dir).glob("*.json.enc"))) == 0

    def test_list_apis_combines_both(self, storage):
        """list_apis should return APIs from both backends."""
        storage.set_preference("api1", use_file_storage=False)
        storage.set_preference("api2", use_file_storage=True)

        storage.save_credentials("api1", StoredCredentials("test1", "apiKey", {}))
        storage.save_credentials("api2", StoredCredentials("test2", "oauth2", {}))

        apis = storage.list_apis()
        assert "api1" in apis


class TestGenerateApiId:
    """Tests for generate_api_id function."""

    def test_generates_consistent_id(self):
        id1 = generate_api_id("https://api.example.com", "/openapi.json")
        id2 = generate_api_id("https://api.example.com", "/openapi.json")
        assert id1 == id2

    def test_different_urls_different_ids(self):
        id1 = generate_api_id("https://api1.example.com", "/openapi.json")
        id2 = generate_api_id("https://api2.example.com", "/openapi.json")
        assert id1 != id2

    def test_id_length(self):
        api_id = generate_api_id("https://api.example.com", "/openapi.json")
        assert len(api_id) == 16

    def test_id_is_hex(self):
        api_id = generate_api_id("https://api.example.com", "/openapi.json")
        # Should be valid hexadecimal
        int(api_id, 16)
