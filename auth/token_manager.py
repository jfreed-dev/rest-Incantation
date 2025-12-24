"""Token management with per-API automatic renewal.

Provides centralized management of OAuth 2.0 tokens with:
- Per-API token storage and retrieval
- Automatic token renewal via APScheduler
- Configurable renewal intervals
- Exponential backoff on failure
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from apscheduler.schedulers.background import BackgroundScheduler

from auth.oauth2_flows import (
    ClientCredentialsFlow,
    OAuth2Error,
    PasswordFlow,
    RefreshTokenFlow,
    TokenResponse,
)
from auth.storage import StorageBackend, StoredToken

logger = logging.getLogger(__name__)

# Maximum consecutive failures before disabling renewal
MAX_FAILURES = 5

# Base backoff interval in seconds
BASE_BACKOFF_SECONDS = 60


@dataclass
class TokenConfig:
    """Configuration for token acquisition and renewal.

    Attributes:
        oauth2_flow: Flow type ("client_credentials", "authorization_code", etc.)
        token_url: OAuth 2.0 token endpoint URL
        client_id: Client identifier
        client_secret: Client secret (optional for PKCE flows)
        scopes: List of requested scopes
        refresh_token: Refresh token for renewal (if available)
        username: Username for password flow
        password: Password for password flow
        renewal_interval_minutes: How often to renew (0 = disabled)
        buffer_seconds: Renew this many seconds before expiry
    """

    oauth2_flow: str
    token_url: str
    client_id: str
    client_secret: Optional[str] = None
    scopes: List[str] = field(default_factory=list)
    refresh_token: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    renewal_interval_minutes: int = 0  # 0 = auto based on expires_in
    buffer_seconds: int = 60

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "oauth2_flow": self.oauth2_flow,
            "token_url": self.token_url,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scopes": self.scopes,
            "refresh_token": self.refresh_token,
            "username": self.username,
            "password": self.password,
            "renewal_interval_minutes": self.renewal_interval_minutes,
            "buffer_seconds": self.buffer_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TokenConfig":
        """Create from dictionary."""
        return cls(
            oauth2_flow=data.get("oauth2_flow", ""),
            token_url=data.get("token_url", ""),
            client_id=data.get("client_id", ""),
            client_secret=data.get("client_secret"),
            scopes=data.get("scopes", []),
            refresh_token=data.get("refresh_token"),
            username=data.get("username"),
            password=data.get("password"),
            renewal_interval_minutes=data.get("renewal_interval_minutes", 0),
            buffer_seconds=data.get("buffer_seconds", 60),
        )


class TokenManager:
    """Manages tokens for multiple APIs with independent renewal schedules.

    Each API is identified by a unique api_id. The manager handles:
    - Storing and retrieving tokens
    - Scheduling automatic renewal
    - Handling renewal failures with exponential backoff
    """

    def __init__(
        self,
        storage: StorageBackend,
        scheduler: Optional[BackgroundScheduler] = None,
    ):
        """Initialize token manager.

        Args:
            storage: Storage backend for tokens and configs
            scheduler: APScheduler instance (created if not provided)
        """
        self._storage = storage
        self._scheduler = scheduler or BackgroundScheduler()
        self._configs: Dict[str, TokenConfig] = {}
        self._failure_counts: Dict[str, int] = {}
        self._renewal_callbacks: Dict[str, Callable[[str, TokenResponse], None]] = {}

        # Start scheduler if not already running
        if not self._scheduler.running:
            self._scheduler.start()

    def shutdown(self) -> None:
        """Shutdown the scheduler gracefully."""
        if self._scheduler.running:
            self._scheduler.shutdown(wait=False)

    def register_api(
        self,
        api_id: str,
        config: TokenConfig,
        initial_token: Optional[TokenResponse] = None,
    ) -> None:
        """Register an API for token management.

        Args:
            api_id: Unique identifier for the API
            config: Token configuration
            initial_token: Optional initial token to store
        """
        self._configs[api_id] = config
        self._failure_counts[api_id] = 0

        # Store initial token if provided
        if initial_token:
            self._store_token(api_id, initial_token)

            # Update config with refresh token if available
            if initial_token.refresh_token:
                config.refresh_token = initial_token.refresh_token
                self._configs[api_id] = config

        # Schedule renewal if configured
        if config.renewal_interval_minutes > 0:
            self.schedule_renewal(api_id, config.renewal_interval_minutes)
        elif initial_token and initial_token.expires_in:
            # Auto-schedule based on token expiry
            renewal_seconds = max(
                60, initial_token.expires_in - config.buffer_seconds
            )
            self.schedule_renewal(api_id, renewal_seconds / 60)

    def unregister_api(self, api_id: str) -> None:
        """Unregister an API and cancel its renewal.

        Args:
            api_id: API identifier to unregister
        """
        self.cancel_renewal(api_id)
        self._configs.pop(api_id, None)
        self._failure_counts.pop(api_id, None)
        self._storage.delete_api(api_id)

    def get_config(self, api_id: str) -> Optional[TokenConfig]:
        """Get token configuration for an API.

        Args:
            api_id: API identifier

        Returns:
            TokenConfig or None if not registered
        """
        return self._configs.get(api_id)

    def get_token(self, api_id: str, auto_renew: bool = True) -> Optional[str]:
        """Get current valid token for an API.

        Args:
            api_id: API identifier
            auto_renew: If True, trigger renewal if token is expired

        Returns:
            Access token string or None if unavailable
        """
        stored = self._storage.load_token(api_id)
        if not stored:
            if auto_renew and api_id in self._configs:
                try:
                    result = self.renew_now(api_id)
                    return result.access_token if result else None
                except Exception as e:
                    logger.error("Failed to renew token for %s: %s", api_id, e)
                    return None
            return None

        # Convert to TokenResponse to check expiry
        token = StoredToken.from_dict(stored.to_dict())
        if token.is_expired():
            if auto_renew and api_id in self._configs:
                try:
                    result = self.renew_now(api_id)
                    return result.access_token if result else None
                except Exception as e:
                    logger.error("Failed to renew expired token for %s: %s", api_id, e)
                    return None
            return None

        return stored.access_token

    def get_full_token(self, api_id: str) -> Optional[StoredToken]:
        """Get full token information for an API.

        Args:
            api_id: API identifier

        Returns:
            StoredToken or None if unavailable
        """
        return self._storage.load_token(api_id)

    def schedule_renewal(self, api_id: str, interval_minutes: float) -> None:
        """Schedule automatic token renewal for an API.

        Args:
            api_id: API identifier
            interval_minutes: Renewal interval in minutes
        """
        job_id = f"token_renewal_{api_id}"

        # Remove existing job if present
        try:
            self._scheduler.remove_job(job_id)
        except Exception:  # nosec B110 - job removal is best-effort
            pass

        # Add new job
        self._scheduler.add_job(
            func=self._renewal_job,
            trigger="interval",
            minutes=interval_minutes,
            id=job_id,
            args=[api_id],
            replace_existing=True,
            misfire_grace_time=60,
        )

        logger.info(
            "Scheduled token renewal for %s every %.1f minutes",
            api_id,
            interval_minutes,
        )

    def cancel_renewal(self, api_id: str) -> None:
        """Cancel automatic renewal for an API.

        Args:
            api_id: API identifier
        """
        job_id = f"token_renewal_{api_id}"
        try:
            self._scheduler.remove_job(job_id)
            logger.info("Cancelled token renewal for %s", api_id)
        except Exception:  # nosec B110 - job removal is best-effort
            pass

    def renew_now(self, api_id: str) -> Optional[TokenResponse]:
        """Force immediate token renewal.

        Args:
            api_id: API identifier

        Returns:
            New TokenResponse or None if renewal fails

        Raises:
            OAuth2Error: If token endpoint returns an error
            ValueError: If API is not registered
        """
        config = self._configs.get(api_id)
        if not config:
            raise ValueError(f"API {api_id} is not registered")

        # Try to get existing token for refresh token
        existing = self._storage.load_token(api_id)

        token = self._authenticate(config, existing)
        self._store_token(api_id, token)

        # Reset failure count on success
        self._failure_counts[api_id] = 0

        # Update refresh token if new one provided
        if token.refresh_token and token.refresh_token != config.refresh_token:
            config.refresh_token = token.refresh_token
            self._configs[api_id] = config

        # Trigger callback if registered
        callback = self._renewal_callbacks.get(api_id)
        if callback:
            try:
                callback(api_id, token)
            except Exception as e:
                logger.error("Renewal callback failed for %s: %s", api_id, e)

        return token

    def set_renewal_callback(
        self,
        api_id: str,
        callback: Callable[[str, TokenResponse], None],
    ) -> None:
        """Set a callback to be called after successful renewal.

        Args:
            api_id: API identifier
            callback: Function taking (api_id, token) as arguments
        """
        self._renewal_callbacks[api_id] = callback

    def get_failure_count(self, api_id: str) -> int:
        """Get the number of consecutive renewal failures.

        Args:
            api_id: API identifier

        Returns:
            Number of failures (0 if none)
        """
        return self._failure_counts.get(api_id, 0)

    def is_renewal_active(self, api_id: str) -> bool:
        """Check if automatic renewal is scheduled for an API.

        Args:
            api_id: API identifier

        Returns:
            True if renewal job exists
        """
        job_id = f"token_renewal_{api_id}"
        return self._scheduler.get_job(job_id) is not None

    def _renewal_job(self, api_id: str) -> None:
        """Background job that renews a token.

        Args:
            api_id: API identifier
        """
        try:
            self.renew_now(api_id)
            logger.info("Successfully renewed token for %s", api_id)
        except Exception as e:
            self._handle_failure(api_id, e)

    def _handle_failure(self, api_id: str, error: Exception) -> None:
        """Handle token renewal failure with exponential backoff.

        Args:
            api_id: API identifier
            error: The exception that occurred
        """
        self._failure_counts[api_id] = self._failure_counts.get(api_id, 0) + 1
        count = self._failure_counts[api_id]

        if count >= MAX_FAILURES:
            self.cancel_renewal(api_id)
            logger.error(
                "Token renewal disabled for %s after %d failures: %s",
                api_id,
                count,
                error,
            )
        else:
            # Exponential backoff: 1, 2, 4, 8, 16 minutes
            backoff_minutes = (2 ** (count - 1)) * (BASE_BACKOFF_SECONDS / 60)
            self.schedule_renewal(api_id, backoff_minutes)
            logger.warning(
                "Token renewal failed for %s (attempt %d), retry in %.1f min: %s",
                api_id,
                count,
                backoff_minutes,
                error,
            )

    def _authenticate(
        self,
        config: TokenConfig,
        existing_token: Optional[StoredToken] = None,
    ) -> TokenResponse:
        """Authenticate using the configured flow.

        Args:
            config: Token configuration
            existing_token: Existing token (for refresh token)

        Returns:
            TokenResponse with new token
        """
        # Try refresh token first if available
        refresh_token = config.refresh_token
        if existing_token and existing_token.refresh_token:
            refresh_token = existing_token.refresh_token

        if refresh_token:
            try:
                flow = RefreshTokenFlow()
                return flow.refresh(
                    token_url=config.token_url,
                    refresh_token=refresh_token,
                    client_id=config.client_id,
                    client_secret=config.client_secret,
                    scopes=config.scopes or None,
                )
            except OAuth2Error as e:
                if e.error not in ("invalid_grant", "invalid_token"):
                    raise
                # Refresh token expired/invalid, fall through to re-auth
                logger.info("Refresh token invalid for %s, re-authenticating", config.client_id)

        # Authenticate based on flow type
        flow_type = config.oauth2_flow.lower().replace("-", "_")

        if flow_type in ("client_credentials", "clientcredentials"):
            cc_flow = ClientCredentialsFlow()
            return cc_flow.authenticate(
                token_url=config.token_url,
                client_id=config.client_id,
                client_secret=config.client_secret or "",
                scopes=config.scopes or None,
            )
        elif flow_type == "password":
            if not config.username or not config.password:
                raise ValueError("Password flow requires username and password")
            pw_flow = PasswordFlow()
            return pw_flow.authenticate(
                token_url=config.token_url,
                username=config.username,
                password=config.password,
                client_id=config.client_id,
                client_secret=config.client_secret,
                scopes=config.scopes or None,
            )
        else:
            raise ValueError(
                f"Flow type {config.oauth2_flow} requires user interaction "
                "and cannot be renewed automatically"
            )

    def _store_token(self, api_id: str, token: TokenResponse) -> None:
        """Store a token response.

        Args:
            api_id: API identifier
            token: Token to store
        """
        stored = StoredToken(
            access_token=token.access_token,
            token_type=token.token_type,
            expires_in=token.expires_in,
            refresh_token=token.refresh_token,
            scope=token.scope,
            obtained_at=token.obtained_at.isoformat(),
        )
        self._storage.save_token(api_id, stored)
