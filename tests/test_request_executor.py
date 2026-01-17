"""Tests for request_executor module."""

import pytest
from request_executor import VariableResolver, RequestExecutor, find_request_in_collection


class TestVariableResolver:
    """Test variable resolution."""

    def test_resolve_single_variable(self):
        """Should resolve single variable."""
        resolver = VariableResolver([{"key": "base_url", "value": "https://api.example.com"}])
        result = resolver.resolve("{{base_url}}/users")
        assert result == "https://api.example.com/users"

    def test_resolve_multiple_variables(self):
        """Should resolve multiple variables in same string."""
        resolver = VariableResolver([
            {"key": "base_url", "value": "https://api.example.com"},
            {"key": "version", "value": "v1"}
        ])
        result = resolver.resolve("{{base_url}}/{{version}}/users")
        assert result == "https://api.example.com/v1/users"

    def test_resolve_with_spaces(self):
        """Should resolve variables with spaces."""
        resolver = VariableResolver([{"key": "user_id", "value": "123"}])
        result = resolver.resolve("/users/{{ user_id }}/profile")
        assert result == "/users/123/profile"

    def test_resolve_undefined_variable(self):
        """Should leave undefined variables as-is."""
        resolver = VariableResolver([{"key": "base_url", "value": "https://api.example.com"}])
        result = resolver.resolve("{{base_url}}/{{undefined}}")
        assert result == "https://api.example.com/{{undefined}}"

    def test_resolve_empty_string(self):
        """Should handle empty string."""
        resolver = VariableResolver([])
        result = resolver.resolve("")
        assert result == ""

    def test_resolve_none(self):
        """Should handle None."""
        resolver = VariableResolver([])
        result = resolver.resolve(None)
        assert result is None


class TestFindRequestInCollection:
    """Test finding requests in collections."""

    def test_find_existing_request(self):
        """Should find request by name."""
        collection = {
            "requests": [
                {"name": "Get Users", "url": "/users"},
                {"name": "Get User", "url": "/users/1"}
            ]
        }
        result = find_request_in_collection(collection, "Get Users")
        assert result is not None
        assert result["url"] == "/users"

    def test_find_nonexistent_request(self):
        """Should return None for nonexistent request."""
        collection = {"requests": [{"name": "Get Users", "url": "/users"}]}
        result = find_request_in_collection(collection, "Not Found")
        assert result is None

    def test_find_in_empty_collection(self):
        """Should handle empty collection."""
        collection = {"requests": []}
        result = find_request_in_collection(collection, "Get Users")
        assert result is None

    def test_find_with_missing_requests_key(self):
        """Should handle missing requests key."""
        collection = {}
        result = find_request_in_collection(collection, "Get Users")
        assert result is None


class TestRequestExecutor:
    """Test request execution."""

    def test_resolve_url_variables(self):
        """Should resolve variables in URL."""
        executor = RequestExecutor([
            {"key": "base_url", "value": "https://jsonplaceholder.typicode.com"},
            {"key": "user_id", "value": "1"}
        ])
        
        # Mock successful request
        import responses
        
        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://jsonplaceholder.typicode.com/users/1",
                json={"id": 1, "name": "Test User"},
                status=200
            )
            
            result = executor.execute(
                method="GET",
                url="{{base_url}}/users/{{user_id}}",
            )
            
            assert result["success"] is True
            assert result["status_code"] == 200
            assert result["resolved_url"] == "https://jsonplaceholder.typicode.com/users/1"
            assert result["body"]["name"] == "Test User"
        
        run()

    def test_bearer_auth_resolution(self):
        """Should resolve bearer token."""
        executor = RequestExecutor([
            {"key": "base_url", "value": "https://api.example.com"},
            {"key": "api_token", "value": "secret_token_123"}
        ])
        
        import responses
        
        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://api.example.com/protected",
                json={"status": "authorized"},
                status=200
            )
            
            result = executor.execute(
                method="GET",
                url="{{base_url}}/protected",
                auth_type="bearer",
                auth_params={"token": "{{api_token}}"}
            )
            
            assert result["success"] is True
            # Check that Authorization header was added
            assert len(responses.calls) == 1
            assert "Authorization" in responses.calls[0].request.headers
            assert responses.calls[0].request.headers["Authorization"] == "Bearer secret_token_123"
        
        run()

    def test_timeout_error(self):
        """Should handle timeout errors."""
        executor = RequestExecutor([])
        
        import responses
        from requests.exceptions import Timeout
        
        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://api.example.com/slow",
                body=Timeout()
            )
            
            result = executor.execute(
                method="GET",
                url="https://api.example.com/slow"
            )
            
            assert result["success"] is False
            assert "timeout" in result["error"].lower()
            assert result["error_type"] == "timeout"
        
        run()

    def test_connection_error(self):
        """Should handle connection errors."""
        executor = RequestExecutor([])
        
        # Use invalid URL to trigger connection error
        result = executor.execute(
            method="GET",
            url="http://invalid-domain-that-does-not-exist-12345.com"
        )
        
        assert result["success"] is False
        assert result["error_type"] == "connection"

    def test_json_response_parsing(self):
        """Should parse JSON responses."""
        executor = RequestExecutor([])
        
        import responses
        
        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://api.example.com/data",
                json={"key": "value", "nested": {"data": 123}},
                status=200
            )
            
            result = executor.execute(
                method="GET",
                url="https://api.example.com/data"
            )
            
            assert result["success"] is True
            assert isinstance(result["body"], dict)
            assert result["body"]["key"] == "value"
            assert result["body"]["nested"]["data"] == 123
        
        run()

    def test_text_response_fallback(self):
        """Should fall back to text for non-JSON responses."""
        executor = RequestExecutor([])
        
        import responses
        
        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://api.example.com/text",
                body="Plain text response",
                status=200,
                content_type="text/plain"
            )
            
            result = executor.execute(
                method="GET",
                url="https://api.example.com/text"
            )
            
            assert result["success"] is True
            assert isinstance(result["body"], str)
            assert result["body"] == "Plain text response"
        
        run()

    def test_response_metrics(self):
        """Should include response metrics."""
        executor = RequestExecutor([])
        
        import responses
        
        @responses.activate
        def run():
            responses.add(
                responses.GET,
                "https://api.example.com/data",
                json={"test": "data"},
                status=200
            )
            
            result = executor.execute(
                method="GET",
                url="https://api.example.com/data"
            )
            
            assert result["success"] is True
            assert "time_ms" in result
            assert result["time_ms"] > 0
            assert "size_bytes" in result
            assert result["size_bytes"] > 0
            assert "headers" in result
            assert isinstance(result["headers"], dict)
        
        run()
