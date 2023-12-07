def find_authentication_method(api_documentation):
    """
    Find the authentication method used by the API from its OpenAPI documentation.
    """
    try:
        security_schemes = api_documentation.get('components', {}).get('securitySchemes', {})
        if not security_schemes:
            return "No authentication method found in documentation."

        auth_methods = []
        for name, details in security_schemes.items():
            auth_type = details.get('type')
            auth_methods.append((name, auth_type))

        return auth_methods
    except Exception as e:
        print(f"Error processing API documentation: {e}")
        return []

# Example usage
# Assuming api_documentation is a dictionary containing the parsed OpenAPI documentation
authentication_methods = find_authentication_method(api_documentation)
print("Authentication Methods:", authentication_methods)