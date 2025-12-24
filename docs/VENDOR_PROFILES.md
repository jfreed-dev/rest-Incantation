# Vendor Profiles & Implementation Planning

This document provides detailed specifications for implementing vendor-specific API integrations in REST Incantation. It serves as a reference for development and preserves research context.

## Table of Contents

1. [Overview](#overview)
2. [Vendor Profiles](#vendor-profiles)
   - [Cisco Meraki](#cisco-meraki)
   - [Cisco Viptela/SD-WAN](#cisco-viptelasd-wan)
   - [Cisco Umbrella](#cisco-umbrella)
   - [Palo Alto Prisma SASE](#palo-alto-prisma-sase)
   - [Palo Alto Strata Cloud Manager](#palo-alto-strata-cloud-manager)
   - [Palo Alto Panorama](#palo-alto-panorama)
   - [Juniper Mist](#juniper-mist)
   - [Juniper Security Director](#juniper-security-director)
   - [Schneider Electric EcoStruxure IT](#schneider-electric-ecostruxure-it)
   - [AWS](#aws)
   - [Microsoft Azure](#microsoft-azure)
3. [Feature Implementation Plans](#feature-implementation-plans)
4. [Data Models](#data-models)
5. [API Workflow Patterns](#api-workflow-patterns)

---

## Overview

### Purpose

REST Incantation targets IT infrastructure APIs used by corporations, schools, and government organizations. These APIs manage:

- **Network Infrastructure**: SD-WAN, firewalls, switches, wireless
- **Security**: SASE, cloud security, threat intelligence
- **Data Center**: Power, cooling, environmental monitoring
- **Cloud Platforms**: AWS, Azure resource management

### Common Challenges

1. **Authentication Complexity**: Each vendor uses different auth methods (OAuth 2.0, API keys, JWT, session tokens, AWS SigV4)
2. **Rate Limiting**: Varies from 10/sec (Meraki) to 6,000/min (Cisco SD-WAN)
3. **Pagination**: Multiple patterns (offset/limit, cursor, Link headers, scrollId)
4. **API Dependencies**: Many calls require data from previous calls (org_id, device_id, etc.)
5. **Multi-Tenancy**: MSPs need to manage multiple customer organizations

---

## Vendor Profiles

### Cisco Meraki

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `cisco_meraki` |
| **Display Name** | Cisco Meraki |
| **Category** | Network Infrastructure |
| **Base URL** | `https://api.meraki.com/api/v1` |
| **Documentation** | https://developer.cisco.com/meraki/api-v1/ |

#### Authentication

```yaml
auth_type: api_key
auth_config:
  header_name: X-Cisco-Meraki-API-Key
  key_location: header
  description: "Generate API key in Meraki Dashboard > Organization > Settings > API access"
```

#### OpenAPI Specification

```yaml
openapi_sources:
  - type: github
    url: https://github.com/meraki/openapi
    branch: master
    file: openapi/spec3.json
  - type: url
    url: https://raw.githubusercontent.com/meraki/openapi/master/openapi/spec3.json
```

#### Rate Limiting

```yaml
rate_limits:
  - scope: organization
    limit: 10
    period: second
    burst: 10
    burst_period: first_second
  - scope: ip_address
    limit: 100
    period: second
  - scope: concurrent
    limit: 10
    description: "Maximum concurrent requests per IP"
retry_config:
  status_code: 429
  header: Retry-After
  default_wait: 1
  max_retries: 5
```

#### Pagination

```yaml
pagination:
  type: rfc5988_link_header
  params:
    per_page:
      param: perPage
      default: 1000
      max: 1000
    cursor_forward: startingAfter
    cursor_backward: endingBefore
  response:
    link_header: Link
    # Example: <https://api.meraki.com/api/v1/...?startingAfter=abc>; rel=next
```

#### Common API Patterns

```yaml
api_patterns:
  hierarchy:
    - organizations
    - networks
    - devices
  common_endpoints:
    list_organizations: GET /organizations
    list_networks: GET /organizations/{organizationId}/networks
    list_devices: GET /organizations/{organizationId}/devices
    get_device: GET /devices/{serial}
```

#### Required Headers

```yaml
required_headers:
  - name: X-Cisco-Meraki-API-Key
    source: auth
  - name: Content-Type
    value: application/json
    condition: request_has_body
```

---

### Cisco Viptela/SD-WAN

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `cisco_sdwan` |
| **Display Name** | Cisco SD-WAN (Catalyst SD-WAN Manager) |
| **Category** | Network Infrastructure |
| **Base URL** | `https://{vmanage_host}:{port}` (default port 8443) |
| **Documentation** | https://developer.cisco.com/docs/sdwan/ |

#### Authentication

```yaml
auth_type: session_jwt_xsrf
auth_config:
  # Step 1: Get session cookie and XSRF token
  login_endpoint: /j_security_check
  login_method: POST
  login_content_type: application/x-www-form-urlencoded
  login_params:
    j_username: "{{username}}"
    j_password: "{{password}}"

  # Step 2: Get JWT token (for cloud-hosted vManage)
  token_endpoint: /dataservice/client/token
  token_method: GET

  # Required headers for all subsequent requests
  session_headers:
    - name: X-XSRF-TOKEN
      source: cookie  # Extract from XSRF-TOKEN cookie
    - name: Cookie
      source: session  # JSESSIONID cookie
```

#### OpenAPI Specification

```yaml
openapi_sources:
  - type: builtin_swagger
    url: https://{vmanage_host}/apidocs
    description: "Built-in Swagger UI - requires authentication"
  - type: postman
    url: https://www.postman.com/ciscodevnet/cisco-devnet-s-public-workspace/collection/qsc3yy8/cisco-sd-wan
```

#### Rate Limiting

```yaml
rate_limits:
  - scope: global
    limit: 6000
    period: minute
retry_config:
  status_code: 429
  default_wait: 10
  max_retries: 3
```

#### Pagination

```yaml
pagination:
  types:
    config_db:
      # For configuration database queries
      params:
        offset: offset
        limit: limit
      max_limit: 3999
    stats_db:
      # For statistics database queries
      params:
        scroll_id: scrollId
        count: count
      description: "Use scrollId from previous response"
    device_query:
      # Device-specific queries
      description: "Pagination determined by device response"
```

#### Common API Patterns

```yaml
api_patterns:
  base_path: /dataservice
  common_endpoints:
    # Device management
    list_devices: GET /device
    device_status: GET /device/monitor
    device_counters: GET /device/counters

    # Templates
    list_templates: GET /template/device
    get_template: GET /template/device/object/{templateId}

    # Policies
    list_policies: GET /template/policy/vsmart

    # Alarms
    list_alarms: GET /alarms

    # Certificate management
    list_certificates: GET /certificate/vsmart/list
```

#### Session Management

```yaml
session_config:
  timeout: 1800  # 30 minutes default
  refresh_endpoint: /dataservice/client/token
  keepalive_interval: 300  # 5 minutes
```

---

### Cisco Umbrella

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `cisco_umbrella` |
| **Display Name** | Cisco Umbrella |
| **Category** | Cloud Security |
| **Base URL** | `https://api.umbrella.com` |
| **Documentation** | https://developer.cisco.com/docs/cloud-security/ |

#### Authentication

```yaml
auth_type: oauth2_client_credentials
auth_config:
  token_endpoint: https://api.umbrella.com/auth/v2/token
  grant_type: client_credentials
  token_expiry: 3600  # 1 hour
  credentials:
    client_id: "{{client_id}}"
    client_secret: "{{client_secret}}"
  scopes:
    - admin.users:read
    - admin.users:write
    - reports:read
    - policies:read
    - policies:write
```

#### OpenAPI Specification

```yaml
openapi_sources:
  - type: documentation_link
    description: "OpenAPI spec linked at bottom of each API use case page"
    base_url: https://developer.cisco.com/docs/cloud-security/
```

#### Common API Patterns

```yaml
api_patterns:
  api_versions:
    admin: /admin/v2
    reports: /reports/v2
    policies: /policies/v2
    deployments: /deployments/v2
  common_endpoints:
    list_users: GET /admin/v2/users
    list_roles: GET /admin/v2/roles
    destination_lists: GET /policies/v2/destinationlists
    activity_report: GET /reports/v2/activity
```

---

### Palo Alto Prisma SASE

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `paloalto_prisma_sase` |
| **Display Name** | Palo Alto Prisma SASE / Prisma Access |
| **Category** | SASE / Cloud Security |
| **Base URL** | `https://api.sase.paloaltonetworks.com` |
| **Documentation** | https://pan.dev/sase/docs/ |

#### Authentication

```yaml
auth_type: oauth2_client_credentials
auth_config:
  token_endpoint: https://auth.apps.paloaltonetworks.com/oauth2/access_token
  grant_type: client_credentials
  credentials:
    client_id: "{{client_id}}"
    client_secret: "{{client_secret}}"
  required_params:
    scope: "tsg_id:{{tsg_id}}"  # Tenant Service Group ID required
  token_response:
    access_token: access_token
    expires_in: expires_in
```

#### TSG ID Requirement

```yaml
tenant_config:
  tsg_id:
    description: "Tenant Service Group ID - found in Strata Cloud Manager"
    required: true
    format: "numeric string"
    location: "Common Services > Tenant Service Groups"
```

#### Common API Patterns

```yaml
api_patterns:
  config_model: candidate
  # Changes are staged in candidate config, then pushed
  workflow:
    1_make_changes: "POST/PUT/DELETE to config endpoints"
    2_push_config: "POST /sse/config/v1/config-versions/candidate:push"
  common_endpoints:
    # Remote Networks
    list_remote_networks: GET /sse/config/v1/remote-networks
    # Security Policies
    list_security_rules: GET /sse/config/v1/security-rules
    # Service Connections
    list_service_connections: GET /sse/config/v1/service-connections
```

---

### Palo Alto Strata Cloud Manager

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `paloalto_scm` |
| **Display Name** | Palo Alto Strata Cloud Manager |
| **Category** | Cloud Management |
| **Base URL** | `https://api.strata.paloaltonetworks.com` |
| **Documentation** | https://pan.dev/scm/docs/home/ |

#### Authentication

```yaml
auth_type: oauth2_client_credentials
auth_config:
  # Same auth framework as Prisma SASE
  token_endpoint: https://auth.apps.paloaltonetworks.com/oauth2/access_token
  grant_type: client_credentials
  credentials:
    client_id: "{{client_id}}"
    client_secret: "{{client_secret}}"
  required_params:
    scope: "tsg_id:{{tsg_id}}"
```

#### Notes

```yaml
notes:
  - "Shared authentication framework with Prisma SASE"
  - "Terraform provider available: PaloAltoNetworks/scm"
  - "Go SDK available on GitHub"
  - "As of June 2025, IoT Security requires SCM authentication"
```

---

### Palo Alto Panorama

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `paloalto_panorama` |
| **Display Name** | Palo Alto Panorama |
| **Category** | Network Security Management |
| **Base URL** | `https://{panorama_host}/api` |
| **Documentation** | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api |

#### Authentication

```yaml
auth_type: api_key
auth_config:
  # Generate API key via keygen request
  keygen_endpoint: /api/?type=keygen
  keygen_method: GET
  keygen_params:
    user: "{{username}}"
    password: "{{password}}"
  # Use key in subsequent requests
  key_location: header
  header_name: X-PAN-KEY
  # Alternative: query parameter
  # key_location: query
  # query_param: key
```

#### API Types

```yaml
api_types:
  xml_api:
    description: "Full functionality - configuration, operational commands, commits"
    content_type: application/xml
    endpoints:
      config: /api/?type=config
      op: /api/?type=op
      commit: /api/?type=commit
      export: /api/?type=export
      import: /api/?type=import
  rest_api:
    description: "Subset functionality - CRUD operations only, no commits"
    content_type: application/json
    base_path: /restapi/v10.1
    note: "Commits still require XML API"
```

#### OpenAPI Specification

```yaml
openapi_sources:
  - type: none
    description: "No OpenAPI spec - proprietary XML API and REST API documentation"
    workaround: "Parse documentation or use predefined endpoint catalog"
```

---

### Juniper Mist

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `juniper_mist` |
| **Display Name** | Juniper Mist |
| **Category** | Network Infrastructure (Wireless/Wired/SD-WAN) |
| **Base URL** | `https://api.mist.com/api/v1` |
| **Documentation** | https://www.juniper.net/documentation/us/en/software/mist/automation-integration/ |

#### Authentication

```yaml
auth_type: token
auth_config:
  header_name: Authorization
  header_format: "token {{api_token}}"
  token_types:
    organization:
      description: "Shared token for organization-wide access"
      persistence: permanent_until_revoked
      scope: organization
    user:
      description: "Personal token tied to user permissions"
      persistence: permanent_until_revoked
      scope: user_role_based
  # Basic auth deprecated September 2026
  deprecated:
    basic_auth:
      sunset_date: 2026-09-01
```

#### OpenAPI Specification

```yaml
openapi_sources:
  - type: github
    url: https://github.com/Mist-Automation-Programmability/mist_openapi
    note: "Documentation purposes only - not for code generation"
  - type: builtin
    url: https://api.mist.com/api/v1/docs/
```

#### Rate Limiting

```yaml
rate_limits:
  - scope: token
    limit: 5000
    period: hour
retry_config:
  status_code: 429
  default_wait: 60
  max_retries: 3
```

#### Common API Patterns

```yaml
api_patterns:
  note: "100% API architecture - everything in portal is API-accessible"
  hierarchy:
    - orgs
    - sites
    - devices (aps, switches, gateways)
  common_endpoints:
    # Organization
    whoami: GET /self
    list_orgs: GET /self/orgs
    get_org: GET /orgs/{org_id}

    # Sites
    list_sites: GET /orgs/{org_id}/sites
    get_site: GET /sites/{site_id}

    # Devices
    list_devices: GET /orgs/{org_id}/devices
    list_site_devices: GET /sites/{site_id}/devices
    get_device_stats: GET /sites/{site_id}/stats/devices

    # Clients
    list_clients: GET /sites/{site_id}/clients

    # Inventory
    list_inventory: GET /orgs/{org_id}/inventory
```

#### Postman Collections

```yaml
postman:
  workspace: https://www.postman.com/juniper-mist/workspace/mist-systems-s-public-workspace
  collections:
    - version: 2502.1.0
    - version: 2509.1.1
```

---

### Juniper Security Director

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `juniper_security_director` |
| **Display Name** | Juniper Security Director Cloud |
| **Category** | Network Security Management |
| **Base URL** | `https://apigw.{region}.jnpr-sd-cloud.juniper.net` |
| **Documentation** | https://www.juniper.net/documentation/us/en/software/sd-cloud/ |

#### Authentication

```yaml
auth_type: api_key_or_oauth2
auth_config:
  options:
    api_key:
      header_name: x-api-key
      description: "API key from Security Director Cloud portal"
    oauth2:
      header_name: x-oauth2-token
      supported_idps:
        - Okta
        - "Microsoft Entra ID (Azure AD)"
```

#### Notes

```yaml
notes:
  - "SASE portal for on-prem, cloud-based, and cloud-delivered security"
  - "Zero Touch Provisioning (ZTP) for SRX firewalls"
  - "JIMS integration for identity management"
```

---

### Schneider Electric EcoStruxure IT

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `schneider_ecostruxure_it` |
| **Display Name** | Schneider Electric EcoStruxure IT Expert |
| **Category** | Data Center Infrastructure Management |
| **Base URL** | `https://api.ecostruxureit.com` |
| **Documentation** | https://api.ecostruxureit.com/ (requires login) |

#### Authentication

```yaml
auth_type: api_key_or_password
auth_config:
  options:
    api_key:
      description: "API key from IT Expert portal"
    username_password:
      description: "IT Expert account credentials"
      mfa_required: true
  requirements:
    - "Valid IT Expert subscription"
    - "For partners: customer must enable 'Allow API access to device data'"
```

#### Rate Limiting

```yaml
rate_limits:
  - scope: fair_use
    description: "No explicit limits; Schneider reserves right to disconnect users causing performance issues"
```

#### Features

```yaml
features:
  - "Live measurement streaming"
  - "Replay of missed measurements"
  - "Device notes and service dates (April 2025)"
  - "Warranty expiration tracking"
```

---

### AWS

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `aws` |
| **Display Name** | Amazon Web Services |
| **Category** | Cloud Platform |
| **Base URL** | Service-specific (e.g., `https://ec2.{region}.amazonaws.com`) |
| **Documentation** | https://docs.aws.amazon.com/ |

#### Authentication

```yaml
auth_type: aws_sigv4
auth_config:
  signature_version: 4
  credentials:
    access_key_id: "{{aws_access_key_id}}"
    secret_access_key: "{{aws_secret_access_key}}"
    session_token: "{{aws_session_token}}"  # Optional, for temporary credentials
  signing:
    algorithm: AWS4-HMAC-SHA256
    signed_headers:
      - host
      - x-amz-date
      - x-amz-content-sha256
    request_validity: 300  # 5 minutes
  # Presigned URLs
  presigned_urls:
    max_validity: 604800  # 7 days
```

#### Implementation Notes

```yaml
implementation:
  sigv4_signing:
    steps:
      1: "Create canonical request"
      2: "Create string to sign"
      3: "Calculate signature"
      4: "Add signature to request"
    libraries:
      python: boto3, botocore
      javascript: aws-sdk
      note: "SDKs handle signing automatically"
  temporary_credentials:
    service: AWS STS
    methods:
      - AssumeRole
      - GetSessionToken
      - AssumeRoleWithSAML
      - AssumeRoleWithWebIdentity
```

#### Pagination

```yaml
pagination:
  patterns:
    next_token:
      request_param: NextToken
      response_field: NextToken
      services: [EC2, S3 ListObjectsV2, Lambda]
    marker:
      request_param: Marker
      response_field: Marker
      services: [S3 ListObjects, IAM]
    last_evaluated_key:
      request_param: ExclusiveStartKey
      response_field: LastEvaluatedKey
      services: [DynamoDB]
```

---

### Microsoft Azure

#### Basic Information

| Property | Value |
|----------|-------|
| **Vendor ID** | `microsoft_azure` |
| **Display Name** | Microsoft Azure |
| **Category** | Cloud Platform |
| **Base URL** | `https://management.azure.com` (ARM), service-specific for data plane |
| **Documentation** | https://learn.microsoft.com/en-us/rest/api/azure/ |

#### Authentication

```yaml
auth_type: oauth2_entra_id
auth_config:
  # Microsoft Entra ID (formerly Azure AD)
  authorize_endpoint: https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize
  token_endpoint: https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
  supported_flows:
    - authorization_code
    - client_credentials
  scopes:
    management: https://management.azure.com/.default
    graph: https://graph.microsoft.com/.default
  credentials:
    client_id: "{{client_id}}"
    client_secret: "{{client_secret}}"
    tenant_id: "{{tenant_id}}"
```

#### OpenAPI Specification

```yaml
openapi_sources:
  - type: github
    url: https://github.com/Azure/azure-rest-api-specs
    structure:
      - specification/{service}/resource-manager  # ARM APIs
      - specification/{service}/data-plane        # Data plane APIs
  - type: inventory
    url: https://azure.github.io/azure-sdk/releases/latest/specs.html
    note: "Last updated December 2025"
```

#### Pagination

```yaml
pagination:
  type: odata_style
  params:
    skip: $skip
    top: $top
    max_page_size: maxpagesize
  response:
    next_link: nextLink
  extension: x-ms-pageable
```

---

## Feature Implementation Plans

### 1. Vendor Profile System

#### Data Model

```python
@dataclass
class VendorProfile:
    id: str                          # e.g., "cisco_meraki"
    name: str                        # Display name
    category: str                    # Network, Security, Cloud, DCIM
    base_url: str                    # Default base URL (may have placeholders)
    auth_config: AuthConfig          # Authentication configuration
    rate_limits: List[RateLimit]     # Rate limiting rules
    pagination: PaginationConfig     # Pagination handling
    openapi_sources: List[OpenAPISource]  # Where to fetch specs
    required_headers: List[Header]   # Headers needed for all requests
    common_endpoints: Dict[str, str] # Predefined useful endpoints
```

#### Storage

```yaml
storage:
  location: config/vendor_profiles/
  format: yaml
  files:
    - cisco_meraki.yaml
    - cisco_sdwan.yaml
    - paloalto_prisma.yaml
    # etc.
  user_overrides: config/vendor_profiles/custom/
```

#### UI Components

```yaml
ui:
  vendor_selector:
    - Dropdown with vendor categories
    - Search/filter by name
    - "Custom" option for manual configuration
  profile_editor:
    - View/edit profile settings
    - Test connection button
    - Override specific settings per-use
```

### 2. API Workflow Builder

#### Workflow Definition

```yaml
workflow:
  name: "Meraki Device Inventory"
  vendor: cisco_meraki
  description: "Get all devices across all organizations and networks"

  steps:
    - id: get_orgs
      name: "List Organizations"
      method: GET
      endpoint: /organizations
      extract:
        - name: org_ids
          path: $[*].id
          type: array

    - id: get_networks
      name: "List Networks per Org"
      method: GET
      endpoint: /organizations/{{org_id}}/networks
      loop:
        over: org_ids
        as: org_id
      extract:
        - name: network_ids
          path: $[*].id
          type: array
          append: true  # Accumulate across loop iterations

    - id: get_devices
      name: "List Devices per Network"
      method: GET
      endpoint: /networks/{{network_id}}/devices
      loop:
        over: network_ids
        as: network_id
      output: devices
```

#### Variable System

```yaml
variables:
  types:
    - input: User-provided at workflow start
    - extracted: Pulled from API responses using JSONPath
    - computed: Calculated from other variables
    - environment: From environment/secrets

  extraction:
    jsonpath: true
    jmespath: true
    regex: true

  templates:
    syntax: "{{variable_name}}"
    filters:
      - "{{org_id | first}}"
      - "{{devices | length}}"
      - "{{timestamp | iso8601}}"
```

### 3. Rate Limit Tracking

#### Implementation

```python
class RateLimitTracker:
    def __init__(self, vendor_profile: VendorProfile):
        self.limits = vendor_profile.rate_limits
        self.counters: Dict[str, Counter] = {}

    def check_limit(self, scope: str) -> Tuple[bool, Optional[float]]:
        """Returns (allowed, wait_time_if_not_allowed)"""
        pass

    def record_request(self, scope: str):
        """Record a request against the rate limit"""
        pass

    def get_usage(self, scope: str) -> Dict:
        """Get current usage statistics"""
        pass
```

#### UI Dashboard

```yaml
dashboard:
  displays:
    - Current usage vs limit (progress bar)
    - Requests over time (chart)
    - Time until limit reset
    - Warning threshold alerts
  actions:
    - Pause requests when approaching limit
    - Auto-retry with exponential backoff
    - Manual override option
```

### 4. AWS SigV4 Authentication

#### Implementation Steps

```python
# New auth type in auth/aws_sigv4.py

class AWSSigV4Auth:
    def __init__(
        self,
        access_key: str,
        secret_key: str,
        region: str,
        service: str,
        session_token: Optional[str] = None
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.service = service
        self.session_token = session_token

    def sign_request(self, request: Request) -> Request:
        """Add SigV4 signature to request"""
        # 1. Create canonical request
        # 2. Create string to sign
        # 3. Calculate signature
        # 4. Add Authorization header
        pass
```

#### Integration with Auth Module

```yaml
auth_schemes:
  existing:
    - apiKey
    - http (basic, bearer)
    - oauth2
    - openIdConnect
  new:
    - awsSigV4:
        access_key_id: string
        secret_access_key: string (sensitive)
        session_token: string (optional)
        region: string
        service: string
```

---

## Data Models

### Database Schema (Future)

```sql
-- Vendor profiles (could also be YAML files)
CREATE TABLE vendor_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT,
    config JSON NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Saved workflows
CREATE TABLE workflows (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    vendor_id TEXT REFERENCES vendor_profiles(id),
    definition JSON NOT NULL,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

-- Workflow executions (for history/replay)
CREATE TABLE workflow_runs (
    id TEXT PRIMARY KEY,
    workflow_id TEXT REFERENCES workflows(id),
    status TEXT,  -- pending, running, completed, failed
    variables JSON,
    results JSON,
    started_at TIMESTAMP,
    completed_at TIMESTAMP
);

-- Rate limit tracking
CREATE TABLE rate_limit_usage (
    id TEXT PRIMARY KEY,
    vendor_id TEXT,
    scope TEXT,
    count INTEGER,
    window_start TIMESTAMP,
    window_end TIMESTAMP
);
```

---

## API Workflow Patterns

### Common Dependency Chains

#### Pattern 1: Hierarchical Discovery

```
Organizations → Networks → Devices → Device Details
```

Used by: Cisco Meraki, Juniper Mist

#### Pattern 2: Auth + Tenant Selection

```
Get Token → List Tenants/TSGs → Select Tenant → API Calls with Tenant Context
```

Used by: Palo Alto (TSG_ID), Multi-tenant platforms

#### Pattern 3: Candidate Configuration

```
Make Changes → Validate → Push/Commit
```

Used by: Palo Alto Prisma SASE, Cisco SD-WAN templates

#### Pattern 4: Paginated Collection

```
Initial Request → Process Page → Check for Next → Repeat
```

Used by: All vendors (with different pagination styles)

### Example Workflows

#### Cisco Meraki: Full Inventory

```yaml
name: Full Meraki Inventory
steps:
  - GET /organizations
  - FOR each org: GET /organizations/{id}/networks
  - FOR each network: GET /networks/{id}/devices
  - Aggregate all devices with org/network context
```

#### Palo Alto Prisma: Security Rule Audit

```yaml
name: Security Rule Audit
steps:
  - POST /oauth2/token (get access token)
  - GET /sse/config/v1/security-rules
  - FOR each rule: Extract source, destination, action
  - Generate compliance report
```

#### Juniper Mist: Site Health Check

```yaml
name: Site Health Check
steps:
  - GET /self (verify token, get org access)
  - GET /orgs/{org_id}/sites
  - FOR each site: GET /sites/{site_id}/stats/devices
  - Calculate health scores per site
```

---

## Implementation Priority

### Phase 1: Foundation

1. Vendor profile data model and YAML storage
2. Profile loader and selector UI
3. Basic workflow definition format

### Phase 2: Core Features

4. Variable extraction and templating
5. Workflow executor with step-by-step execution
6. Rate limit tracking

### Phase 3: Advanced

7. AWS SigV4 authentication
8. Pagination handlers (all patterns)
9. Workflow recorder

### Phase 4: Polish

10. Multi-org credential management
11. Documentation aggregator
12. Postman import/export

---

## References

### Official Documentation Links

| Vendor | Documentation |
|--------|---------------|
| Cisco Meraki | https://developer.cisco.com/meraki/api-v1/ |
| Cisco SD-WAN | https://developer.cisco.com/docs/sdwan/ |
| Cisco Umbrella | https://developer.cisco.com/docs/cloud-security/ |
| Palo Alto SASE | https://pan.dev/sase/docs/ |
| Palo Alto SCM | https://pan.dev/scm/docs/home/ |
| Palo Alto Panorama | https://docs.paloaltonetworks.com/pan-os/11-1/pan-os-panorama-api |
| Juniper Mist | https://www.juniper.net/documentation/us/en/software/mist/automation-integration/ |
| Juniper Security Director | https://www.juniper.net/documentation/us/en/software/sd-cloud/ |
| EcoStruxure IT | https://api.ecostruxureit.com/ |
| AWS | https://docs.aws.amazon.com/ |
| Microsoft Azure | https://learn.microsoft.com/en-us/rest/api/azure/ |

### OpenAPI Repositories

| Vendor | Repository |
|--------|------------|
| Cisco Meraki | https://github.com/meraki/openapi |
| Juniper Mist | https://github.com/Mist-Automation-Programmability/mist_openapi |
| Microsoft Azure | https://github.com/Azure/azure-rest-api-specs |

### Postman Collections

| Vendor | Workspace |
|--------|-----------|
| Cisco SD-WAN | https://www.postman.com/ciscodevnet/cisco-devnet-s-public-workspace |
| Juniper Mist | https://www.postman.com/juniper-mist/workspace/mist-systems-s-public-workspace |
