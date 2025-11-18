# Phase 3: SAML to Credential Issuance Bridge

## Overview
Phase 3 implements the integration between SAML authentication and credential issuance, completing the end-to-end flow from SAML assertion to OpenID4VCI credential offer.

## Architecture

### Flow Diagram
```
SAML Assertion → Attribute Claims → Document Structure → Credential Creation → Credential Offer
     (ACS)           (mapper)         (transform)         (apiv1.MakeSDJWT)      (OpenID4VCI)
```

### Key Components

#### 1. Claim-to-Document Transformation (`endpoints_saml.go`)

**claimsToDocument()**
- Routes to credential-specific transformation functions
- Supports: PID, Diploma, EHIC
- Returns serialized JSON document data

**claimsToPIDDocument()**
- Maps SAML attributes to `model.Identity` structure
- Required fields: `family_name`, `given_name`, `birth_date`
- Optional fields: nationality, address, contact info
- Uses schema: `https://github.com/dc4eu/vc/identity/1.0`

**claimsToDiplomaDocument()**
- Creates `education.DiplomaDocument` with SAML claims
- Inherits default structure from `NewDiploma()`
- Can be extended with degree title, institution, etc.

**claimsToEHICDocument()**
- Currently returns error - EHIC requires health insurance data
- SAML typically doesn't provide: insurance number, institution, expiry
- Indicates need for additional data sources

#### 2. Credential Creation (`createCredential()`)

```go
CreateCredentialRequest {
    DocumentType: "urn:eudi:pid:1"
    DocumentData: <marshaled document JSON>
    JWK: <optional key for binding>
}
→ s.apiv1.MakeSDJWT(ctx, req)
→ CreateCredentialReply.Data[0].Credential (SD-JWT token string)
```

Uses existing issuer API client via `Apiv1` interface:
- Leverages credential-specific handlers (pidClient, diplomaClient, etc.)
- Each handler calls its `sdjwt()` method with document and JWK
- Returns signed SD-JWT credential token

#### 3. Credential Offer Generation (`generateCredentialOffer()`)

```go
CredentialOfferParameters {
    CredentialIssuer: <from cfg.Common.CredentialOffer.IssuerURL>
    CredentialConfigurationIDs: [<from session.CredentialConfigID>]
    Grants: {
        "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
            "pre-authorized_code": <generated code>
            "tx_code": null
        }
    }
}
→ params.CredentialOffer()
→ CredentialOffer object (JSON)
```

Uses OpenID4VCI standard:
- Pre-authorized code grant type
- No transaction code (tx_code) by default
- Returns credential offer for wallet consumption

## Updated Structures

### SAMLSession (pkg/saml/session.go)
```go
type SAMLSession struct {
    ID                 string
    CredentialType     string
    CredentialConfigID string              // NEW: For credential offer
    IDPEntityID        string
    JWK                *apiv1_issuer.Jwk   // NEW: For credential binding
    CreatedAt          time.Time
    ExpiresAt          time.Time
}
```

### Apiv1 Interface (internal/issuer/httpserver/api.go)
```go
type Apiv1 interface {
    Health(ctx, req) (*StatusReply, error)
    MakeSDJWT(ctx, req) (*CreateCredentialReply, error)  // NEW
}
```

## Endpoint Updates

### POST /saml/acs (endpoints_saml.go)

**Before (Phase 2):**
```json
{
    "status": "authenticated",
    "credential_type": "urn:eudi:pid:1",
    "claims": { ... },
    "message": "Credential issuance integration pending."
}
```

**After (Phase 3):**
```json
{
    "status": "success",
    "credential_type": "urn:eudi:pid:1",
    "credential": "eyJhbGc...<SD-JWT>",
    "credential_offer": {
        "credential_issuer": "https://issuer.example.com",
        "credential_configuration_ids": ["urn:eudi:pid:1"],
        "grants": {
            "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
                "pre-authorized_code": "1234567890-987654321"
            }
        }
    },
    "message": "SAML authentication and credential issuance successful"
}
```

## Configuration Requirements

### Issuer URL
```yaml
common:
  credential_offer:
    issuer_url: "https://issuer.example.com"  # Used in credential offers
```

### Credential Constructors
Each credential type must be configured:
```yaml
credential_constructor:
  "urn:eudi:pid:1":
    vct: "https://example.com/vct/pid"
    vctm_file_path: "metadata/vctm_pid.json"
    auth_method: "basic"
```

## Limitations & Future Work

### Current Limitations

1. **Pre-authorized Code Generation**
   - Uses simple timestamp + random integer
   - TODO: Implement cryptographically secure generation
   - TODO: Store in database with expiry

2. **JWK Handling**
   - Currently accepts optional JWK from session
   - Logs warning if missing but continues
   - TODO: Consider requiring JWK from wallet

3. **EHIC Support**
   - Not fully implemented due to missing health insurance data
   - SAML alone insufficient for EHIC issuance
   - Requires integration with health insurance database

4. **Session Store**
   - In-memory implementation (not production-ready)
   - TODO: Upgrade to Redis/database for scalability

5. **Credential Offer Storage**
   - Currently generated but not persisted
   - TODO: Store in database for retrieval by UUID
   - Wallet needs to fetch offer via offer URI

### Next Steps (Phase 4)

1. **Integration Testing**
   - Test with TestShib IdP
   - Verify full flow: metadata → initiate → auth → ACS → credential → offer
   - Test error conditions and edge cases

2. **Credential Offer Persistence**
   - Store offers in database
   - Generate offer URIs: `openid-credential-offer://issuer.example.com/?credential_offer_uri=https://...`
   - Implement offer retrieval endpoint

3. **Security Enhancements**
   - Cryptographically secure pre-auth code
   - Transaction code (tx_code) support
   - Offer expiry and single-use enforcement

4. **Wallet Integration**
   - Support JWK from wallet for DID binding
   - Return credential offer URI for QR code
   - Implement authorization code flow (alternative to pre-auth)

## Testing

### Build Verification
```bash
# With SAML
go build -tags saml ./cmd/issuer/
✓ Success

# Without SAML (stub)
go build ./cmd/issuer/
✓ Success
```

### Manual Test Flow
```bash
# 1. Get SP metadata
curl http://localhost:8080/saml/metadata

# 2. Initiate authentication
curl -X POST http://localhost:8080/saml/initiate \
  -d '{"credential_type": "urn:eudi:pid:1", "idp_entity_id": "https://idp.example.com"}'

# 3. User authenticates at IdP (browser)

# 4. IdP POSTs assertion to ACS
curl -X POST http://localhost:8080/saml/acs \
  -d "SAMLResponse=<base64>&RelayState=<relay>"

# Response includes credential and offer
```

## Code Organization

```
internal/issuer/httpserver/
  endpoints_saml.go          # SAML endpoints with credential bridge (//go:build saml)
    - endpointSAMLACS()      # Updated with credential issuance
    - claimsToDocument()     # NEW: Transformation router
    - claimsToPIDDocument()  # NEW: PID-specific mapping
    - claimsToDiplomaDocument()  # NEW: Diploma mapping
    - claimsToEHICDocument() # NEW: EHIC stub (error)
    - createCredential()     # NEW: Calls apiv1.MakeSDJWT
    - generateCredentialOffer()  # NEW: Creates OpenID4VCI offer
    - generatePreAuthCode()  # NEW: Simple code generator
  endpoints_saml_stub.go     # Stub endpoints (//go:build !saml)
  api.go                     # Apiv1 interface with MakeSDJWT method
  service.go                 # Service struct with apiv1 client

pkg/saml/
  session.go                 # Updated SAMLSession struct
```

## Dependencies

### New/Updated Packages
- `vc/internal/issuer/apiv1` - Credential creation API
- `vc/internal/gen/issuer/apiv1_issuer` - Protobuf types (Jwk, Credential)
- `vc/pkg/openid4vci` - Credential offer generation
- `vc/pkg/education` - Diploma document structures
- `vc/pkg/pid` - PID document structures
- `vc/pkg/socialsecurity` - EHIC document structures
- `vc/pkg/model` - Identity and config structures

## References

- OpenID4VCI: https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
- SAML Design: `/docs/design/SAML_ISSUER_DESIGN.md`
- Phase 1 & 2 Summary: See git history
- Configuration Example: `/config.saml.example.yaml`
