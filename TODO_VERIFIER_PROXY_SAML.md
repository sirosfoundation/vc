# TODO: Verifier Proxy SAML Support

## Context
During SAML issuer implementation, changes were made to verifier_proxy that need to be preserved and potentially expanded.

## Files Modified
- `internal/verifier_proxy/httpserver/endpoints_client_registration.go`
- `internal/verifier_proxy/httpserver/endpoints_oidc_ratelimited.go`
- `internal/verifier_proxy/db/client.go`

## Action Items
1. Review the changes in these files (currently uncommitted)
2. Determine if they are SAML-related or separate fixes
3. If SAML-related: Add build tags and proper integration
4. If separate: Create a separate commit/PR for verifier_proxy improvements
5. Test verifier_proxy functionality with SAML enabled/disabled

## Priority
- Review after Phase 3 (SAML credential issuance bridge) is complete
- Before final PR/merge to main branch

## Command to Review Changes
```bash
git diff internal/verifier_proxy/
```
