//go:build vc20

package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
)

// ExtractEd25519FromMetadata extracts an Ed25519 public key from a DID document
// or entity configuration returned in the trust_metadata field of an AuthZEN response.
func ExtractEd25519FromMetadata(metadata interface{}, verificationMethod string) (ed25519.PublicKey, error) {
	doc, ok := metadata.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: expected map, got %T", metadata)
	}

	// Find verification method in document
	vms, err := getVerificationMethods(doc)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		vmMap, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is the verification method we're looking for
		if !matchesVerificationMethod(vmMap, verificationMethod, doc) {
			continue
		}

		// Try publicKeyMultibase first (preferred for Ed25519)
		if multibase, ok := vmMap["publicKeyMultibase"].(string); ok {
			key, err := decodeMultikeyEd25519(multibase)
			if err == nil {
				return key, nil
			}
			// Fall through to try other formats
		}

		// Try publicKeyJwk
		if jwk, ok := vmMap["publicKeyJwk"].(map[string]interface{}); ok {
			key, err := JWKToEd25519(jwk)
			if err == nil {
				return key, nil
			}
		}

		// Try publicKeyBase58 (legacy format)
		if keyBase58, ok := vmMap["publicKeyBase58"].(string); ok {
			key, err := decodeBase58Ed25519(keyBase58)
			if err == nil {
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("Ed25519 verification method not found: %s", verificationMethod)
}

// ExtractECDSAFromMetadata extracts an ECDSA public key from a DID document
// or entity configuration returned in the trust_metadata field.
func ExtractECDSAFromMetadata(metadata interface{}, verificationMethod string) (*ecdsa.PublicKey, error) {
	doc, ok := metadata.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid metadata format: expected map, got %T", metadata)
	}

	// Find verification method in document
	vms, err := getVerificationMethods(doc)
	if err != nil {
		return nil, err
	}

	for _, vm := range vms {
		vmMap, ok := vm.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if this is the verification method we're looking for
		if !matchesVerificationMethod(vmMap, verificationMethod, doc) {
			continue
		}

		// Try publicKeyJwk (preferred for ECDSA)
		if jwk, ok := vmMap["publicKeyJwk"].(map[string]interface{}); ok {
			key, err := JWKToECDSA(jwk)
			if err == nil {
				return key, nil
			}
		}

		// Try publicKeyMultibase (P-256 multicodec is 0x1200)
		if multibase, ok := vmMap["publicKeyMultibase"].(string); ok {
			key, err := decodeMultikeyECDSA(multibase)
			if err == nil {
				return key, nil
			}
		}
	}

	return nil, fmt.Errorf("ECDSA verification method not found: %s", verificationMethod)
}

// getVerificationMethods extracts the verification methods array from a DID document.
func getVerificationMethods(doc map[string]interface{}) ([]interface{}, error) {
	// Standard DID document format
	if vms, ok := doc["verificationMethod"].([]interface{}); ok {
		return vms, nil
	}

	// Try as array of maps (some serializations)
	if vms, ok := doc["verificationMethod"].([]map[string]interface{}); ok {
		result := make([]interface{}, len(vms))
		for i, vm := range vms {
			result[i] = vm
		}
		return result, nil
	}

	// OpenID Federation entity configuration - check for JWKS in metadata
	// The structure is: metadata -> openid_relying_party/openid_provider -> jwks -> keys
	if metadata, ok := doc["metadata"].(map[string]interface{}); ok {
		for _, entityType := range []string{"openid_relying_party", "openid_provider", "federation_entity"} {
			if entityMeta, ok := metadata[entityType].(map[string]interface{}); ok {
				if jwks, ok := entityMeta["jwks"].(map[string]interface{}); ok {
					if keys, ok := jwks["keys"].([]interface{}); ok {
						// Convert JWKs to verification method format
						result := make([]interface{}, len(keys))
						for i, key := range keys {
							if keyMap, ok := key.(map[string]interface{}); ok {
								// Create a pseudo verification method from the JWK
								vm := map[string]interface{}{
									"id":           keyMap["kid"],
									"publicKeyJwk": keyMap,
								}
								result[i] = vm
							}
						}
						return result, nil
					}
				}
			}
		}
	}

	return nil, fmt.Errorf("no verification methods found in metadata")
}

// matchesVerificationMethod checks if a verification method entry matches the requested ID.
func matchesVerificationMethod(vmMap map[string]interface{}, verificationMethod string, doc map[string]interface{}) bool {
	// Direct ID match
	if id, ok := vmMap["id"].(string); ok {
		if id == verificationMethod {
			return true
		}
		// Also match if verificationMethod is just the fragment
		if strings.HasSuffix(verificationMethod, "#"+id) {
			return true
		}
		// Match if the VM id is a fragment and we're looking for the full ID
		if strings.HasPrefix(id, "#") {
			docID, _ := doc["id"].(string)
			if docID+id == verificationMethod {
				return true
			}
		}
	}

	// Match by kid (for JWKs)
	if kid, ok := vmMap["kid"].(string); ok {
		if kid == verificationMethod || strings.HasSuffix(verificationMethod, "#"+kid) {
			return true
		}
	}

	return false
}

// decodeMultikeyEd25519 decodes a multikey-encoded Ed25519 public key.
// Multikey format: multibase(multicodec || raw-key-bytes)
// Ed25519 multicodec is 0xed (237)
func decodeMultikeyEd25519(multikey string) (ed25519.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase: %w", err)
	}

	// Check length (2 bytes multicodec + 32 bytes key)
	if len(decoded) != 34 {
		return nil, fmt.Errorf("invalid multikey length: expected 34, got %d", len(decoded))
	}

	// Check Ed25519 multicodec prefix (0xed, 0x01)
	if decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("not an Ed25519 multikey: multicodec 0x%02x%02x", decoded[0], decoded[1])
	}

	return ed25519.PublicKey(decoded[2:]), nil
}

// decodeMultikeyECDSA decodes a multikey-encoded ECDSA public key.
// P-256 multicodec is 0x1200, P-384 is 0x1201
func decodeMultikeyECDSA(multikey string) (*ecdsa.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	// Decode multibase
	_, decoded, err := multibase.Decode(multikey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode multibase: %w", err)
	}

	if len(decoded) < 3 {
		return nil, fmt.Errorf("multikey too short")
	}

	// Check multicodec - P-256 compressed is 0x1200 (varint: 0x80 0x24)
	// For now, we only support P-256 in compressed format
	// The exact encoding depends on the multicodec version
	// This is a simplified check

	// Try to parse as JWK in base64 if the multicodec doesn't match expected patterns
	// This is a fallback for non-standard encodings

	return nil, fmt.Errorf("ECDSA multikey decoding not fully implemented")
}

// decodeBase58Ed25519 decodes a base58-encoded Ed25519 public key (legacy format).
func decodeBase58Ed25519(encoded string) (ed25519.PublicKey, error) {
	// Use multibase with 'z' prefix for base58-btc decoding
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Try base58
		_, decoded, err = multibase.Decode("z" + encoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base58: %w", err)
		}
	}

	if len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid key size: expected %d, got %d", ed25519.PublicKeySize, len(decoded))
	}

	return ed25519.PublicKey(decoded), nil
}

// ExtractDIDFromVerificationMethod extracts the DID from a verification method ID.
// For example: "did:web:example.com#key-1" -> "did:web:example.com"
func ExtractDIDFromVerificationMethod(verificationMethod string) string {
	if idx := strings.Index(verificationMethod, "#"); idx > 0 {
		return verificationMethod[:idx]
	}
	return verificationMethod
}

// ExtractFragmentFromVerificationMethod extracts the fragment from a verification method ID.
// For example: "did:web:example.com#key-1" -> "key-1"
func ExtractFragmentFromVerificationMethod(verificationMethod string) string {
	if idx := strings.Index(verificationMethod, "#"); idx >= 0 && idx < len(verificationMethod)-1 {
		return verificationMethod[idx+1:]
	}
	return ""
}
