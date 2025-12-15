//go:build vc20

// Package keyresolver provides pluggable key resolution for verifiable credentials
package keyresolver

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/multiformats/go-multibase"
)

// Resolver provides methods to resolve public keys from verification methods.
// Implementations may support one or both key types.
type Resolver interface {
	// ResolveEd25519 resolves an Ed25519 public key from a verification method identifier
	ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error)
}

// ECDSAResolver extends Resolver with ECDSA key resolution capability.
// Resolvers that support ECDSA keys should implement this interface.
type ECDSAResolver interface {
	Resolver
	// ResolveECDSA resolves an ECDSA public key from a verification method identifier
	ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error)
}

// MultiResolver combines multiple resolvers with fallback behavior
type MultiResolver struct {
	resolvers []Resolver
}

// NewMultiResolver creates a resolver that tries each resolver in order
func NewMultiResolver(resolvers ...Resolver) *MultiResolver {
	return &MultiResolver{
		resolvers: resolvers,
	}
}

// ResolveEd25519 tries each resolver until one succeeds
func (m *MultiResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	var errors []error

	for _, resolver := range m.resolvers {
		key, err := resolver.ResolveEd25519(verificationMethod)
		if err == nil {
			return key, nil
		}
		errors = append(errors, err)
	}

	if len(errors) == 0 {
		return nil, fmt.Errorf("no resolvers configured")
	}

	// Return the last error
	return nil, fmt.Errorf("all resolvers failed: %v", errors[len(errors)-1])
}

// ResolveECDSA tries each resolver that supports ECDSA until one succeeds
func (m *MultiResolver) ResolveECDSA(verificationMethod string) (*ecdsa.PublicKey, error) {
	var errors []error
	foundECDSAResolver := false

	for _, resolver := range m.resolvers {
		if ecdsaResolver, ok := resolver.(ECDSAResolver); ok {
			foundECDSAResolver = true
			key, err := ecdsaResolver.ResolveECDSA(verificationMethod)
			if err == nil {
				return key, nil
			}
			errors = append(errors, err)
		}
	}

	if !foundECDSAResolver {
		return nil, fmt.Errorf("no ECDSA-capable resolvers configured")
	}

	if len(errors) == 0 {
		return nil, fmt.Errorf("no resolvers configured")
	}

	// Return the last error
	return nil, fmt.Errorf("all ECDSA resolvers failed: %v", errors[len(errors)-1])
}

// LocalResolver resolves keys from local data (multikey, did:key)
type LocalResolver struct{}

// NewLocalResolver creates a resolver that handles local key formats
func NewLocalResolver() *LocalResolver {
	return &LocalResolver{}
}

// ResolveEd25519 extracts Ed25519 keys from local formats
func (l *LocalResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	// Handle did:key format
	if strings.HasPrefix(verificationMethod, "did:key:") {
		return l.resolveDidKey(verificationMethod)
	}

	// Handle multikey format directly
	if strings.HasPrefix(verificationMethod, "u") || strings.HasPrefix(verificationMethod, "z") {
		return l.decodeMultikey(verificationMethod)
	}

	return nil, fmt.Errorf("unsupported verification method format: %s", verificationMethod)
}

// resolveDidKey extracts the public key from a did:key identifier
func (l *LocalResolver) resolveDidKey(didKey string) (ed25519.PublicKey, error) {
	// did:key format: did:key:{multikey}#{fragment}
	// We need to extract the multikey part

	// Remove "did:key:" prefix
	withoutPrefix := strings.TrimPrefix(didKey, "did:key:")

	// Split on # to get the multikey (before fragment)
	parts := strings.Split(withoutPrefix, "#")
	if len(parts) == 0 {
		return nil, fmt.Errorf("invalid did:key format: %s", didKey)
	}

	multikey := parts[0]
	fmt.Printf("[DEBUG] resolveDidKey: extracted multikey=%s from didKey=%s\n", multikey, didKey)
	key, err := l.decodeMultikey(multikey)
	if err != nil {
		fmt.Printf("[DEBUG] resolveDidKey: decodeMultikey failed: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] resolveDidKey: SUCCESS, key length=%d\n", len(key))
	}
	return key, err
}

// decodeMultikey decodes a multikey-encoded public key
func (l *LocalResolver) decodeMultikey(multikey string) (ed25519.PublicKey, error) {
	if len(multikey) == 0 {
		return nil, fmt.Errorf("empty multikey")
	}

	var keyBytes []byte
	var err error

	// Check the multibase prefix (first character)
	prefix := multikey[0]
	fmt.Printf("[DEBUG] decodeMultikey: prefix=%c, multikey length=%d\n", prefix, len(multikey))

	switch prefix {
	case 'z':
		// Base58-btc encoding (multibase prefix 'z')
		// Decode using go-multibase which handles the prefix
		_, decoded, err := multibase.Decode(multikey)
		if err != nil {
			fmt.Printf("[DEBUG] decodeMultikey: base58-btc decode failed: %v\n", err)
			return nil, fmt.Errorf("failed to decode base58-btc multikey: %w", err)
		}
		fmt.Printf("[DEBUG] decodeMultikey: base58-btc decoded %d bytes\n", len(decoded))
		keyBytes = decoded

	case 'u':
		// Base64url encoding (no padding)
		// For multibase base64url, the first character is the prefix
		encoded := multikey[1:]
		keyBytes, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			fmt.Printf("[DEBUG] decodeMultikey: base64url decode failed: %v\n", err)
			return nil, fmt.Errorf("failed to decode base64url multikey: %w", err)
		}
		fmt.Printf("[DEBUG] decodeMultikey: base64url decoded %d bytes\n", len(keyBytes))

	default:
		return nil, fmt.Errorf("unsupported multibase prefix: %c", prefix)
	}

	// The multikey format is: multicodec || public-key-bytes
	// We need to parse the multicodec varint to identify the key type
	if len(keyBytes) < 3 {
		return nil, fmt.Errorf("multikey too short: expected at least 3 bytes, got %d", len(keyBytes))
	}

	// Decode multicodec (varint)
	// Ed25519 public key multicodec is 0xed (237)
	multicodec, bytesRead := binary.Uvarint(keyBytes)
	fmt.Printf("[DEBUG] decodeMultikey: multicodec=0x%x, bytesRead=%d\n", multicodec, bytesRead)
	if bytesRead <= 0 {
		return nil, fmt.Errorf("failed to decode multicodec varint")
	}

	// Extract the public key bytes after the multicodec
	pubKeyBytes := keyBytes[bytesRead:]
	fmt.Printf("[DEBUG] decodeMultikey: extracted %d public key bytes\n", len(pubKeyBytes))

	// Ed25519 public keys are 32 bytes
	// Multicodec 0xed (237) is the Ed25519 public key type
	if multicodec != 0xed {
		return nil, fmt.Errorf("unsupported key type: multicodec 0x%x (expected 0xed for Ed25519)", multicodec)
	}

	if len(pubKeyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d bytes, expected %d", len(pubKeyBytes), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(pubKeyBytes), nil
}

// StaticResolver provides a simple key->value resolver for testing
type StaticResolver struct {
	keys map[string]ed25519.PublicKey
}

// NewStaticResolver creates a resolver with a static key map
func NewStaticResolver() *StaticResolver {
	return &StaticResolver{
		keys: make(map[string]ed25519.PublicKey),
	}
}

// AddKey adds a key to the static resolver
func (s *StaticResolver) AddKey(verificationMethod string, publicKey ed25519.PublicKey) {
	s.keys[verificationMethod] = publicKey
}

// ResolveEd25519 looks up the key in the static map
func (s *StaticResolver) ResolveEd25519(verificationMethod string) (ed25519.PublicKey, error) {
	key, ok := s.keys[verificationMethod]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", verificationMethod)
	}
	return key, nil
}
