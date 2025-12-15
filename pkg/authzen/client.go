//go:build vc20

// Package authzen implements a client for draft-johansson-authzen-trust protocol.
// This provides trust evaluation for name-to-key bindings via AuthZEN.
//
// Deprecated: This package is deprecated in favor of github.com/SUNET/go-trust/pkg/authzenclient.
// The go-trust package provides additional features including:
//   - Discovery via .well-known/authzen-configuration endpoint
//   - Resolution-only requests for DID document retrieval
//   - Better error handling and context support
//   - Support for both JWK and X.509 certificate evaluation
//
// Migration guide:
//
//	// Old code:
//	client := authzen.NewClient("https://pdp.example.com")
//	decision, err := client.EvaluateJWK(subjectID, jwk, role)
//
//	// New code:
//	import "github.com/SUNET/go-trust/pkg/authzenclient"
//	client := authzenclient.New("https://pdp.example.com")
//	resp, err := client.EvaluateJWK(ctx, subjectID, jwk, &authzen.Action{Name: role})
//	decision := resp.Decision
//
// For key resolution, use the pkg/keyresolver package with GoTrustResolver:
//
//	resolver := keyresolver.NewGoTrustResolver("https://pdp.example.com")
//	key, err := resolver.ResolveEd25519("did:web:example.com#key-1")
package authzen

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client implements the AuthZEN Trust protocol client
type Client struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new AuthZEN Trust protocol client
func NewClient(baseURL string) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		timeout: 10 * time.Second,
	}
}

// SetTimeout configures the HTTP timeout
func (c *Client) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
	c.httpClient.Timeout = timeout
}

// Subject represents the name part of the name-to-key binding
type Subject struct {
	Type string `json:"type"` // MUST be "key"
	ID   string `json:"id"`   // The name bound to the public key
}

// Resource represents the public key to be validated
type Resource struct {
	Type string `json:"type"` // "jwk" or "x5c"
	ID   string `json:"id"`   // MUST match subject.id
	Key  any    `json:"key"`  // JWK object or array of base64 X.509 certs
}

// Action represents the role associated with the name-to-key binding
type Action struct {
	Name string `json:"name"` // Role identifier
}

// EvaluationRequest represents an AuthZEN evaluation request
type EvaluationRequest struct {
	Subject  Subject           `json:"subject"`
	Resource Resource          `json:"resource"`
	Action   *Action           `json:"action,omitempty"`
	Context  map[string]string `json:"context,omitempty"`
}

// EvaluationResponse represents an AuthZEN evaluation response
type EvaluationResponse struct {
	Decision bool           `json:"decision"`
	Context  map[string]any `json:"context,omitempty"`
}

// EvaluationEnvelope wraps the request according to AuthZEN format
type EvaluationEnvelope struct {
	Type    string            `json:"type"` // MUST be "authzen"
	Request EvaluationRequest `json:"request"`
}

// EvaluateJWK evaluates whether a JWK is bound to a given name (subject ID)
// Returns true if the trust registry authorizes this binding
func (c *Client) EvaluateJWK(subjectID string, jwk map[string]any, role string) (bool, error) {
	req := EvaluationEnvelope{
		Type: "authzen",
		Request: EvaluationRequest{
			Subject: Subject{
				Type: "key",
				ID:   subjectID,
			},
			Resource: Resource{
				Type: "jwk",
				ID:   subjectID,
				Key:  jwk,
			},
		},
	}

	if role != "" {
		req.Request.Action = &Action{Name: role}
	}

	return c.evaluate(req)
}

// EvaluateX5C evaluates whether an X.509 certificate chain is bound to a given name
// certChain is an array of base64-encoded X.509 certificates
func (c *Client) EvaluateX5C(subjectID string, certChain []string, role string) (bool, error) {
	req := EvaluationEnvelope{
		Type: "authzen",
		Request: EvaluationRequest{
			Subject: Subject{
				Type: "key",
				ID:   subjectID,
			},
			Resource: Resource{
				Type: "x5c",
				ID:   subjectID,
				Key:  certChain,
			},
		},
	}

	if role != "" {
		req.Request.Action = &Action{Name: role}
	}

	return c.evaluate(req)
}

// evaluate performs the actual HTTP request to the /evaluation endpoint
func (c *Client) evaluate(req EvaluationEnvelope) (bool, error) {
	reqBody, err := json.Marshal(req)
	if err != nil {
		return false, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Make HTTP POST to /evaluation endpoint
	httpReq, err := http.NewRequest("POST", c.baseURL+"/evaluation", bytes.NewReader(reqBody))
	if err != nil {
		return false, fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("evaluation failed with status %d: %s", resp.StatusCode, string(body))
	}

	var evalResp EvaluationResponse
	if err := json.NewDecoder(resp.Body).Decode(&evalResp); err != nil {
		return false, fmt.Errorf("failed to decode response: %w", err)
	}

	return evalResp.Decision, nil
}

// JWKFromEd25519 creates a JWK from an Ed25519 public key
func JWKFromEd25519(publicKey []byte) map[string]any {
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(publicKey),
	}
}

// Ed25519FromJWK extracts an Ed25519 public key from a JWK
func Ed25519FromJWK(jwk map[string]any) ([]byte, error) {
	kty, ok := jwk["kty"].(string)
	if !ok || kty != "OKP" {
		return nil, fmt.Errorf("invalid key type, expected OKP")
	}

	crv, ok := jwk["crv"].(string)
	if !ok || crv != "Ed25519" {
		return nil, fmt.Errorf("invalid curve, expected Ed25519")
	}

	x, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing x coordinate")
	}

	publicKey, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x coordinate: %w", err)
	}

	if len(publicKey) != 32 {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(publicKey))
	}

	return publicKey, nil
}
