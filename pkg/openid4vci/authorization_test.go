package openid4vci

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin/binding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	mockEscapedAuthorizationDetails = "%5B%7B%22type%22%3A%22openid_credential%22%2C%22credential_configuration_id%22%3A%22TestCredential%22%7D%2C%7B%22type%22%3A%22openid_credential%22%2C%22format%22%3A%22vc%2Bsd-jwt%22%2C%22vct%22%3A%22SD_JWT_VC_example_in_OpenID4VCI%22%7D%5D"
)

func TestMockAuthorizationDetails(t *testing.T) {
	tts := []struct {
		name string
		have []AuthorizationDetailsParameter
	}{
		{
			name: "credentialIdentifier",
			have: []AuthorizationDetailsParameter{
				{ // #nosec G101
					Type:                      "openid_credential",
					CredentialConfigurationID: "TestCredential",
				},
				{
					Type:   "openid_credential",
					Format: "vc+sd-jwt",
					VCT:    "SD_JWT_VC_example_in_OpenID4VCI",
				},
			},
		},
		{
			name: "format",
			have: []AuthorizationDetailsParameter{
				{
					Type:   "openid_credential",
					Format: "vc+sd-jwt",
					VCT:    "SD_JWT_VC_example_in_OpenID4VCI",
				},
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			for _, p := range tt.have {
				if err := CheckSimple(p); err != nil {
					t.Log(err)
					t.FailNow()
				}
			}

			authorizationDetailsParameters, err := json.Marshal(tt.have)
			assert.NoError(t, err)

			escaped := url.QueryEscape(string(authorizationDetailsParameters))
			fmt.Println("escaped", escaped)
		})
	}
}

func TestURLDecode(t *testing.T) {
	tts := []struct {
		name string
		have string
		want string
	}{
		{
			name: "test",
			have: mockEscapedAuthorizationDetails,
			want: "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"TestCredential\"},{\"type\":\"openid_credential\",\"format\":\"vc+sd-jwt\",\"vct\":\"SD_JWT_VC_example_in_OpenID4VCI\"}]",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			got, err := url.QueryUnescape(tt.have)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthParse(t *testing.T) {
	tts := []struct {
		name string
		have string
	}{
		{
			name: "test",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			//got, err := tt.have.AuthRedirectURL(tt.redirectURL)
			//assert.NoError(t, err)

			//assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthorizeBinding(t *testing.T) {
	tts := []struct {
		name string
		want *PARRequest
		have map[string]any
	}{
		{
			name: "with authorization details",
			want: &PARRequest{
				ResponseType: "code",
				AuthorizationDetails: AuthorizationDetails{
					{ // #nosec G101
						Type:                      "openid_credential",
						CredentialConfigurationID: "TestCredential",
					},
					{
						Type:   "openid_credential",
						Format: "vc+sd-jwt",
						VCT:    "SD_JWT_VC_example_in_OpenID4VCI",
					},
				},
			},
			have: map[string]any{
				"authorization_details": mockEscapedAuthorizationDetails,
				"response_type":         "code",
			},
		},
		{
			name: "without authorization details",
			want: &PARRequest{
				ResponseType: "code",
			},
			have: map[string]any{
				"response_type": "code",
			},
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.have)
			assert.NoError(t, err)

			body := io.NopCloser(bytes.NewBuffer(b))

			got, err := BindAuthorizationRequest(body)
			assert.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPARRequestFormBindsAuthorizationDetailsArray(t *testing.T) {
	body := "client_id=eudiw-abca&scope=demo_pid_rb_1_5&state=ada378be-14c0-4d00-a542-2a0c81d3e01d&redirect_uri=http%3A%2F%2Flocalhost%3A3001%2Fcontinue-issuance&authorization_details=%5B%7B%22credential_configuration_id%22%3A%22demo_pid_rb_1_5%22%2C%22type%22%3A%22openid_credential%22%7D%5D&response_type=code&code_challenge=SjqUCZE5Pa9kLcMieOpWAWwtl-OvNkGX5yBXntTyJo4&code_challenge_method=S256&nonce=GHqO4BDA4Vmc9r7oyNvzs01ZwEZeRg5S"

	req, err := http.NewRequest(http.MethodPost, "/oauth/par", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Form binding validates the struct. This test only checks decoding.
	prev := binding.Validator
	binding.Validator = nil
	t.Cleanup(func() { binding.Validator = prev })

	got := &PARRequest{}
	require.NoError(t, binding.Form.Bind(req, got))

	assert.Equal(t, "eudiw-abca", got.ClientID)
	assert.Equal(t, "demo_pid_rb_1_5", got.Scope)
	assert.Equal(t, "code", got.ResponseType)
	assert.Equal(t, AuthorizationDetails{{
		Type:                      "openid_credential",
		CredentialConfigurationID: "demo_pid_rb_1_5",
	}}, got.AuthorizationDetails)
}
