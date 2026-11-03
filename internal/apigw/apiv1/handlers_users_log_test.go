package apiv1

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/model"
	"github.com/SUNET/vc/pkg/vcclient"
)

// UserLookup is driven for real, against a file logger, because a leak
// shows only in the rendering - and because a test that re-types the
// handler's log line asserts nothing about the handler. This one fails if
// handlers_users.go goes back to logging the whole context, which is the
// regression it exists for.
//
// The call is expected to fail: the context carries no wallet URI and no
// provider, so UserLookup gets as far as the line under test and then
// stops. The log is the assertion, not the return value.
func TestUserLookupNeverLogsTheWholeAuthorizationContext(t *testing.T) {
	dir := t.TempDir()
	log, err := logger.New("probe", dir, false)
	require.NoError(t, err)

	c := newMDocPresentationTestClient(t, log)
	// UserLookup builds the wallet redirect from this before it reaches
	// the switch; without it the handler cannot run at all.
	c.cfg.APIGW = &model.APIGW{PublicURL: "https://apigw.test"}

	secrets := map[string]string{
		"access token":        "AT-eyJhbGciOiJFUzI1NiJ9",
		"nested access token": "TOKEN-xyzzy",
		"refresh token":       "RT-r3fr3sh",
		"id token":            "IDT-eyJ",
		"authorization code":  "CODE-abc123",
		"tx code":             "TX-998877",
		"vp token":            "VP-presented",
		"a verified claim":    "PAN-198001011234",
	}
	authCtx := &cache.AuthorizationContext{
		SessionID:    "sess-1",
		RequestURI:   "https://example.test/request/1",
		AccessToken:  secrets["access token"],
		RefreshToken: secrets["refresh token"],
		IDToken:      secrets["id token"],
		Code:         secrets["authorization code"],
		TXCode:       secrets["tx code"],
		VPToken:      secrets["vp token"],
		Token: &cache.Token{
			AccessToken: secrets["nested access token"],
			ExpiresAt:   time.Now().Add(time.Hour).Unix(),
		},
		VerifiedClaims: map[string]any{
			"personal_administrative_number": secrets["a verified claim"],
		},
	}
	require.NoError(t, c.cacheService.AuthContext.Create(t.Context(), authCtx))

	_, _ = c.UserLookup(t.Context(), &vcclient.UserLookupRequest{
		RequestURI: authCtx.RequestURI,
	})

	written, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)
	out := string(written)

	require.Contains(t, out, "sess-1",
		"the session id is what makes the line useful and must survive the redaction")
	for what, value := range secrets {
		require.NotContainsf(t, out, value, "the %s reached the log", what)
	}
}
