package cache_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/SUNET/vc/pkg/cache"
	"github.com/SUNET/vc/pkg/logger"
	"github.com/SUNET/vc/pkg/openid4vci"
)

// logAndRead logs kv at debug level and returns the written log file.
func logAndRead(t *testing.T, msg string, kv ...any) string {
	t.Helper()
	dir := t.TempDir()
	log, err := logger.New("probe", dir, false)
	require.NoError(t, err)
	log.Debug(msg, kv...)
	out, err := os.ReadFile(filepath.Join(dir, "probe.log"))
	require.NoError(t, err)
	return string(out)
}

func TestAnAuthorizationContextRedactsItselfInALog(t *testing.T) {
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
	ctx := &cache.AuthorizationContext{
		SessionID: "sess-1", ClientID: "client-1",
		AccessToken: secrets["access token"], RefreshToken: secrets["refresh token"],
		IDToken: secrets["id token"], Code: secrets["authorization code"],
		TXCode: secrets["tx code"], VPToken: secrets["vp token"],
		Token:          &cache.Token{AccessToken: secrets["nested access token"]},
		VerifiedClaims: map[string]any{"personal_administrative_number": secrets["a verified claim"]},
	}

	// The whole struct, as several call sites log it.
	out := logAndRead(t, "ctx", "auth", ctx)

	for what, value := range secrets {
		require.NotContainsf(t, out, value, "the %s reached the log", what)
	}
	require.Contains(t, out, "sess-1", "the session id is what the line is for")
	require.Contains(t, out, "has_access_token", "whether a token exists is useful; its value is not")
	require.Contains(t, out, "personal_administrative_number",
		"the claim NAMES are useful and are not the holder's data; the values are")
}

// A dereferenced context redacts too. This is what the value receiver
// buys: *authCtx is a one-character slip at a call site and indis-
// tinguishable from authCtx in review, and with a pointer receiver it
// would reflect over the struct and print every field.
func TestADereferencedAuthorizationContextRedactsItselfToo(t *testing.T) {
	ctx := cache.AuthorizationContext{
		SessionID:   "sess-2",
		AccessToken: "AT-dereferenced",
		VerifiedClaims: map[string]any{
			"personal_administrative_number": "PAN-198001011234",
		},
	}

	out := logAndRead(t, "ctx", "auth", ctx)

	require.NotContains(t, out, "AT-dereferenced", "the access token reached the log")
	require.NotContains(t, out, "PAN-198001011234", "the claim value reached the log")
	require.Contains(t, out, "sess-2")
	require.Contains(t, out, "has_access_token")
}

// The claim names are sorted, so two logs of the same context compare.
// Map order is randomised per iteration, so an unsorted list made every
// line different and hid a real change in the claim set among the churn.
func TestTheClaimNamesAreLoggedInAStableOrder(t *testing.T) {
	ctx := &cache.AuthorizationContext{
		SessionID: "sess-3",
		VerifiedClaims: map[string]any{
			"given_name": "x", "birth_date": "y", "family_name": "z",
			"nationality": "w", "resident_city": "v", "age_over_18": "u",
		},
	}

	first := logAndRead(t, "ctx", "auth", ctx)
	require.Contains(t, first, `"age_over_18","birth_date","family_name","given_name","nationality","resident_city"`,
		"the claim names must be sorted, not in map order")

	for range 20 {
		require.Equal(t, claimList(t, first), claimList(t, logAndRead(t, "ctx", "auth", ctx)),
			"the same context logged twice must produce the same claim list")
	}
}

// claimList returns the verified_claim_keys array as written.
func claimList(t *testing.T, logLine string) string {
	t.Helper()
	const key = `"verified_claim_keys":[`
	start := strings.Index(logLine, key)
	require.GreaterOrEqual(t, start, 0, "the log line carries no verified_claim_keys")
	rest := logLine[start+len(key):]
	end := strings.Index(rest, "]")
	require.GreaterOrEqual(t, end, 0)
	return rest[:end]
}

func TestATokenResponseRedactsItselfInALog(t *testing.T) {
	reply := &openid4vci.TokenResponse{
		AccessToken: "AT-eyJhbGciOiJFUzI1NiJ9", TokenType: "DPoP", ExpiresIn: 3600,
		Scope: "nym_auth", CNonce: "NONCE-c0ffee", RefreshToken: "RT-r3fr3sh",
	}
	out := logAndRead(t, "Token endpoint", "reply", reply)

	require.NotContains(t, out, "AT-eyJhbGciOiJFUzI1NiJ9", "the access token reached the log")
	require.NotContains(t, out, "NONCE-c0ffee", "the c_nonce reached the log")
	require.NotContains(t, out, "RT-r3fr3sh", "the refresh token reached the log")
	require.Contains(t, out, "DPoP")
	require.Contains(t, out, "nym_auth")
}

// A nil pointer logs without panicking.
func TestRedactionHandlesNil(t *testing.T) {
	require.NotPanics(t, func() {
		logAndRead(t, "nil", "auth", (*cache.AuthorizationContext)(nil), "reply", (*openid4vci.TokenResponse)(nil))
	})
}
