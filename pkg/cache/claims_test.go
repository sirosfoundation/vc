package cache

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Verified claims read back from the BSON encoding of the Mongo-backed
// store as they were written: objects as map[string]any, arrays as []any,
// an undisclosed array element at its position.
func TestVerifiedClaimsSurviveTheMongoStore(t *testing.T) {
	claims := map[string]any{
		"address":       map[string]any{"country": "SE", "lines": []any{"Storgatan 1"}},
		"nationalities": []any{map[string]any{"...": "digest-of-DE"}, "FR", "US"},
	}
	raw, err := bson.Marshal(&AuthorizationContext{SessionID: "s", VerifiedClaims: claims})
	require.NoError(t, err)
	var stored AuthorizationContext
	require.NoError(t, bson.Unmarshal(raw, &stored))
	assert.Equal(t, Claims(claims), stored.VerifiedClaims)
}
