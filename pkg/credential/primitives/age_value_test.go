package primitives

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A refused birthdate is not quoted back.
//
// The caller wraps this into "the presented claims cannot satisfy this
// scope" and logs it, so a date here is a holder's date of birth in the
// log. The operator needs the claim and the session, and the session id
// is already on that line.
func TestARefusedBirthdateDoesNotReachTheError(t *testing.T) {
	now := time.Date(2026, 11, 3, 0, 0, 0, 0, time.UTC)

	for name, birthdate := range map[string]string{
		"a malformed date": "1990-15-45",
		"a future date":    "2099-01-15",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := AgeOverThresholds(birthdate, now, []int{18})
			require.Error(t, err)
			require.ErrorIs(t, err, ErrInvalidClaimInput)
			require.NotContains(t, err.Error(), birthdate,
				"the refusal quoted the holder's birthdate: %s", err.Error())
			require.NotRegexp(t, `[0-9]{4}`, err.Error(),
				"no run of digits long enough to be a year: %s", err.Error())
		})
	}
}
