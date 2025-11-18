//go:build saml

package saml

import (
	"fmt"
	"sync"
	"time"
	apiv1_issuer "vc/internal/gen/issuer/apiv1_issuer"
	"vc/pkg/logger"
)

// SAMLSession represents an active SAML authentication session
type SAMLSession struct {
	ID                 string
	CredentialType     string // Credential type identifier (e.g., "pid")
	CredentialConfigID string // OpenID4VCI credential configuration ID
	IDPEntityID        string
	JWK                *apiv1_issuer.Jwk // Optional: JWK for credential binding
	CreatedAt          time.Time
	ExpiresAt          time.Time
}

// SessionStore manages SAML sessions with TTL
type SessionStore struct {
	sessions map[string]*SAMLSession
	mu       sync.RWMutex
	ttl      time.Duration
	log      *logger.Log
	stopChan chan struct{}
}

// NewSessionStore creates a new session store
func NewSessionStore(ttl time.Duration, log *logger.Log) *SessionStore {
	store := &SessionStore{
		sessions: make(map[string]*SAMLSession),
		ttl:      ttl,
		log:      log.New("session"),
		stopChan: make(chan struct{}),
	}

	go store.cleanupExpired()

	return store
}

// Set stores a SAML session
func (s *SessionStore) Set(id string, session *SAMLSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	session.ExpiresAt = time.Now().Add(s.ttl)
	s.sessions[id] = session

	s.log.Debug("session created",
		"id", id,
		"credential_type", session.CredentialType,
		"expires_at", session.ExpiresAt)
}

// Get retrieves a SAML session
func (s *SessionStore) Get(id string) (*SAMLSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[id]
	if !exists {
		return nil, fmt.Errorf("session not found: %s", id)
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, fmt.Errorf("session expired: %s", id)
	}

	return session, nil
}

// Delete removes a SAML session
func (s *SessionStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, id)
	s.log.Debug("session deleted", "id", id)
}

// cleanupExpired removes expired sessions periodically
func (s *SessionStore) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			deletedCount := 0

			for id, session := range s.sessions {
				if now.After(session.ExpiresAt) {
					delete(s.sessions, id)
					deletedCount++
				}
			}

			if deletedCount > 0 {
				s.log.Debug("cleaned up expired sessions", "count", deletedCount)
			}
			s.mu.Unlock()

		case <-s.stopChan:
			return
		}
	}
}

// Close stops the cleanup goroutine
func (s *SessionStore) Close() {
	close(s.stopChan)
	s.log.Debug("session store closed")
}

// Count returns the number of active sessions
func (s *SessionStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}
