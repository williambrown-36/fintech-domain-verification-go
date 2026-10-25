package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerificationDecision(t *testing.T) {
	for _, tc := range []struct {
		name, domain, event string
		want                bool
	}{
		{"matching notification", "pay.example.com", "verified", true},
		{"unrelated event", "pay.example.com", "pending", false},
		{"unknown domain", "other.example.com", "verified", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &service{event: "verified", domains: map[string]onboarding{"pay.example.com": {Domain: "pay.example.com", State: "pending_verification"}}}
			if got := s.transition(tc.domain, tc.event); got != tc.want {
				t.Fatalf("transition = %v, want %v", got, tc.want)
			}
			if len(s.audit) != 0 != tc.want {
				t.Fatalf("audit count = %d", len(s.audit))
			}
		})
	}
}

func TestPaymentRiskDecision(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		amount      int64
		want        string
	}{
		{"verified small charge", "verified", 5000, "allow"},
		{"unverified domain", "pending_verification", 5000, "review"},
		{"large charge", "verified", 150000, "review"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := decidePayment(onboarding{State: tc.state}, paymentEvent{ID: "evt-1", AmountCents: tc.amount, Action: "charge"})
			if got.RiskAction != tc.want || got.Notification != "recorded" {
				t.Fatalf("decision = %+v", got)
			}
		})
	}
}

func TestSignedNotification(t *testing.T) {
	s := &service{secret: []byte("test-secret"), event: "verified", signatureHeader: "X-Signature", domains: map[string]onboarding{"pay.example.com": {Domain: "pay.example.com", State: "pending_verification"}}}
	body := `{"event":"verified","domain":"pay.example.com"}`
	for _, tc := range []struct {
		name   string
		signed bool
		status int
		state  string
	}{
		{"valid signature", true, http.StatusNoContent, "verified"},
		{"invalid signature", false, http.StatusUnauthorized, "pending_verification"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s.domains["pay.example.com"] = onboarding{Domain: "pay.example.com", State: "pending_verification"}
			req := httptest.NewRequest(http.MethodPost, "/webhooks/verification", strings.NewReader(body))
			if tc.signed {
				mac := hmac.New(sha256.New, s.secret)
				mac.Write([]byte(body))
				req.Header.Set("X-Signature", hex.EncodeToString(mac.Sum(nil)))
			}
			res := httptest.NewRecorder()
			s.webhook(res, req)
			if res.Code != tc.status || s.domains["pay.example.com"].State != tc.state {
				t.Fatalf("status = %d, state = %s", res.Code, s.domains["pay.example.com"].State)
			}
		})
	}
}
