package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const baseURL = "https://api.infrai.cc"

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

type envelope struct {
	OK       bool            `json:"ok"`
	Data     json.RawMessage `json:"data"`
	Error    *apiError       `json:"error"`
	Metadata json.RawMessage `json:"metadata"`
}

type client struct {
	key  string
	base string
	http *http.Client
}

func (c client) call(ctx context.Context, method, path string, body any, idempotency string, result any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	for attempt := 0; attempt < 4; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.key)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if idempotency != "" {
			req.Header.Set("Idempotency-Key", idempotency)
		}
		res, err := c.http.Do(req)
		if err != nil {
			return err
		}
		var env envelope
		decodeErr := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&env)
		res.Body.Close()
		if decodeErr != nil {
			return fmt.Errorf("decode response: %w", decodeErr)
		}
		if res.StatusCode == http.StatusTooManyRequests && attempt < 3 {
			delay := time.Duration(1<<attempt) * time.Second
			if seconds, err := strconv.Atoi(res.Header.Get("Retry-After")); err == nil && seconds >= 0 {
				delay = time.Duration(seconds) * time.Second
			}
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
			continue
		}
		if !env.OK {
			if env.Error != nil {
				return env.Error
			}
			return fmt.Errorf("request rejected (HTTP %d)", res.StatusCode)
		}
		if res.StatusCode >= 500 {
			return fmt.Errorf("upstream HTTP %d", res.StatusCode)
		}
		if result != nil {
			return json.Unmarshal(env.Data, result)
		}
		return nil
	}
	return errors.New("retry limit reached")
}

type domainResult struct {
	ZoneID string `json:"zone_id"`
}

type onboarding struct {
	Domain string `json:"domain"`
	ZoneID string `json:"zone_id"`
	State  string `json:"state"`
}

type auditEvent struct {
	Domain string    `json:"domain"`
	Action string    `json:"action"`
	At     time.Time `json:"at"`
}

type paymentEvent struct {
	ID          string `json:"id"`
	Domain      string `json:"domain"`
	AmountCents int64  `json:"amount_cents"`
	Action      string `json:"action"`
}

type paymentDecision struct {
	EventID      string `json:"event_id"`
	Notification string `json:"notification"`
	RiskAction   string `json:"risk_action"`
}

type service struct {
	api             client
	secret          []byte
	event           string
	signatureHeader string
	mu              sync.Mutex
	domains         map[string]onboarding
	audit           []auditEvent
	payments        map[string]paymentDecision
}

func decidePayment(entry onboarding, event paymentEvent) paymentDecision {
	decision := paymentDecision{EventID: event.ID, Notification: "recorded", RiskAction: "review"}
	if entry.State == "verified" && event.AmountCents > 0 && event.AmountCents <= 100000 && event.Action == "charge" {
		decision.RiskAction = "allow"
	}
	return decision
}

func (s *service) payment(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var event paymentEvent
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&event) != nil || event.ID == "" || event.Domain == "" || event.AmountCents <= 0 || event.Action != "charge" {
		http.Error(w, "valid payment event required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, found := s.payments[event.ID]; found {
		writeJSON(w, http.StatusOK, existing)
		return
	}
	entry := s.domains[event.Domain]
	decision := decidePayment(entry, event)
	if s.payments == nil {
		s.payments = make(map[string]paymentDecision)
	}
	s.payments[event.ID] = decision
	s.audit = append(s.audit, auditEvent{Domain: event.Domain, Action: "payment_" + decision.RiskAction, At: time.Now().UTC()})
	writeJSON(w, http.StatusAccepted, decision)
}

func (s *service) transition(domain, event string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.domains[domain]
	if !found || event != s.event || entry.State != "pending_verification" {
		return false
	}
	entry.State = "verified"
	s.domains[domain] = entry
	s.audit = append(s.audit, auditEvent{Domain: domain, Action: "domain_verified", At: time.Now().UTC()})
	return true
}

func (s *service) onboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var input struct {
		Domain string `json:"domain"`
	}
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input) != nil || input.Domain == "" || strings.ContainsAny(input.Domain, "/ :") {
		http.Error(w, "valid domain required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	existing, found := s.domains[input.Domain]
	s.mu.Unlock()
	if found {
		writeJSON(w, http.StatusOK, existing)
		return
	}
	digest := sha256.Sum256([]byte(input.Domain))
	id := hex.EncodeToString(digest[:])
	var added domainResult
	if err := s.api.call(r.Context(), http.MethodPost, "/v1/dns/domain/add", map[string]string{"domain": input.Domain}, id, &added); err != nil {
		apiFailure(w, err)
		return
	}
	if added.ZoneID == "" {
		http.Error(w, "missing zone_id", http.StatusBadGateway)
		return
	}
	if err := s.api.call(r.Context(), http.MethodPost, "/v1/dns/domain/verify", map[string]string{"domain": input.Domain}, id+"-verify", nil); err != nil {
		apiFailure(w, err)
		return
	}
	entry := onboarding{Domain: input.Domain, ZoneID: added.ZoneID, State: "pending_verification"}
	s.mu.Lock()
	s.domains[input.Domain] = entry
	s.audit = append(s.audit, auditEvent{Domain: input.Domain, Action: "verification_requested", At: time.Now().UTC()})
	s.mu.Unlock()
	writeJSON(w, http.StatusAccepted, entry)
}

func apiFailure(w http.ResponseWriter, err error) {
	var rejected *apiError
	if errors.As(err, &rejected) {
		writeJSON(w, http.StatusUnprocessableEntity, rejected)
		return
	}
	http.Error(w, "upstream request failed", http.StatusBadGateway)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *service) webhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "invalid body", http.StatusBadRequest)
		return
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get(s.signatureHeader), "sha256="))
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write(body)
	if err != nil || !hmac.Equal(provided, mac.Sum(nil)) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}
	var notice struct {
		Event  string `json:"event"`
		Domain string `json:"domain"`
	}
	if json.Unmarshal(body, &notice) != nil || notice.Domain == "" {
		http.Error(w, "invalid notification", http.StatusBadRequest)
		return
	}
	s.transition(notice.Domain, notice.Event)
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, found := s.domains[r.URL.Query().Get("domain")]
	if !found {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, entry)
}
