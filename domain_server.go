package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	key := os.Getenv("INFRAI_API_KEY")
	secret := os.Getenv("INFRAI_WEBHOOK_SECRET")
	url := os.Getenv("PUBLIC_WEBHOOK_URL")
	event := os.Getenv("INFRAI_VERIFIED_EVENT")
	header := os.Getenv("INFRAI_SIGNATURE_HEADER")
	if key == "" || secret == "" || url == "" || event == "" || header == "" {
		log.Fatal("set INFRAI_API_KEY, INFRAI_WEBHOOK_SECRET, PUBLIC_WEBHOOK_URL, INFRAI_VERIFIED_EVENT, INFRAI_SIGNATURE_HEADER")
	}
	api := client{key: key, base: baseURL, http: &http.Client{Timeout: 10 * time.Second}}
	// DNS onboarding and account webhook registration share one credential and base URL.
	if err := api.call(context.Background(), http.MethodPost, "/v1/account/webhooks/register", map[string]any{
		"url": url, "events": []string{event}, "secret": secret,
	}, "fintech-domain-verification-webhook", nil); err != nil {
		log.Fatal(err)
	}
	s := &service{api: api, secret: []byte(secret), event: event, signatureHeader: header, domains: make(map[string]onboarding)}
	mux := http.NewServeMux()
	mux.HandleFunc("/domains", s.onboard)
	mux.HandleFunc("/domains/status", s.status)
	mux.HandleFunc("/payments", s.payment)
	mux.HandleFunc("/webhooks/verification", s.webhook)
	log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))
}
