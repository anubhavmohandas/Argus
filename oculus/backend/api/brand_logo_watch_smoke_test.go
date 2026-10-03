package api

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"reconvision/store"
)

func TestBrandLogoWatchPayPalSmoke(t *testing.T) {
	if os.Getenv("RUN_URLSCAN_SMOKE") != "1" {
		t.Skip("set RUN_URLSCAN_SMOKE=1 to run URLScan smoke test")
	}
	if urlscanAPIKey() == "" {
		t.Fatal("URLSCAN_API_KEY is not configured")
	}

	h := NewHandler(store.New())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	brands := []brandWatchBrand{{
		Name:             "PayPal",
		QueryNames:       []string{"PayPal", "paypal"},
		LegitDomains:     []string{"paypal.com", "paypalobjects.com", "paypal-corp.com", "paypal-community.com", "paypal.me", "braintreepayments.com"},
		VerdictThreshold: defaultVerdictFloor,
		PollMinutes:      15,
	}}
	hits, logs, _ := h.collectBrandLogoHits(ctx, brands, 30, 100)
	if len(hits) == 0 {
		t.Fatalf("expected PayPal visible-logo hits, got 0; logs=%+v", logs)
	}
	for _, hit := range hits {
		if hit.Brand != "PayPal" {
			t.Fatalf("unexpected brand %q in hit %+v", hit.Brand, hit)
		}
		if !strings.Contains(strings.ToLower(hit.VisibleBrand), "paypal") {
			t.Fatalf("hit missing PayPal visible brand: %+v", hit)
		}
		if hit.Screenshot == "" {
			t.Fatalf("hit missing screenshot: %+v", hit)
		}
		if hit.LiveStatus != 200 {
			t.Fatalf("hit was not live 200: %+v", hit)
		}
	}
	t.Logf("PayPal strict logo smoke passed: %d hits; first=%s visible=%s confidence=%s", len(hits), hits[0].Domain, hits[0].VisibleBrand, hits[0].Confidence)
}

func TestBrandLogoWatchExnessSmoke(t *testing.T) {
	if os.Getenv("RUN_URLSCAN_SMOKE") != "1" {
		t.Skip("set RUN_URLSCAN_SMOKE=1 to run URLScan smoke test")
	}
	if urlscanAPIKey() == "" {
		t.Fatal("URLSCAN_API_KEY is not configured")
	}

	h := NewHandler(store.New())
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	brands := []brandWatchBrand{{
		Name:             "Exness",
		QueryNames:       []string{"exness"},
		LegitDomains:     []string{"exness.com", "exness.org"},
		VerdictThreshold: defaultVerdictFloor,
		PollMinutes:      15,
	}}
	hits, logs, _ := h.collectBrandLogoHits(ctx, brands, 30, 100)
	if len(hits) == 0 {
		t.Fatalf("expected Exness visible-logo hits, got 0; logs=%+v", logs)
	}
	for _, hit := range hits {
		if hit.Brand != "Exness" {
			t.Fatalf("unexpected brand %q in hit %+v", hit.Brand, hit)
		}
		if !strings.Contains(strings.ToLower(hit.VisibleBrand), "exness") {
			t.Fatalf("hit missing Exness visible brand: %+v", hit)
		}
		if hit.Screenshot == "" {
			t.Fatalf("hit missing screenshot: %+v", hit)
		}
		if hit.LiveStatus != 200 {
			t.Fatalf("hit was not live 200: %+v", hit)
		}
	}
	t.Logf("Exness strict logo smoke passed: %d hits; first=%s visible=%s confidence=%s", len(hits), hits[0].Domain, hits[0].VisibleBrand, hits[0].Confidence)
}
