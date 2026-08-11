package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type recordingHTTPDoer struct {
	request *http.Request
	body    []byte
}

func (doer *recordingHTTPDoer) Do(request *http.Request) (*http.Response, error) {
	doer.request = request
	data, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	doer.body = data
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"ok":true}`))}, nil
}

func TestTelegramTransportAndMessageBuilderAreInjectable(t *testing.T) {
	doer := &recordingHTTPDoer{}
	results := []CheckResult{{Type: ResultError, Domain: "example.com", Error: io.EOF}}
	err := sendTelegramReportWith("telegram://token@telegram?chats=123", results, "renew", 2*time.Second, doer, telegramMessageBuilder{})
	if err != nil {
		t.Fatal(err)
	}
	if doer.request == nil || doer.request.URL.String() != "https://api.telegram.org/bottoken/sendMessage" {
		t.Fatalf("unexpected request: %#v", doer.request)
	}
	var payload map[string]any
	if err := json.Unmarshal(doer.body, &payload); err != nil {
		t.Fatal(err)
	}
	message, _ := payload["text"].(string)
	for _, want := range []string{"*Operation:* renew", "*Duration:* 2s", "Fix: certgot renew --domain example.com"} {
		if !strings.Contains(message, want) {
			t.Fatalf("message missing %q: %s", want, message)
		}
	}
}
