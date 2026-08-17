package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

var telegramHTTPClient = &http.Client{Timeout: 15 * time.Second}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type NotificationMessageBuilder interface {
	Build(hostname, operation string, results []CheckResult, duration time.Duration) string
}

type telegramMessageBuilder struct{}

func formatOneLineConsole(r CheckResult) string {
	switch r.Type {
	case ResultSuccess:
		return fmt.Sprintf("[ISSUED] %s (%dd left)", r.Domain, r.DaysLeft)
	case ResultValid:
		return fmt.Sprintf("[VALID] %s (%dd left)", r.Domain, r.DaysLeft)
	case ResultError:
		return fmt.Sprintf("[ERROR] %s: %v", r.Domain, r.Error)
	}
	return ""
}

func escapeMarkdown(text string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"`", "\\`",
	)
	return replacer.Replace(text)
}

func formatOneLineMarkdown(r CheckResult) string {
	dateStr := r.Until.Format("02.01.2006")
	safeDomain := escapeMarkdown(r.Domain)

	switch r.Type {
	case ResultSuccess:
		return fmt.Sprintf("✅ *Certificate issued:* %s • %dd until %s", safeDomain, r.DaysLeft, dateStr)
	case ResultValid:
		return fmt.Sprintf("🕒 *Certificate valid:* %s • %dd until %s", safeDomain, r.DaysLeft, dateStr)
	case ResultError:
		errText := "unknown error"
		if r.Error != nil {
			errText = r.Error.Error()
		}
		safeErr := escapeMarkdown(errText)
		errLines := strings.Split(safeErr, "\n")

		var quotedErr strings.Builder
		for _, line := range errLines {
			quotedErr.WriteString(fmt.Sprintf("> %s\n", line))
		}

		return fmt.Sprintf("❌ *Certificate error:* %s\n%s", safeDomain, quotedErr.String())
	}

	return ""
}

func sendTelegramDirect(rawURL string, results []CheckResult) error {
	return sendTelegramReport(rawURL, results, "run", 0)
}

func sendTelegramReport(rawURL string, results []CheckResult, operation string, duration time.Duration) error {
	return sendTelegramReportWith(rawURL, results, operation, duration, telegramHTTPClient, telegramMessageBuilder{})
}

func sendTelegramReportWith(rawURL string, results []CheckResult, operation string, duration time.Duration, transport HTTPDoer, builder NotificationMessageBuilder) error {
	token, chatID, threadID, err := parseTelegramURL(rawURL)
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       builder.Build(hostname, operation, results, duration),
		"parse_mode": "Markdown",
	}
	if threadID != "" {
		payload["message_thread_id"] = threadID
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram request: %w", err)
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	request, err := http.NewRequest(http.MethodPost, apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("build telegram request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	resp, err := transport.Do(request)
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("telegram api returned status %d", resp.StatusCode)
	}

	return nil
}

func (telegramMessageBuilder) Build(hostname, operation string, results []CheckResult, duration time.Duration) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*CertGOt Report |* %s\n\n", escapeMarkdown(hostname)))
	if operation == "" {
		operation = "run"
	}
	sb.WriteString(fmt.Sprintf("*Operation:* %s\n", escapeMarkdown(operation)))
	sb.WriteString(fmt.Sprintf("*Version:* %s\n", escapeMarkdown(version)))
	if duration > 0 {
		sb.WriteString(fmt.Sprintf("*Duration:* %s\n", escapeMarkdown(duration.Round(time.Millisecond).String())))
	}
	sb.WriteString("\n")
	for _, result := range results {
		sb.WriteString(formatOneLineMarkdown(result) + "\n")
		if result.Type == ResultError {
			sb.WriteString(fmt.Sprintf("> Fix: certgot renew --domain %s\n", escapeMarkdown(result.Domain)))
		}
	}
	return sb.String()
}

func parseTelegramURL(rawURL string) (token, chatID, threadID string, err error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", "", "", fmt.Errorf("invalid telegram url: %w", err)
	}
	if u.Scheme != "telegram" || u.User == nil || strings.TrimSpace(u.User.String()) == "" {
		return "", "", "", fmt.Errorf("telegram url must contain a token")
	}

	token = u.User.String()
	chatParam := u.Query().Get("chats")
	if chatParam == "" {
		return "", "", "", fmt.Errorf("missing 'chats' query param in telegram url")
	}

	parts := strings.Split(chatParam, ":")
	if len(parts) > 2 || strings.TrimSpace(parts[0]) == "" || (len(parts) == 2 && strings.TrimSpace(parts[1]) == "") {
		return "", "", "", fmt.Errorf("invalid chats query param")
	}
	chatID = parts[0]
	if len(parts) > 1 {
		threadID = parts[1]
	}

	return token, chatID, threadID, nil
}
