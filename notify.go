package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

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
		safeErr := escapeMarkdown(r.Error.Error())
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
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid telegram url: %w", err)
	}

	token := u.User.String()
	chatParam := u.Query().Get("chats")
	if chatParam == "" {
		return fmt.Errorf("missing 'chats' query param in telegram url")
	}

	var chatID string
	var threadID string
	parts := strings.Split(chatParam, ":")
	chatID = parts[0]
	if len(parts) > 1 {
		threadID = parts[1]
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("*CertGOt Report |* %s\n\n", escapeMarkdown(hostname)))
	for _, r := range results {
		sb.WriteString(formatOneLineMarkdown(r) + "\n")
	}

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       sb.String(),
		"parse_mode": "Markdown",
	}
	if threadID != "" {
		payload["message_thread_id"] = threadID
	}

	jsonBody, _ := json.Marshal(payload)
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var body bytes.Buffer
		_, _ = body.ReadFrom(resp.Body)
		return fmt.Errorf("telegram api error (%d): %s", resp.StatusCode, body.String())
	}

	return nil
}
