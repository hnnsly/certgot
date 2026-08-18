package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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

func sendTelegramReport(config TelegramConfig, results []CheckResult, operation string, duration time.Duration) error {
	return sendTelegramReportWith(config, results, operation, duration, telegramHTTPClient, telegramMessageBuilder{})
}

func sendTelegramReportWith(config TelegramConfig, results []CheckResult, operation string, duration time.Duration, transport HTTPDoer, builder NotificationMessageBuilder) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	payload := map[string]interface{}{
		"chat_id":    config.ChatID,
		"text":       builder.Build(hostname, operation, results, duration),
		"parse_mode": "Markdown",
	}
	if config.TopicID != 0 {
		payload["message_thread_id"] = config.TopicID
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal telegram request: %w", err)
	}
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", config.BotToken)

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
