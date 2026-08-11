package main

import (
	"io"
	"log/slog"
	"strings"
)

func newLogger(format string, w io.Writer, verbose bool) (*slog.Logger, error) {
	format, err := parseLogFormat(format)
	if err != nil {
		return nil, err
	}
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	options := &slog.HandlerOptions{Level: level}
	switch format {
	case "", "text":
		return slog.New(slog.NewTextHandler(w, options)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, options)), nil
	default:
		return nil, &invalidOptionError{field: "log-format", value: format, allowed: "text or json"}
	}
}

func parseLogFormat(raw string) (string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	switch format {
	case "", "text":
		return "text", nil
	case "json":
		return "json", nil
	default:
		return "", &invalidOptionError{field: "log-format", value: raw, allowed: "text or json"}
	}
}

type invalidOptionError struct {
	field   string
	value   string
	allowed string
}

func (e *invalidOptionError) Error() string {
	return e.field + " " + e.value + " is invalid; use " + e.allowed
}
