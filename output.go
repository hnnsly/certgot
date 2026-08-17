package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

type OutputFormat string

const (
	OutputText OutputFormat = "text"
	OutputJSON OutputFormat = "json"
)

type ColorMode string

const (
	ColorAuto   ColorMode = "auto"
	ColorAlways ColorMode = "always"
	ColorNever  ColorMode = "never"
)

type RenderOptions struct {
	Format OutputFormat
	Color  ColorMode
	Quiet  bool
}

type RunRecord struct {
	Domain   string `json:"domain"`
	Status   string `json:"status"`
	DaysLeft int    `json:"days_left,omitempty"`
	Expiry   string `json:"expiry,omitempty"`
	Error    string `json:"error,omitempty"`
}

type RunReport struct {
	Operation    string         `json:"operation"`
	Mode         string         `json:"mode,omitempty"`
	Results      []RunRecord    `json:"results"`
	Reloads      []ReloadRecord `json:"reloads,omitempty"`
	Summary      Summary        `json:"summary"`
	Duration     string         `json:"duration"`
	Notification string         `json:"notification,omitempty"`
}

type ReloadRecord struct {
	Domain string `json:"domain"`
	Unit   string `json:"unit"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type Summary struct {
	Checked int `json:"checked"`
	Valid   int `json:"valid"`
	Renewed int `json:"renewed"`
	Skipped int `json:"skipped"`
	Failed  int `json:"failed"`
}

type DoctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Message     string `json:"message"`
	Domain      string `json:"domain,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type DoctorReport struct {
	Operation string        `json:"operation"`
	Checks    []DoctorCheck `json:"checks"`
}

type StatusRecord struct {
	Domain      string `json:"domain"`
	Status      string `json:"status"`
	Expiry      string `json:"expiry,omitempty"`
	DaysLeft    int    `json:"days_left,omitempty"`
	Provider    string `json:"provider"`
	ReleasePath string `json:"release_path,omitempty"`
	Error       string `json:"error,omitempty"`
}

type StatusReport struct {
	Operation string         `json:"operation"`
	Mode      string         `json:"mode,omitempty"`
	Results   []StatusRecord `json:"results"`
}

type RenewRecord struct {
	Domain string `json:"domain"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
}

type RenewReport struct {
	Operation string        `json:"operation"`
	Mode      string        `json:"mode,omitempty"`
	Results   []RenewRecord `json:"results"`
}

func parseOutputFormat(raw string) (OutputFormat, error) {
	switch OutputFormat(strings.ToLower(strings.TrimSpace(raw))) {
	case "", OutputText:
		return OutputText, nil
	case OutputJSON:
		return OutputJSON, nil
	default:
		return "", fmt.Errorf("unsupported output %q; use text or json", raw)
	}
}

func parseColorMode(raw string) (ColorMode, error) {
	switch ColorMode(strings.ToLower(strings.TrimSpace(raw))) {
	case "", ColorAuto:
		return ColorAuto, nil
	case ColorAlways, ColorNever:
		return ColorMode(strings.ToLower(raw)), nil
	default:
		return "", fmt.Errorf("unsupported color %q; use auto, always, or never", raw)
	}
}

func writeJSON(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func renderRun(w io.Writer, report RunReport, opts RenderOptions) error {
	opts = normalizeRenderOptions(opts)
	if opts.Format == OutputJSON {
		return writeJSON(w, report)
	}
	if opts.Quiet {
		return nil
	}
	if report.Mode != "" && report.Mode != "production" {
		if _, err := fmt.Fprintf(w, "Mode: %s (isolated state; reload hooks disabled)\n", report.Mode); err != nil {
			return err
		}
	}
	for _, result := range report.Results {
		line := fmt.Sprintf("%s %s", statusSymbol(result.Status), result.Domain)
		if result.DaysLeft > 0 {
			line += fmt.Sprintf(" (%dd left)", result.DaysLeft)
		}
		if result.Error != "" {
			line += ": " + result.Error
		}
		if _, err := fmt.Fprintln(w, colorize(line, result.Status, opts, w)); err != nil {
			return err
		}
	}
	for _, reload := range report.Reloads {
		line := fmt.Sprintf("%s %s: reload %s", statusSymbol(reload.Status), reload.Domain, reload.Unit)
		if reload.Error != "" {
			line += ": " + reload.Error
		}
		if _, err := fmt.Fprintln(w, colorize(line, reload.Status, opts, w)); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%d certificates checked: %d valid, %d renewed, %d skipped, %d failed\n", report.Summary.Checked, report.Summary.Valid, report.Summary.Renewed, report.Summary.Skipped, report.Summary.Failed)
	if err != nil {
		return err
	}
	if report.Notification == "sent" {
		if _, err := fmt.Fprintln(w, "Report sent to Telegram"); err != nil {
			return err
		}
	} else if report.Notification == "failed" {
		if _, err := fmt.Fprintln(w, "Telegram report failed; see stderr for details"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "Completed in %s\n", report.Duration)
	return err
}

func renderDoctor(w io.Writer, report DoctorReport, opts RenderOptions) error {
	opts = normalizeRenderOptions(opts)
	if opts.Format == OutputJSON {
		return writeJSON(w, report)
	}
	if opts.Quiet {
		return nil
	}
	for _, check := range report.Checks {
		line := fmt.Sprintf("%s %s", statusSymbol(check.Status), check.Message)
		if _, err := fmt.Fprintln(w, colorize(line, check.Status, opts, w)); err != nil {
			return err
		}
		if check.Remediation != "" {
			if _, err := fmt.Fprintf(w, "  Fix: %s\n", check.Remediation); err != nil {
				return err
			}
		}
	}
	return nil
}

func renderStatus(w io.Writer, report StatusReport, opts RenderOptions) error {
	opts = normalizeRenderOptions(opts)
	if opts.Format == OutputJSON {
		return writeJSON(w, report)
	}
	if opts.Quiet {
		return nil
	}
	if report.Mode != "" && report.Mode != "production" {
		if _, err := fmt.Fprintf(w, "Mode: %s (isolated state)\n", report.Mode); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintln(w, "DOMAIN\tSTATUS\tEXPIRY\tDAYS\tPROVIDER\tRELEASE"); err != nil {
		return err
	}
	for _, result := range report.Results {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\n", result.Domain, result.Status, result.Expiry, result.DaysLeft, result.Provider, result.ReleasePath); err != nil {
			return err
		}
	}
	return nil
}

func renderRenew(w io.Writer, report RenewReport, opts RenderOptions) error {
	opts = normalizeRenderOptions(opts)
	if opts.Format == OutputJSON {
		return writeJSON(w, report)
	}
	if opts.Quiet {
		return nil
	}
	if report.Mode != "" && report.Mode != "production" {
		if _, err := fmt.Fprintf(w, "Mode: %s (isolated state; reload hooks disabled)\n", report.Mode); err != nil {
			return err
		}
	}
	for _, result := range report.Results {
		line := fmt.Sprintf("%s %s: %s", statusSymbol(result.Status), result.Domain, result.Status)
		if result.Error != "" {
			line += ": " + result.Error
		}
		if _, err := fmt.Fprintln(w, colorize(line, result.Status, opts, w)); err != nil {
			return err
		}
	}
	return nil
}

func statusSymbol(status string) string {
	switch status {
	case "ok", "valid", "renewed", "reloaded", "success":
		return "✓"
	case "warning", "renewal", "skipped", "forced", "would-renew":
		return "!"
	default:
		return "✗"
	}
}

func normalizeRenderOptions(opts RenderOptions) RenderOptions {
	if opts.Format == "" {
		opts.Format = OutputText
	}
	if opts.Color == "" {
		opts.Color = ColorAuto
	}
	return opts
}

func colorize(line, status string, opts RenderOptions, w io.Writer) string {
	if opts.Color == ColorNever || (opts.Color == ColorAuto && !writerIsTTY(w)) {
		return line
	}
	color := "32"
	if status == "warning" || status == "renewal" || status == "skipped" {
		color = "33"
	}
	if status == "error" || status == "failed" || status == "malformed" || status == "key-mismatch" {
		color = "31"
	}
	return "\033[" + color + "m" + line + "\033[0m"
}

func writerIsTTY(w io.Writer) bool {
	if w == nil {
		return false
	}
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func resultStatus(result CheckResult) string {
	if result.Type == ResultSuccess {
		return "renewed"
	}
	if result.Type == ResultValid {
		return "valid"
	}
	return "failed"
}

func certificateStatusName(status certificateStatus) string {
	switch status {
	case certificateMissing:
		return "missing"
	case certificateMalformed:
		return "malformed"
	case certificateNotYetValid:
		return "not-yet-valid"
	case certificateWrongDomain:
		return "wrong-domain"
	case certificateExpiringSoon:
		return "renewal"
	case certificateKeyMismatch:
		return "key-mismatch"
	case certificateValid:
		return "valid"
	default:
		return "error"
	}
}

func formatExpiry(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339)
}
