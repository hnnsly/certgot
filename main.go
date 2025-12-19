package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"gopkg.in/yaml.v3"
)

// --- Config Structs ---
type Config struct {
	Email        string       `yaml:"email"`
	TelegramURL  string       `yaml:"telegram_url"`
	StoragePath  string       `yaml:"storage_path"`
	Certificates []CertConfig `yaml:"certificates"`
}

type CertConfig struct {
	Domain      string            `yaml:"domain"`
	Provider    string            `yaml:"provider"`
	Env         map[string]string `yaml:"env"`
	Permissions string            `yaml:"permissions"`
	Group       string            `yaml:"group"`
}

// --- Report Structs ---
type ResultType int

const (
	ResultSuccess ResultType = iota
	ResultValid
	ResultError
)

type CheckResult struct {
	Type     ResultType
	Domain   string
	DaysLeft int
	Until    time.Time
	Error    error
}

// --- ACME User ---
type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string                        { return u.Email }
func (u *MyUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *MyUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// --- Main ---

func main() {
	configPath := flag.String("config", "config.yaml", "Path to the config")
	setupMode := flag.Bool("setup", false, "Run the Systemd unit creation wizard")
	flag.Parse()

	if *setupMode {
		runSystemdWizard(*configPath)
		return
	}

	absConfigPath, _ := filepath.Abs(*configPath)
	cfg, err := loadConfig(absConfigPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	// Init Directories
	certDir := filepath.Join(cfg.StoragePath, "certs")
	accountDir := filepath.Join(cfg.StoragePath, "accounts")
	os.MkdirAll(certDir, 0755)
	os.MkdirAll(accountDir, 0700)

	// Init User & Lego
	user, err := getOrCreateUser(cfg.Email, accountDir)
	if err != nil {
		log.Fatalf("User error: %v", err)
	}
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = lego.LEDirectoryProduction
	legoConfig.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		log.Fatalf("Client error: %v", err)
	}
	if user.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			log.Fatalf("Registration error: %v", err)
		}
		user.Registration = reg
	}

	// Process
	var results []CheckResult
	for _, certCfg := range cfg.Certificates {
		res := processDomain(client, certCfg, certDir)
		results = append(results, res)
		fmt.Println(formatOneLineConsole(res))
	}

	// Send Report
	if err := sendTelegramDirect(cfg.TelegramURL, results); err != nil {
		log.Printf("Failed to send telegram: %v", err)
	} else {
		log.Println("Report sent to Telegram")
	}
}

// --- Logic ---

func processDomain(client *lego.Client, cfg CertConfig, certDir string) CheckResult {
	domainDir := filepath.Join(certDir, cfg.Domain)
	os.MkdirAll(domainDir, 0755)

	pemPath := filepath.Join(domainDir, "fullchain.pem")

	daysLeft, expiry, exists := checkCertFile(pemPath)
	if exists && daysLeft > 30 {
		return CheckResult{Type: ResultValid, Domain: cfg.Domain, DaysLeft: daysLeft, Until: expiry}
	}

	// Set ENV
	for k, v := range cfg.Env {
		os.Setenv(k, v)
	}
	defer func() {
		for k := range cfg.Env {
			os.Unsetenv(k)
		}
	}()

	provider, err := dns.NewDNSChallengeProviderByName(cfg.Provider)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	request := certificate.ObtainRequest{
		Domains: []string{cfg.Domain, "*." + cfg.Domain},
		Bundle:  true,
	}

	certs, err := client.Certificate.Obtain(request)
	if err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: err}
	}

	if err := saveToDisk(domainDir, cfg.Domain, certs, cfg); err != nil {
		return CheckResult{Type: ResultError, Domain: cfg.Domain, Error: fmt.Errorf("save failed: %w", err)}
	}

	newDays, newExpiry, _ := checkCertFile(pemPath)
	return CheckResult{Type: ResultSuccess, Domain: cfg.Domain, DaysLeft: newDays, Until: newExpiry}
}

func checkCertFile(path string) (int, time.Time, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, time.Time{}, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return 0, time.Time{}, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return 0, time.Time{}, false
	}
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
	return daysLeft, cert.NotAfter, true
}

func saveToDisk(dir, domain string, certs *certificate.Resource, cfg CertConfig) error {
	pemPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	fullChain := append(certs.Certificate, certs.IssuerCertificate...)
	if err := os.WriteFile(pemPath, fullChain, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		return err
	}

	// Apply file access control (permissions and group)
	if err := applyFileAccess(dir, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", dir, err)
	}
	if err := applyFileAccess(pemPath, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", pemPath, err)
	}
	if err := applyFileAccess(keyPath, cfg); err != nil {
		log.Printf("Warning: could not apply access control to %s: %v", keyPath, err)
	}

	return nil
}

// applyFileAccess applies permissions and group ownership to a certificate file
func applyFileAccess(path string, cfg CertConfig) error {
	// Apply permissions if specified
	if cfg.Permissions != "" {
		mode, err := strconv.ParseUint(cfg.Permissions, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid permissions format '%s': %w", cfg.Permissions, err)
		}
		if err := os.Chmod(path, os.FileMode(mode)); err != nil {
			return fmt.Errorf("chmod failed: %w", err)
		}
	}

	// Apply group ownership if specified
	if cfg.Group != "" {
		// Get current owner
		stat, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat failed: %w", err)
		}

		// Get group ID by name
		grp, err := user.LookupGroup(cfg.Group)
		if err != nil {
			return fmt.Errorf("group '%s' not found: %w", cfg.Group, err)
		}

		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			return fmt.Errorf("invalid group id: %w", err)
		}

		// Get current uid from stat
		uid := int(stat.Sys().(*syscall.Stat_t).Uid)

		// Change group ownership
		if err := os.Chown(path, uid, gid); err != nil {
			return fmt.Errorf("chown failed: %w", err)
		}
	}

	return nil
}

// --- Formatting & Notification (Direct API) ---

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

// escapeMarkdown escapes special characters in Legacy Markdown
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
		// Escape error text as it may contain underscores (e.g., acme_challenge)
		safeErr := escapeMarkdown(r.Error.Error())

		// Format as a quote
		errLines := strings.Split(safeErr, "\n")
		var quotedErr strings.Builder
		for _, line := range errLines {
			quotedErr.WriteString(fmt.Sprintf("> %s\n", line))
		}
		return fmt.Sprintf("❌ *Certificate error:* %s\n%s", safeDomain, quotedErr.String())
	}
	return ""
}

// sendTelegramDirect parses shoutrrr-style URL and sends a direct request to the Telegram API
func sendTelegramDirect(rawURL string, results []CheckResult) error {
	// 1. Parse URL: telegram://TOKEN@telegram?chats=CHAT_ID
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid telegram url: %w", err)
	}

	token := u.User.String() // This is the "TOKEN" part before @telegram

	chatParam := u.Query().Get("chats")
	if chatParam == "" {
		return fmt.Errorf("missing 'chats' query param in telegram url")
	}

	// Extract chat_id and message_thread_id (if present)
	var chatID string
	var threadID string
	parts := strings.Split(chatParam, ":")
	chatID = parts[0]
	if len(parts) > 1 {
		threadID = parts[1]
	}

	// 2. Build the message
	var sb strings.Builder
	sb.WriteString("*CertGOt Report*\n\n")
	for _, r := range results {
		sb.WriteString(formatOneLineMarkdown(r) + "\n")
	}
	messageText := sb.String()

	// 3. Send JSON request
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	payload := map[string]interface{}{
		"chat_id":    chatID,
		"text":       messageText,
		"parse_mode": "Markdown", // Legacy Markdown
	}

	// Add message_thread_id if present
	if threadID != "" {
		payload["message_thread_id"] = threadID
	}

	jsonBody, _ := json.Marshal(payload)

	resp, err := http.Post(apiURL, "application/json", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("http post failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read the response to understand the error
		var body bytes.Buffer
		body.ReadFrom(resp.Body)
		return fmt.Errorf("telegram api error (%d): %s", resp.StatusCode, body.String())
	}

	return nil
}

// --- Helpers ---
func loadConfig(path string) (*Config, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = yaml.Unmarshal(f, &cfg)
	return &cfg, err
}

func getOrCreateUser(email, dir string) (*MyUser, error) {
	keyFile := filepath.Join(dir, "account.key")
	var privateKey crypto.PrivateKey
	if keyBytes, err := os.ReadFile(keyFile); err == nil {
		block, _ := pem.Decode(keyBytes)
		if block != nil {
			privateKey, _ = x509.ParseECPrivateKey(block.Bytes)
		}
	}
	if privateKey == nil {
		newKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		privateKey = newKey
		keyBytes, _ := x509.MarshalECPrivateKey(newKey)
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
		os.WriteFile(keyFile, pemBytes, 0600)
	}
	return &MyUser{Email: email, key: privateKey}, nil
}

// --- Systemd Wizard ---

const serviceTpl = `[Unit]
Description=ACME DNS certGOt
After=network.target

[Service]
Type=oneshot
User={{.User}}
WorkingDirectory={{.WorkDir}}
ExecStart={{.BinPath}} -config {{.ConfigPath}}

[Install]
WantedBy=multi-user.target
`

const timerTpl = `[Unit]
Description=ACME DNS certGOt daily

[Timer]
OnCalendar={{.Schedule}}
Persistent=true

[Install]
WantedBy=timers.target
`

func runSystemdWizard(configRelPath string) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("🛠  Setup wizard for CertGOt Systemd")
	fmt.Println("----------------------------")

	binPath, _ := os.Executable()
	workDir, _ := os.Getwd()
	absConfigPath, _ := filepath.Abs(configRelPath)
	currentUser, _ := user.Current()

	fmt.Printf("Binary: %s\n", binPath)
	fmt.Printf("User:  %s\n", currentUser.Username)
	fmt.Println("----------------------------")

	fmt.Println("How often should the check run?")
	fmt.Println("💡 Tip: The application automatically checks the certificate's expiration date.")
	fmt.Println("   Running it daily is safe and consumes minimal resources.")
	fmt.Println("")
	fmt.Println("Examples of schedules (systemd OnCalendar):")
	fmt.Println(" - daily        (Once a day at 00:00)")
	fmt.Println(" - 04:00        (Once a day at 04:00 — recommended)")
	fmt.Println(" - weekly       (Once a week, on Monday)")
	fmt.Println(" - Mon,Fri 04:00 (Twice a week: Mon and Fri at 04:00)")
	fmt.Println("")

	fmt.Print("Enter schedule [default: daily]: ")
	schedule, _ := reader.ReadString('\n')
	schedule = strings.TrimSpace(schedule)
	if schedule == "" {
		schedule = "daily"
	}

	data := map[string]string{
		"User": currentUser.Username, "WorkDir": workDir,
		"BinPath": binPath, "ConfigPath": absConfigPath, "Schedule": schedule,
	}

	fmt.Printf("\n✅ Files generated! Execute the following commands (as root):\n\n")

	// We use printf with quotes for heredoc or just echo
	// Note: For the systemd timer, it's important that User is in the .service, not the .timer

	serviceCmd := fmt.Sprintf("cat <<EOF > /etc/systemd/system/certgot.service\n%sEOF", renderTpl(serviceTpl, data))
	timerCmd := fmt.Sprintf("cat <<EOF > /etc/systemd/system/certgot.timer\n%sEOF", renderTpl(timerTpl, data))

	fmt.Println(serviceCmd)
	fmt.Println("")
	fmt.Println(timerCmd)

	fmt.Println("\n# After creating the files:")
	fmt.Println("systemctl daemon-reload")
	fmt.Println("systemctl enable --now certgot.timer")
	fmt.Println("systemctl list-timers --all | grep certgot")
}

func renderTpl(tplStr string, data map[string]string) string {
	t, _ := template.New("t").Parse(tplStr)
	var sb strings.Builder
	t.Execute(&sb, data)
	return sb.String()
}

func escapeEcho(s string) string {
	return strings.ReplaceAll(s, "\n", "\\n")
}
