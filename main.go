package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

type commonCLIOptions struct {
	ConfigPath string
	Output     OutputFormat
	Color      ColorMode
	Quiet      bool
	Verbose    bool
	LogFormat  string
}

func main() {
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		log.Printf("Run failed: %v", err)
		os.Exit(1)
	}
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	if err := enforceLongOnlySetupFlag(args); err != nil {
		return err
	}
	if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
		return writeHelp(stdout)
	}

	command := "run"
	commandArgs := args
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = strings.ToLower(args[0])
		commandArgs = args[1:]
	} else if containsArg(args, "--setup") {
		command = "setup"
		commandArgs = withoutArgs(args, "--setup")
	} else if containsArg(args, "--version") || containsArg(args, "-v") {
		command = "version"
		commandArgs = withoutArgs(args, "--version", "-v")
		commandArgs = append(commandArgs, "--short")
	}

	var err error
	switch command {
	case "run":
		err = runCommandCLI(commandArgs, stdout, stderr)
	case "setup":
		err = setupCommandCLI(commandArgs, stderr)
	case "doctor":
		err = doctorCommandCLI(commandArgs, stdout, stderr)
	case "status":
		err = statusCommandCLI(commandArgs, stdout, stderr)
	case "renew":
		err = renewCommandCLI(commandArgs, stdout, stderr)
	case "init":
		err = initCommandCLI(commandArgs, os.Stdin, stdout, stderr)
	case "version":
		err = versionCommandCLI(commandArgs, stdout, stderr)
	default:
		return fmt.Errorf("unknown command %q; use --help", command)
	}
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	return err
}

func runCommandCLI(args []string, stdout, stderr io.Writer) error {
	common, remaining, err := parseCommonFlags("run", args, stderr, nil)
	if err != nil {
		return err
	}
	if len(remaining) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(remaining, " "))
	}
	logger, err := newLogger(common.LogFormat, stderr, common.Verbose)
	if err != nil {
		return err
	}
	return runAppWithOptions(common.ConfigPath, RunOptions{Render: RenderOptions{Format: common.Output, Color: common.Color, Quiet: common.Quiet}, Verbose: common.Verbose}, stdout, logger)
}

func setupCommandCLI(args []string, stderr io.Writer) error {
	opts, err := parseSetupOptions(args, stderr)
	if err != nil {
		return err
	}
	return runSystemdWizard(opts.configPath, opts.interval, opts.yes, opts.nonInteractive)
}

type setupOptions struct {
	configPath     string
	interval       string
	yes            bool
	nonInteractive bool
}

func parseSetupOptions(args []string, stderr io.Writer) (setupOptions, error) {
	flags := flag.NewFlagSet("setup", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", defaultConfigPath(), "Path to config")
	configShort := flags.String("c", "", "Path to config")
	interval := flags.String("setup-interval", "", "Timer interval, for example 2w")
	nonInteractive := flags.Bool("non-interactive", false, "Require explicit flags; do not read stdin or run sudo")
	yes := flags.Bool("yes", false, "Confirm setup choices")
	if err := flags.Parse(args); err != nil {
		return setupOptions{}, err
	}
	if strings.TrimSpace(*configShort) != "" {
		configPath = configShort
	}
	return setupOptions{configPath: *configPath, interval: *interval, yes: *yes, nonInteractive: *nonInteractive}, nil
}

func doctorCommandCLI(args []string, stdout, stderr io.Writer) error {
	var offline bool
	common, remaining, err := parseCommonFlags("doctor", args, stderr, func(flags *flag.FlagSet) {
		flags.BoolVar(&offline, "offline", false, "Skip network and systemd checks")
	})
	if err != nil {
		return err
	}
	if len(remaining) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(remaining, " "))
	}
	return runDoctor(common.ConfigPath, DoctorOptions{Render: RenderOptions{Format: common.Output, Color: common.Color, Quiet: common.Quiet}, Offline: offline}, stdout)
}

func statusCommandCLI(args []string, stdout, stderr io.Writer) error {
	var domain string
	common, remaining, err := parseCommonFlags("status", args, stderr, func(flags *flag.FlagSet) {
		flags.StringVar(&domain, "domain", "", "Show one configured domain")
	})
	if err != nil {
		return err
	}
	if len(remaining) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(remaining, " "))
	}
	return runStatus(common.ConfigPath, domain, RenderOptions{Format: common.Output, Color: common.Color, Quiet: common.Quiet}, stdout)
}

func renewCommandCLI(args []string, stdout, stderr io.Writer) error {
	var domain string
	var all, force, dryRun, staging bool
	common, remaining, err := parseCommonFlags("renew", args, stderr, func(flags *flag.FlagSet) {
		flags.StringVar(&domain, "domain", "", "Renew one configured domain")
		flags.BoolVar(&all, "all", false, "Renew all configured domains")
		flags.BoolVar(&force, "force", false, "Force renewal")
		flags.BoolVar(&dryRun, "dry-run", false, "Inspect without ACME or storage writes")
		flags.BoolVar(&staging, "staging", false, "Use the ACME staging directory")
	})
	if err != nil {
		return err
	}
	if len(remaining) > 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(remaining, " "))
	}
	if domain == "" && !all {
		return fmt.Errorf("renew requires --domain or --all")
	}
	if domain != "" && all {
		return fmt.Errorf("renew accepts either --domain or --all, not both")
	}
	logger, err := newLogger(common.LogFormat, stderr, common.Verbose)
	if err != nil {
		return err
	}
	return runRenew(common.ConfigPath, domain, all, force, dryRun, staging, RenderOptions{Format: common.Output, Color: common.Color, Quiet: common.Quiet}, stdout, logger)
}

func versionCommandCLI(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	short := flags.Bool("short", false, "Print only the version")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *short {
		_, err := fmt.Fprintf(stdout, "certgot %s\n", version)
		return err
	}
	_, err := fmt.Fprintf(stdout, "certgot %s\ncommit: %s\nbuilt: %s\ngo: %s\n", version, commit, buildTime, runtime.Version())
	return err
}

func parseCommonFlags(name string, args []string, stderr io.Writer, register func(*flag.FlagSet)) (commonCLIOptions, []string, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	common := commonCLIOptions{}
	flags.StringVar(&common.ConfigPath, "config", defaultConfigPath(), "Path to config")
	flags.StringVar(&common.ConfigPath, "c", defaultConfigPath(), "Path to config")
	output := flags.String("output", "text", "Output format: text or json")
	color := flags.String("color", "auto", "Color mode: auto, always, or never")
	flags.BoolVar(&common.Quiet, "quiet", false, "Suppress human-readable output")
	flags.BoolVar(&common.Verbose, "verbose", false, "Enable verbose diagnostics")
	flags.StringVar(&common.LogFormat, "log-format", "text", "Log format: text or json")
	if register != nil {
		register(flags)
	}
	if err := flags.Parse(args); err != nil {
		return common, nil, err
	}
	var err error
	common.Output, err = parseOutputFormat(*output)
	if err != nil {
		return common, nil, err
	}
	common.Color, err = parseColorMode(*color)
	if err != nil {
		return common, nil, err
	}
	common.LogFormat, err = parseLogFormat(common.LogFormat)
	if err != nil {
		return common, nil, err
	}
	return common, flags.Args(), nil
}

func containsArg(args []string, wanted string) bool {
	for _, arg := range args {
		if arg == wanted {
			return true
		}
	}
	return false
}

func withoutArgs(args []string, excluded ...string) []string {
	set := make(map[string]struct{}, len(excluded))
	for _, value := range excluded {
		set[value] = struct{}{}
	}
	result := make([]string, 0, len(args))
	for _, arg := range args {
		if _, excluded := set[arg]; !excluded {
			result = append(result, arg)
		}
	}
	return result
}

func writeHelp(w io.Writer) error {
	_, err := fmt.Fprint(w, `certgot - ACME DNS certificate operator

Usage:
  certgot run [--config config.yml]
  certgot init [--config config.yml]
  certgot doctor [--config config.yml] [--output text|json]
  certgot status [--config config.yml] [--domain example.com] [--output text|json]
  certgot renew --domain example.com [--dry-run|--force]
  certgot renew --all [--dry-run|--force]
  certgot setup --config config.yml --setup-interval 2w --yes
  certgot version [--short]

Legacy aliases:
  certgot --config config.yml   is certgot run
  certgot --setup                is certgot setup
  certgot --version              is certgot version

Common flags: --output, --color, --quiet, --verbose, --log-format
`)
	return err
}

func enforceLongOnlySetupFlag(args []string) error {
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, "-setup") && !strings.HasPrefix(trimmed, "--setup") {
			return fmt.Errorf("use --setup (single-dash -setup is not supported)")
		}
	}
	return nil
}
