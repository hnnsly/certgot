package main

import (
	"flag"
	"log"
	"os"
	"strings"
)

func main() {
	enforceLongOnlySetupFlag(os.Args[1:])

	configPath := flag.String("config", "config.yaml", "Path to the config (alias: -c)")
	configPathShort := flag.String("c", "", "Path to the config (shorthand for --config)")
	setupMode := flag.Bool("setup", false, "Run the Systemd unit creation wizard")
	flag.Parse()

	if strings.TrimSpace(*configPathShort) != "" {
		configPath = configPathShort
	}

	if *setupMode {
		runSystemdWizard(*configPath)
		return
	}

	if err := runApp(*configPath); err != nil {
		log.Fatalf("Run failed: %v", err)
	}
}

func enforceLongOnlySetupFlag(args []string) {
	for _, arg := range args {
		trimmed := strings.TrimSpace(arg)
		if strings.HasPrefix(trimmed, "-setup") && !strings.HasPrefix(trimmed, "--setup") {
			log.Fatalf("Use --setup (single-dash -setup is not supported)")
		}
	}
}
