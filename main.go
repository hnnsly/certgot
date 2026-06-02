package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
)

var version = "dev"

func main() {
	enforceLongOnlySetupFlag(os.Args[1:])

	configPath := flag.String("config", "config.yaml", "Path to the config (alias: -c)")
	configPathShort := flag.String("c", "", "Path to the config (shorthand for --config)")
	setupMode := flag.Bool("setup", false, "Run the Systemd unit creation wizard")
	versionMode := flag.Bool("version", false, "Print version and exit (alias: -v)")
	versionModeShort := flag.Bool("v", false, "Print version and exit (shorthand for --version)")
	flag.Parse()

	if *versionMode || *versionModeShort {
		fmt.Printf("certgot %s\n", version)
		return
	}

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
