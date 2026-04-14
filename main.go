package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"securewrapper/connections"

	tea "github.com/charmbracelet/bubbletea"
)

var version = "0.1.0-dev"
var buildDate = "unknown"

func main() {
	args := os.Args[1:]

	// Handle --help
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		printHelp()
		return
	}

	// Handle --version
	if hasFlag(args, "--version") {
		fmt.Printf("SecureWrapper v%s\n", version)
		fmt.Printf("Built:               %s\n", buildDate)
		fmt.Printf("Machine fingerprint: %s\n", ShortFingerprint())
		fmt.Printf("Binary fingerprint:  %s\n", BinaryKeyFingerprint())
		return
	}

	// Handle --list — works with auth key or passphrase
	if hasFlag(args, "--list") {
		if !VaultExists() {
			fmt.Println("No vault found.")
			return
		}
		// Try auth key first (env var, --key-file, --key)
		authKey := os.Getenv("WRAPPER_AUTH_KEY")
		if authKey == "" {
			if kf, _ := extractFlag(args, "--key-file"); kf != "" {
				if data, err := os.ReadFile(kf); err == nil {
					authKey = strings.TrimSpace(string(data))
				}
			}
		}
		if authKey == "" {
			authKey, _ = extractFlag(args, "--key")
		}

		var vault *Vault
		var err error
		if authKey != "" {
			vault, err = OpenVaultWithAuthKey(authKey)
		} else {
			passphrase := readPassword("Vault passphrase: ")
			vault, err = OpenVault(passphrase)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		for _, c := range vault.ListConnections() {
			fmt.Println(c.Name)
		}
		return
	}

	// Check for --sys flag (connection mode)
	sysName, _ := extractFlag(args, "--sys")
	if sysName != "" {
		runConnection(args)
		return
	}

	// No flags — interactive mode
	runInteractive()
}

func runBubbletea(vault *Vault) {
	for {
		p := tea.NewProgram(NewApp(vault), tea.WithAltScreen())
		model, err := p.Run()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if app, ok := model.(App); ok {
			if app.upgradeRequested {
				upgradeScreen(vault)
				continue // restart TUI after upgrade
			}
			if app.restoreCompleted {
				fmt.Println()
				passphrase := printPasswordPrompt("Vault passphrase to restore backup:")
				restoredVault, err := RestoreVault(passphrase)
				if err != nil {
					printError(fmt.Sprintf("Restore failed: %v", err))
					pause()
					continue // back to TUI
				}
				printSuccess("Vault restored from backup!")
				pause()
				vault = restoredVault
				continue // restart TUI with restored vault
			}
		}
		break // normal quit
	}
}

// Mode flags — the third wrapper flag that determines transport
var modeFlagList = []string{"--ssh", "--scp", "--sftp", "--rsync", "--api", "--db", "--winrm", "--test", "--ssh-proxy", "--creds"}

func runConnection(args []string) {
	// Parse the wrapper flags: --key, --key-file, --sys, --mode
	// Everything after these three is raw passthrough
	authKey, _ := extractFlag(args, "--key")
	keyFile, _ := extractFlag(args, "--key-file")
	sysName, _ := extractFlag(args, "--sys")

	// Auth key resolution: env var > --key-file > --key (with warning)
	if envKey := os.Getenv("WRAPPER_AUTH_KEY"); envKey != "" {
		authKey = envKey
	} else if keyFile != "" {
		data, err := os.ReadFile(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot read key file: %v\n", err)
			os.Exit(1)
		}
		authKey = strings.TrimSpace(string(data))
	} else if authKey != "" {
		fmt.Fprintf(os.Stderr, "Warning: --key exposes the auth key in process listings. Use WRAPPER_AUTH_KEY env var or --key-file instead.\n")
	}
	mode := ""

	// Find the mode flag and determine where passthrough starts
	passthroughStart := -1
	for i, arg := range args {
		for _, mf := range modeFlagList {
			if arg == mf {
				mode = arg[2:] // strip "--"
				passthroughStart = i + 1
				break
			}
		}
		if mode != "" {
			break
		}
	}

	if mode == "" {
		fmt.Fprintf(os.Stderr, "Error: mode flag required.\n")
		fmt.Fprintf(os.Stderr, "Usage: wrapper --key <key> --sys <name> --ssh <command>\n")
		fmt.Fprintf(os.Stderr, "Modes: --ssh, --scp, --sftp, --rsync, --api, --test\n")
		os.Exit(1)
	}

	// Everything after the mode flag is passthrough
	var passthrough []string
	if passthroughStart > 0 && passthroughStart < len(args) {
		passthrough = args[passthroughStart:]
	}

	// Open vault using auth key
	if authKey == "" {
		fmt.Fprintf(os.Stderr, "Error: --key (or WRAPPER_AUTH_KEY or --key-file) is required.\n")
		os.Exit(1)
	}

	// Check vault compatibility before attempting auth
	if compatible, reason := CheckVaultCompatibility(); !compatible {
		fmt.Fprintf(os.Stderr, "Error: %s\n", reason)
		os.Exit(1)
	}

	// Rate limit auth key attempts (but never auto-wipe — that's only for interactive)
	ad := loadAttempts()
	if ad.Count > 0 {
		delay := backoffDelay(ad.Count)
		time.Sleep(delay)
	}

	vault, err := OpenVaultWithAuthKey(authKey)
	if err != nil {
		incrementAttempts()
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	resetAttempts()

	// Find connection
	conn := vault.GetConnection(sysName)
	if conn == nil {
		fmt.Fprintf(os.Stderr, "Error: connection \"%s\" not found.\n", sysName)
		os.Exit(1)
	}

	// Execute based on mode
	var result connections.Result

	switch mode {
	case "test":
		fmt.Print("Testing... ")
		if err := testConn(*conn); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("OK")
		return

	case "ssh":
		// passthrough: [flags...] [command]
		var flags []string
		var command string
		for _, arg := range passthrough {
			if strings.HasPrefix(arg, "-") && command == "" {
				flags = append(flags, arg)
			} else {
				if command == "" {
					command = arg
				} else {
					command += " " + arg
				}
			}
		}
		result = ExecuteConnectionSSH(*conn, flags, command)

	case "scp":
		// passthrough: [flags...] source dest
		result = ExecuteConnectionSCP(*conn, passthrough)

	case "sftp":
		// passthrough: [flags...] [batch commands]
		result = ExecuteConnectionSFTP(*conn, passthrough)

	case "rsync":
		// passthrough: [flags...] source dest
		result = ExecuteConnectionRsync(*conn, passthrough)

	case "creds":
		// Output connection credentials as JSON — for other tools (MCP servers) to consume
		// Only outputs non-sensitive metadata + credentials needed by the calling tool
		credOutput := map[string]string{
			"name": conn.Name,
			"type": string(conn.Type),
		}
		switch conn.Type {
		case ConnSSHPassword:
			credOutput["host"] = conn.Host
			credOutput["port"] = fmt.Sprintf("%d", conn.Port)
			credOutput["username"] = conn.Username
			credOutput["password"] = conn.Password
		case ConnSSHKey:
			credOutput["host"] = conn.Host
			credOutput["port"] = fmt.Sprintf("%d", conn.Port)
			credOutput["username"] = conn.Username
			credOutput["key_path"] = conn.KeyPath
			credOutput["key_passphrase"] = conn.KeyPass
		case ConnAPI:
			credOutput["base_url"] = conn.BaseURL
			credOutput["auth_type"] = conn.AuthType
			credOutput["auth_header"] = conn.AuthHeader
			credOutput["auth_value"] = conn.AuthValue
			if conn.TOTPSecret != "" {
				credOutput["totp_secret"] = conn.TOTPSecret
			}
			if conn.ExtraField != "" {
				credOutput["extra_field"] = conn.ExtraField
			}
			credOutput["insecure"] = fmt.Sprintf("%v", conn.Insecure)
		case ConnFTP:
			credOutput["host"] = conn.Host
			credOutput["port"] = fmt.Sprintf("%d", conn.Port)
			credOutput["username"] = conn.Username
			credOutput["password"] = conn.Password
		case ConnDBPostgres, ConnDBMySQL, ConnDBMSSQL:
			credOutput["driver"] = dbDriverForType(conn.Type)
			credOutput["host"] = conn.Host
			credOutput["port"] = fmt.Sprintf("%d", conn.Port)
			credOutput["username"] = conn.Username
			credOutput["password"] = conn.Password
			credOutput["database"] = conn.Database
			credOutput["ssl_mode"] = conn.SSLMode
		case ConnWinRM:
			credOutput["host"] = conn.Host
			credOutput["port"] = fmt.Sprintf("%d", conn.Port)
			credOutput["username"] = conn.Username
			credOutput["password"] = conn.Password
			credOutput["use_https"] = fmt.Sprintf("%v", conn.UseHTTPS)
			credOutput["insecure"] = fmt.Sprintf("%v", conn.Insecure)
		}
		jsonBytes, _ := json.MarshalIndent(credOutput, "", "  ")
		fmt.Println(string(jsonBytes))
		return

	case "ssh-proxy":
		// SSH proxy mode — used by rsync as its -e transport
		// Rsync passes: host command...
		// We ignore the host (we already know it from --sys) and run the command
		// Password never leaves Go's memory
		proxyCmd := ""
		if len(passthrough) > 1 {
			// First arg is the host rsync passes, rest is the command
			proxyCmd = strings.Join(passthrough[1:], " ")
		} else if len(passthrough) == 1 {
			proxyCmd = passthrough[0]
		}
		result = ExecuteConnectionSSHProxy(*conn, proxyCmd)

	case "api":
		// passthrough: METHOD /path [body]
		method := "GET"
		path := "/"
		body := ""
		if len(passthrough) > 0 {
			method = passthrough[0]
		}
		if len(passthrough) > 1 {
			path = passthrough[1]
		}
		if len(passthrough) > 2 {
			body = strings.Join(passthrough[2:], " ")
		}
		result = connections.ExecuteAPI(conn.BaseURL, conn.AuthType, conn.AuthHeader, conn.AuthValue, conn.Headers, conn.Insecure, method, path, body)

	case "db":
		// passthrough: the SQL query (joined with spaces to allow unquoted multi-word queries)
		query := strings.Join(passthrough, " ")
		result = ExecuteConnectionDB(*conn, query)

	case "winrm":
		// passthrough: the PowerShell command (joined so "Get-Service wuauserv" works unquoted)
		command := strings.Join(passthrough, " ")
		result = ExecuteConnectionWinRM(*conn, command)

	default:
		fmt.Fprintf(os.Stderr, "Error: unknown mode \"--%s\"\n", mode)
		os.Exit(1)
	}

	if result.Error != nil && result.Output == "" {
		fmt.Fprintf(os.Stderr, "Error: %v\n", result.Error)
		os.Exit(1)
	}
	if result.Output != "" {
		fmt.Println(result.Output)
	}
	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}
}

func runInteractive() {
	clearScreen()

	fmt.Println(renderLogo())
	fmt.Println()

	// Check for pending migration FIRST — before VaultExists.
	// After an upgrade, vault.enc may not exist (deleted, corrupted, or re-keyed),
	// but the migration file contains the full vault data and can restore it.
	if MigrationPending() && MigrationTooOld() {
		printWarn("Migration file is older than 10 minutes. It may be from a previous upgrade.")
		choice := strings.ToUpper(printPrompt("(I)mport anyway, (D)elete it, or (Q)uit?"))
		switch choice {
		case "D":
			cleanupMigration()
			printSuccess("Migration file deleted.")
		case "Q":
			os.Exit(0)
		case "I":
			// Fall through to import
		default:
			os.Exit(0)
		}
	}

	if MigrationPending() {
		printWarn("Vault migration detected from upgrade.")
		fmt.Println()
		passphrase := printPasswordPrompt("Vault passphrase to complete migration:")

		vault, err := ImportMigration(passphrase)
		if err != nil {
			printError(fmt.Sprintf("Migration failed: %v", err))
			fmt.Println()
			printPrompt("Press enter to continue with normal login...")
		} else {
			resetAttempts() // clear any stale attempt counter from before the upgrade
			printSuccess(fmt.Sprintf("Vault migrated to v%s", version))
			printSuccess("All connections and auth keys preserved.")
			fmt.Println()
			pause()
			runBubbletea(vault)
			return
		}
	}

	// Hardware migration file handling. Four possible states:
	//   A) vault exists, migration exists  → ask: import (overwrite) / open / delete migration / quit
	//   B) vault missing, migration exists → offer import; on decline fall through
	//   C) vault missing, backup exists    → offer restore from portable backup
	//   D) no vault, no migration, no backup → create new vault
	if HardwareMigrationExists() && VaultExists() {
		printWarn("A hardware migration file is present AND a vault already exists on this machine.")
		expiry := ReadHWMigrationExpiry()
		if !expiry.IsZero() {
			remaining := time.Until(expiry).Round(time.Minute)
			if remaining > 0 {
				fmt.Println(dimStyle.Render(fmt.Sprintf("  Migration expires in %s (at %s)", remaining, expiry.Format(time.RFC1123))))
			} else {
				fmt.Println(dimStyle.Render(fmt.Sprintf("  Migration EXPIRED %s ago", (-remaining).Round(time.Minute))))
			}
		}
		fmt.Println()
		printError("Importing the migration will OVERWRITE your current vault.")
		fmt.Println(dimStyle.Render("  (A raw copy of your current vault will be saved to vault.enc.backup first.)"))
		fmt.Println()
		choice := strings.ToUpper(printPrompt("(I)mport migration, (O)pen existing vault, (D)elete migration file, or (Q)uit?"))
		switch choice {
		case "I":
			// Safety net: raw copy of current vault before we clear it for import.
			if err := BackupVault(); err != nil {
				printError(fmt.Sprintf("Could not backup current vault, aborting: %v", err))
				os.Exit(1)
			}
			if err := os.Remove(vaultPath()); err != nil {
				printError(fmt.Sprintf("Could not remove current vault, aborting: %v", err))
				os.Exit(1)
			}
			// Fall through to the !VaultExists() + HardwareMigrationExists() branch below.
		case "D":
			wipeAndRemove(hwMigrationPath())
			printSuccess("Migration file deleted. Continuing to normal login.")
			fmt.Println()
		case "O":
			// Keep both; migration file persists and will re-prompt next launch.
			// Fall through to normal login.
		case "Q", "":
			os.Exit(0)
		default:
			printError("Unknown choice.")
			os.Exit(1)
		}
	}

	if !VaultExists() && HardwareMigrationExists() {
		if vault := tryHardwareMigrationImport(); vault != nil {
			runBubbletea(vault)
			return
		}
		// fall through — admin declined or import failed
	}

	if !VaultExists() && PortableBackupExists() {
		header := ReadPortableBackupHeader()
		info := ""
		if header != nil {
			info = fmt.Sprintf(" (%d connections, %d keys, saved %s)",
				header.ConnectionCount, header.AuthKeyCount, header.LastSaved)
		}
		printWarn(fmt.Sprintf("No vault found, but a portable backup exists%s.", info))
		fmt.Println()
		choice := strings.ToUpper(printPrompt("(R)estore from backup, (C)reate new vault, or (Q)uit?"))
		switch choice {
		case "R":
			passphrase := printPasswordPrompt("Vault passphrase to decrypt backup:")
			vault, err := RestoreVault(passphrase)
			if err != nil {
				printError(fmt.Sprintf("Restore failed: %v", err))
				pause()
				os.Exit(1)
			}
			printSuccess("Vault restored from backup!")
			pause()
			runBubbletea(vault)
			return
		case "Q", "":
			os.Exit(0)
		case "C":
			// fall through to create-new-vault
		default:
			printError("Unknown choice.")
			os.Exit(1)
		}
	}

	if !VaultExists() {
		printWarn("No vault found. Creating new vault...")
		fmt.Println()
		fmt.Println(dimStyle.Render("  Passphrase policy: 12+ chars, upper, lower, digit, special, not common."))
		fmt.Println()

		passphrase := promptStrongPassphrase("Enter vault passphrase:", "Confirm passphrase:")
		if passphrase == "" {
			os.Exit(1)
		}

		vault, err := CreateVault(passphrase)
		if err != nil {
			printError(fmt.Sprintf("Error creating vault: %v", err))
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Vault created at %s", vaultPath()))
		pause()
		runBubbletea(vault)
		return
	}

	// Check compatibility — only if no migration pending
	compatible, reason := CheckVaultCompatibility()
	if !compatible {
		printError("Cannot open vault: " + reason)
		fmt.Println()
		header := ReadVaultHeader()
		if header != nil {
			fmt.Println(dimStyle.Render(fmt.Sprintf("  Vault info: %d connections, %d auth keys, last saved %s",
				header.ConnectionCount, header.AuthKeyCount, header.LastSaved)))
			fmt.Println()
		}

		if PortableBackupExists() {
			header := ReadPortableBackupHeader()
			info := ""
			if header != nil {
				info = fmt.Sprintf(" (%d connections, %d keys, saved %s)", header.ConnectionCount, header.AuthKeyCount, header.LastSaved)
			}
			printWarn(fmt.Sprintf("A portable vault backup exists%s.", info))
			choice := strings.ToUpper(printPrompt("(R)estore from backup, (W)ipe and start fresh, or (Q)uit?"))
			switch choice {
			case "R":
				passphrase := printPasswordPrompt("Vault passphrase to decrypt backup:")
				vault, err := RestoreVault(passphrase)
				if err != nil {
					printError(fmt.Sprintf("Restore failed: %v", err))
					pause()
					os.Exit(1)
				}
				printSuccess("Vault restored from backup!")
				pause()
				runBubbletea(vault)
				return
			case "W":
				confirm := printPrompt("Type WIPE to confirm:")
				if confirm == "WIPE" {
					WipeVault()
					printSuccess("Vault wiped. Restart to create a new vault.")
					os.Exit(0)
				}
			}
		} else {
			printWarn("No portable backup found.")
			fmt.Println()
			choice := strings.ToUpper(printPrompt("(W)ipe vault and start fresh, or (Q)uit?"))
			if choice == "W" {
				confirm := printPrompt("Type WIPE to confirm:")
				if confirm == "WIPE" {
					WipeVault()
					printSuccess("Vault wiped. Restart to create a new vault.")
					os.Exit(0)
				}
			}
		}
		fmt.Println()
		os.Exit(1)
	}

	fmt.Println(dimStyle.Render("  --help for user guide"))
	fmt.Println()

	// Check persistent attempt counter
	ad := loadAttempts()
	if ad.Count >= 5 {
		// Too many failed attempts — backup then wipe
		BackupVault()
		WipeVault()
		os.Exit(1)
	}

	maxAttempts := 5 - ad.Count
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		totalAttempts := ad.Count + attempt - 1
		if totalAttempts > 0 {
			delay := backoffDelay(totalAttempts)
			time.Sleep(delay)
		}

		passphrase := printPasswordPrompt("Vault passphrase:")

		if passphrase == "" {
			continue
		}

		vault, err := OpenVault(passphrase)
		if err == nil {
			resetAttempts()
			runBubbletea(vault)
			return
		}

		newAd := incrementAttempts()
		if newAd.Count >= 5 {
			// Silent wipe — but backup first
			BackupVault()
			WipeVault()
			os.Exit(1)
		}

		printError("Incorrect passphrase.")
		fmt.Println()

		choice := strings.ToUpper(printPrompt("(R)etry, (H)elp, or (W)ipe vault?"))
		switch choice {
		case "W":
			confirm := printPrompt("Type WIPE to confirm:")
			if confirm == "WIPE" {
				BackupVault()
				WipeVault()
				printSuccess("Vault wiped. Backup saved at " + vaultPath() + ".backup")
				os.Exit(0)
			}
		case "H", "?":
			printHelp()
			pause()
		}
		fmt.Println()
	}
}

// promptStrongPassphrase runs the new/confirm loop with validation against
// the project passphrase policy. Reprompts on issues rather than exiting so
// the admin isn't kicked out for a typo. Returns "" if the admin interrupts
// with an empty entry three times in a row (signals give-up).
func promptStrongPassphrase(enterMsg, confirmMsg string) string {
	const maxEmpty = 3
	empty := 0
	for {
		pass := printPasswordPrompt(enterMsg)
		if pass == "" {
			empty++
			if empty >= maxEmpty {
				printError("Passphrase is required.")
				return ""
			}
			printWarn("Passphrase is required.")
			continue
		}
		empty = 0

		if err := ValidatePassphrase(pass); err != nil {
			printError(err.Error())
			fmt.Println()
			continue
		}

		score, label := PassphraseStrength(pass)
		if score <= 1 {
			printWarn(fmt.Sprintf("Strength: %s — consider lengthening or adding more variety.", label))
		} else {
			fmt.Println(dimStyle.Render(fmt.Sprintf("  Strength: %s", label)))
		}

		confirm := printPasswordPrompt(confirmMsg)
		if pass != confirm {
			printError("Passphrases don't match.")
			fmt.Println()
			continue
		}
		return pass
	}
}

// promptStrongPassphraseOptional is like promptStrongPassphrase but an empty
// first entry returns "" immediately (caller interprets as "reuse whatever
// default applies").
func promptStrongPassphraseOptional(enterMsg, confirmMsg string) string {
	for {
		pass := printPasswordPrompt(enterMsg)
		if pass == "" {
			return ""
		}

		if err := ValidatePassphrase(pass); err != nil {
			printError(err.Error())
			fmt.Println()
			continue
		}

		score, label := PassphraseStrength(pass)
		if score <= 1 {
			printWarn(fmt.Sprintf("Strength: %s — consider lengthening or adding more variety.", label))
		} else {
			fmt.Println(dimStyle.Render(fmt.Sprintf("  Strength: %s", label)))
		}

		confirm := printPasswordPrompt(confirmMsg)
		if pass != confirm {
			printError("Passphrases don't match.")
			fmt.Println()
			continue
		}
		return pass
	}
}

// tryHardwareMigrationImport runs the fresh-machine import flow when a
// vault.hwmigration file is detected next to the binary. Returns the
// imported vault on success, or nil if the admin declined or the import
// failed (in which case the caller falls back to new-vault creation).
func tryHardwareMigrationImport() *Vault {
	expiry := ReadHWMigrationExpiry()
	printWarn("Hardware migration file detected next to this binary.")
	if !expiry.IsZero() {
		remaining := time.Until(expiry).Round(time.Minute)
		if remaining <= 0 {
			printError(fmt.Sprintf("Migration file expired %s ago.", (-remaining).Round(time.Minute)))
		} else {
			fmt.Println(dimStyle.Render(fmt.Sprintf("  Expires in %s (at %s)", remaining, expiry.Format(time.RFC1123))))
		}
	}
	fmt.Println()
	choice := strings.ToUpper(printPrompt("(I)mport to this machine, (S)kip and create new vault, or (Q)uit?"))
	switch choice {
	case "S":
		return nil
	case "I":
		// fall through
	default:
		os.Exit(0)
	}

	passphrase := printPasswordPrompt("Source vault passphrase:")
	if passphrase == "" {
		printError("Passphrase required. Aborting import.")
		return nil
	}
	codeInput := printPrompt("One-time code (format XXX-XXX-XXX):")
	if codeInput == "" {
		printError("Code required. Aborting import.")
		return nil
	}

	fmt.Println(dimStyle.Render("  New passphrase policy: 12+ chars, upper, lower, digit, special, not common."))
	fmt.Println(dimStyle.Render("  (Leave blank to reuse the source passphrase, which has already been set.)"))
	newPass := promptStrongPassphraseOptional("New passphrase for this machine:", "Confirm new passphrase:")

	fmt.Println(dimStyle.Render("  Verifying trusted time..."))
	vault, err := ImportHardwareMigration(passphrase, codeInput, newPass)
	if err != nil {
		printError(fmt.Sprintf("Import failed: %v", err))
		pause()
		return nil
	}
	printSuccess("Hardware migration complete. Vault re-encrypted for this machine.")
	printWarn("Auth keys were NOT migrated — regenerate them from the Config menu if needed.")
	pause()
	return vault
}

// attemptsFilePath returns the path to the persistent attempt counter file.
func attemptsFilePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".secure-wrapper", "attempts")
}

type attemptData struct {
	Count     int       `json:"count"`
	LastFail  time.Time `json:"last_fail"`
}

func loadAttempts() attemptData {
	data, err := os.ReadFile(attemptsFilePath())
	if err != nil {
		return attemptData{}
	}
	var ad attemptData
	if err := json.Unmarshal(data, &ad); err != nil {
		return attemptData{}
	}
	return ad
}

func saveAttempts(ad attemptData) {
	dir := filepath.Dir(attemptsFilePath())
	os.MkdirAll(dir, 0700)
	data, _ := json.Marshal(ad)
	os.WriteFile(attemptsFilePath(), data, 0600)
}

func resetAttempts() {
	os.Remove(attemptsFilePath())
}

func incrementAttempts() attemptData {
	ad := loadAttempts()
	ad.Count++
	ad.LastFail = time.Now()
	saveAttempts(ad)
	return ad
}

// backoffDelay returns the exponential backoff delay for the given attempt count, capped at 30 seconds.
func backoffDelay(count int) time.Duration {
	secs := math.Pow(2, float64(count))
	if secs > 30 {
		secs = 30
	}
	return time.Duration(secs) * time.Second
}

// extractFlag finds a --flag value pair and returns the value and the value's index.
func extractFlag(args []string, flag string) (string, int) {
	for i, arg := range args {
		if arg == flag && i+1 < len(args) {
			return args[i+1], i + 1
		}
		if strings.HasPrefix(arg, flag+"=") {
			return strings.SplitN(arg, "=", 2)[1], i
		}
	}
	return "", -1
}

func hasFlag(args []string, flag string) bool {
	for _, arg := range args {
		if arg == flag {
			return true
		}
	}
	return false
}
