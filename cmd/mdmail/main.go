// Command mdmail is a self-hosted mail server whose messages are authored in
// Markdown. See `mdmail help`.
package main

import (
	"fmt"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `mdmail — self-hosted Markdown email server

Usage:
  mdmail serve                       Run the server (configuration from MDMAIL_* environment variables)
  mdmail healthcheck                 Exit 0 if the local server is healthy (for container health checks)
  mdmail user add <email> [--admin]  Create a user (password read from the terminal or stdin)
  mdmail user passwd <email>         Set a new password (also clears lockout)
  mdmail user list                   List users
  mdmail user disable <email>        Disable a user (blocks login and mail delivery)
  mdmail user enable <email>         Re-enable a user
  mdmail user unlock <email>         Clear failed-login lockout
  mdmail user reset-2fa <email>      Remove TOTP from an account (lost device)
  mdmail user delete <email>         Delete a user and all of their mail
  mdmail dkim generate <domain>      Create a DKIM key and print the DNS record
  mdmail dkim show <domain>          Print the DNS record for an existing key
  mdmail dns <domain>                Print all recommended DNS records for a domain
  mdmail queue                       Show the outbound queue
  mdmail backup <file>               Write a consistent online backup of the database to <file>
  mdmail version                     Print the version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve()
	case "healthcheck":
		err = healthcheck()
	case "user":
		err = userCmd(os.Args[2:])
	case "dkim":
		err = dkimCmd(os.Args[2:])
	case "dns":
		err = dnsCmd(os.Args[2:])
	case "queue":
		err = queueCmd()
	case "backup":
		err = backupCmd(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println("mdmail", version)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
