package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/t-el/mdmail/internal/auth"
	"github.com/t-el/mdmail/internal/config"
	"github.com/t-el/mdmail/internal/mailauth"
	"github.com/t-el/mdmail/internal/mailmsg"
	"github.com/t-el/mdmail/internal/store"
)

func openStore() (*config.Config, *store.Store, error) {
	cfg, err := config.LoadForCLI()
	if err != nil {
		return nil, nil, err
	}
	st, err := store.OpenExisting(context.Background(), cfg.DBPath())
	if errors.Is(err, store.ErrNoDatabase) {
		return nil, nil, fmt.Errorf("no mdmail database at %s\n"+
			"  Set MDMAIL_DATA_DIR to the same absolute directory the server uses (its startup log prints \"database\"),\n"+
			"  and start \"mdmail serve\" once before adding users", cfg.DBPath())
	}
	return cfg, st, err
}

func readPassword(confirm bool) (string, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 -- file descriptors fit in int
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Password: ")
		p1, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if confirm {
			fmt.Fprint(os.Stderr, "Repeat password: ")
			p2, err := term.ReadPassword(fd)
			fmt.Fprintln(os.Stderr)
			if err != nil {
				return "", err
			}
			if string(p1) != string(p2) {
				return "", errors.New("passwords do not match")
			}
		}
		return string(p1), nil
	}
	if term.IsTerminal(int(os.Stderr.Fd())) { // #nosec G115 -- file descriptors fit in int
		// Interactive but stdin is not a TTY (e.g. Git Bash/mintty on
		// Windows): the input will be visible and is read only once.
		fmt.Fprint(os.Stderr, "Password (stdin is not a terminal, input is visible; use winpty on Git Bash): ")
	}
	return readPasswordLine(os.Stdin)
}

// readPasswordLine reads one password from a non-terminal reader: the first
// line, without its line terminator ("\n" or "\r\n"). Other whitespace is
// kept, because it is part of the password the browser will send.
func readPasswordLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	line = strings.TrimSuffix(line, "\n")
	line = strings.TrimSuffix(line, "\r")
	if line == "" {
		return "", errors.New("no password on stdin")
	}
	return line, nil
}

func userCmd(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: mdmail user <add|passwd|list|disable|enable|unlock|reset-2fa|delete> [email]")
	}
	cfg, st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := context.Background()

	if args[0] == "list" {
		users, err := st.ListUsers(ctx)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "EMAIL\tADMIN\tDISABLED\t2FA\tLOCKED UNTIL\tCREATED")
		for _, u := range users {
			locked := "-"
			if time.Now().Before(u.LockedUntil) {
				locked = u.LockedUntil.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%v\t%v\t%v\t%s\t%s\n", u.Email, u.IsAdmin, u.Disabled, u.TOTPEnabled, locked, u.CreatedAt.UTC().Format(time.RFC3339))
		}
		return tw.Flush()
	}
	if len(args) < 2 {
		return fmt.Errorf("usage: mdmail user %s <email>", args[0])
	}
	email := auth.NormalizeEmail(args[1])

	if args[0] == "add" {
		if !mailmsg.ValidAddress(email) {
			return errors.New("invalid email address")
		}
		dom := email[strings.LastIndexByte(email, '@')+1:]
		if len(cfg.Domains) > 0 && !cfg.IsLocalDomain(dom) {
			return fmt.Errorf("domain %s is not in MDMAIL_DOMAINS", dom)
		}
		pw, err := readPassword(true)
		if err != nil {
			return err
		}
		h, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		admin := len(args) > 2 && args[2] == "--admin"
		if _, err := st.CreateUser(ctx, email, h, admin); err != nil {
			if errors.Is(err, store.ErrExists) {
				return errors.New("user already exists")
			}
			return err
		}
		fmt.Printf("created %s (database %s)\n", email, cfg.DBPath())
		return nil
	}

	u, err := st.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errors.New("no such user")
		}
		return err
	}
	switch args[0] {
	case "passwd":
		pw, err := readPassword(true)
		if err != nil {
			return err
		}
		h, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		if err := st.SetPassword(ctx, u.ID, h); err != nil {
			return err
		}
		if err := st.DeleteUserSessions(ctx, u.ID, nil); err != nil {
			return err
		}
	case "disable":
		if err = st.SetDisabled(ctx, u.ID, true); err == nil {
			err = st.DeleteUserSessions(ctx, u.ID, nil)
		}
	case "enable":
		err = st.SetDisabled(ctx, u.ID, false)
	case "unlock":
		err = st.ResetLoginFailures(ctx, u.ID)
	case "reset-2fa":
		err = st.SetTOTP(ctx, u.ID, nil, false)
	case "delete":
		err = st.DeleteUser(ctx, u.ID)
	default:
		return fmt.Errorf("unknown user command %q", args[0])
	}
	if err != nil {
		return err
	}
	fmt.Println("ok")
	return nil
}

func dkimCmd(args []string) error {
	if len(args) != 2 || (args[0] != "generate" && args[0] != "show") {
		return errors.New("usage: mdmail dkim <generate|show> <domain>")
	}
	cfg, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	dom := strings.ToLower(args[1])
	var rec string
	if args[0] == "generate" {
		rec, err = mailauth.GenerateKey(cfg.DKIMKeyDir, dom)
	} else {
		rec, err = mailauth.PublicRecordForDomain(cfg.DKIMKeyDir, dom)
	}
	if err != nil {
		return err
	}
	fmt.Printf("%s._domainkey.%s. IN TXT %s\n", cfg.DKIMSelector, dom, splitTXT(rec))
	return nil
}

// splitTXT splits long TXT data into 255-byte quoted strings.
func splitTXT(s string) string {
	var parts []string
	for len(s) > 255 {
		parts = append(parts, `"`+s[:255]+`"`)
		s = s[255:]
	}
	parts = append(parts, `"`+s+`"`)
	return "( " + strings.Join(parts, " ") + " )"
}

func dnsCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: mdmail dns <domain>")
	}
	cfg, err := config.LoadForCLI()
	if err != nil {
		return err
	}
	host := os.Getenv("MDMAIL_HOSTNAME")
	if host == "" {
		host = "mail.example.com"
	}
	dom := strings.ToLower(args[0])
	fmt.Printf("; Recommended DNS records for %s (mail server %s)\n", dom, host)
	fmt.Printf("%s.\tIN MX 10 %s.\n", dom, host)
	fmt.Printf("%s.\tIN TXT \"v=spf1 mx -all\"\n", dom)
	fmt.Printf("_dmarc.%s.\tIN TXT \"v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:postmaster@%s\"\n", dom, dom)
	if rec, err := mailauth.PublicRecordForDomain(cfg.DKIMKeyDir, dom); err == nil {
		fmt.Printf("%s._domainkey.%s.\tIN TXT %s\n", cfg.DKIMSelector, dom, splitTXT(rec))
	} else {
		fmt.Printf("; DKIM: run `mdmail dkim generate %s` first\n", dom)
	}
	fmt.Printf("_mta-sts.%s.\tIN TXT \"v=STSv1; id=%s\"\n", dom, time.Now().UTC().Format("20060102T150405"))
	fmt.Printf("mta-sts.%s.\tIN CNAME %s.\n", dom, host)
	fmt.Printf("_smtp._tls.%s.\tIN TXT \"v=TLSRPTv1; rua=mailto:postmaster@%s\"\n", dom, dom)
	fmt.Printf("_submissions._tcp.%s.\tIN SRV 0 1 465 %s.\n", dom, host)
	fmt.Printf("_submission._tcp.%s.\tIN SRV 0 1 587 %s.\n", dom, host)
	fmt.Printf("; PTR: ask your hosting provider to set reverse DNS of the server IP to %s\n", host)
	return nil
}

func queueCmd() error {
	_, st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	q, err := st.ListQueue(context.Background())
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "RECIPIENT\tATTEMPTS\tNEXT ATTEMPT\tLAST ERROR")
	for _, x := range q {
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", x.Rcpt, x.Attempts, x.Next.UTC().Format(time.RFC3339), x.LastError)
	}
	return tw.Flush()
}

func backupCmd(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: mdmail backup <file>")
	}
	_, st, err := openStore()
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Backup(context.Background(), args[0]); err != nil {
		return err
	}
	fmt.Println("backup written to", args[0])
	return nil
}
