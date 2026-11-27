// Package mailauth implements SPF, DKIM and DMARC verification for inbound
// mail and DKIM signing for outbound mail.
package mailauth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/emersion/go-message/mail"
	"github.com/emersion/go-message/textproto"
	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// Resolver is the DNS interface used for all lookups.
type Resolver = spf.DNSResolver

// Action is the disposition decided for an inbound message.
type Action int

// Dispositions.
const (
	Deliver Action = iota
	Junk
	Reject
)

func (a Action) String() string {
	switch a {
	case Junk:
		return "junk"
	case Reject:
		return "reject"
	default:
		return "deliver"
	}
}

// DKIMResult is the outcome for one DKIM signature.
type DKIMResult struct {
	Domain string
	Value  authres.ResultValue
	Reason string
}

// Result is the combined authentication outcome.
type Result struct {
	SPF        spf.Result
	SPFDomain  string
	DKIM       []DKIMResult
	DMARC      authres.ResultValue
	Policy     dmarc.Policy
	FromDomain string
	Action     Action
	Reason     string
	Header     string // Authentication-Results field value
}

// Summary is a compact human-readable result for the UI.
func (r *Result) Summary() string {
	dk := "none"
	for _, d := range r.DKIM {
		dk = string(d.Value)
		if d.Value == authres.ResultPass {
			break
		}
	}
	return fmt.Sprintf("spf=%s dkim=%s dmarc=%s", r.SPF, dk, r.DMARC)
}

// Verifier checks inbound messages.
type Verifier struct {
	Hostname string // authserv-id
	Resolver Resolver
	Timeout  time.Duration
	Enforce  bool // honour DMARC p=reject by rejecting at SMTP time
}

// Verify runs SPF, DKIM and DMARC for a message received from ip.
func (v *Verifier) Verify(ctx context.Context, ip net.IP, helo, mailFrom string, raw []byte) *Result {
	if v.Timeout == 0 {
		v.Timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, v.Timeout)
	defer cancel()
	res := &Result{}

	// SPF (RFC 7208). For null reverse-path, check the HELO identity.
	spfSender := mailFrom
	if spfSender == "" {
		spfSender = "postmaster@" + helo
	}
	res.SPFDomain = domainOf(spfSender)
	r, err := spf.CheckHostWithSender(ip, helo, spfSender, spf.WithContext(ctx), spf.WithResolver(v.Resolver))
	res.SPF = r
	spfReason := ""
	if err != nil {
		spfReason = trimReason(err.Error())
	}

	// DKIM (RFC 6376).
	verifs, err := dkim.VerifyWithOptions(bytes.NewReader(raw), &dkim.VerifyOptions{
		LookupTXT:        func(d string) ([]string, error) { return v.Resolver.LookupTXT(ctx, d) },
		MaxVerifications: 5,
	})
	if err != nil && !errors.Is(err, dkim.ErrTooManySignatures) {
		res.DKIM = append(res.DKIM, DKIMResult{Value: authres.ResultPermError, Reason: trimReason(err.Error())})
	}
	for _, vf := range verifs {
		d := DKIMResult{Domain: strings.ToLower(vf.Domain), Value: authres.ResultPass}
		if vf.Err != nil {
			d.Reason = trimReason(vf.Err.Error())
			switch {
			case dkim.IsTempFail(vf.Err):
				d.Value = authres.ResultTempError
			case dkim.IsPermFail(vf.Err):
				d.Value = authres.ResultPermError
			default:
				d.Value = authres.ResultFail
			}
		}
		res.DKIM = append(res.DKIM, d)
	}

	// DMARC (RFC 7489).
	v.evalDMARC(ctx, res, raw)

	// Authentication-Results (RFC 8601).
	results := []authres.Result{&authres.SPFResult{Value: authres.ResultValue(res.SPF), Reason: spfReason, From: spfSender, Helo: helo}}
	if len(res.DKIM) == 0 {
		results = append(results, &authres.DKIMResult{Value: authres.ResultNone})
	}
	for _, d := range res.DKIM {
		results = append(results, &authres.DKIMResult{Value: d.Value, Domain: d.Domain, Reason: d.Reason})
	}
	results = append(results, &authres.DMARCResult{Value: res.DMARC, From: res.FromDomain, Reason: res.Reason})
	res.Header = authres.Format(v.Hostname, results)
	return res
}

func (v *Verifier) evalDMARC(ctx context.Context, res *Result, raw []byte) {
	h, err := textproto.ReadHeader(bufio.NewReader(io.LimitReader(bytes.NewReader(raw), 1<<20)))
	if err != nil {
		res.DMARC, res.Action, res.Reason = authres.ResultPermError, Junk, "unparseable header"
		return
	}
	if len(h.Values("From")) != 1 {
		res.DMARC, res.Action, res.Reason = authres.ResultPermError, Junk, "message must have exactly one From field"
		return
	}
	mh := mail.Header{Header: messageHeader(h)}
	from, err := mh.AddressList("From")
	if err != nil || len(from) != 1 {
		res.DMARC, res.Action, res.Reason = authres.ResultPermError, Junk, "From must contain exactly one address"
		return
	}
	res.FromDomain = domainOf(from[0].Address)
	if res.FromDomain == "" {
		res.DMARC, res.Action, res.Reason = authres.ResultPermError, Junk, "invalid From domain"
		return
	}

	lookup := &dmarc.LookupOptions{LookupTXT: func(d string) ([]string, error) { return v.Resolver.LookupTXT(ctx, d) }}
	rec, err := dmarc.LookupWithOptions(res.FromDomain, lookup)
	org := orgDomain(res.FromDomain)
	usedOrg := false
	if errors.Is(err, dmarc.ErrNoPolicy) && org != res.FromDomain {
		rec, err = dmarc.LookupWithOptions(org, lookup)
		usedOrg = true
	}
	switch {
	case errors.Is(err, dmarc.ErrNoPolicy):
		res.DMARC = authres.ResultNone
		if res.SPF == spf.Fail && !anyDKIMPass(res, "") {
			res.Action, res.Reason = Junk, "spf fail without DMARC policy"
		}
		return
	case err != nil && dmarc.IsTempFail(err):
		res.DMARC, res.Reason = authres.ResultTempError, "dmarc lookup failed"
		return
	case err != nil:
		res.DMARC, res.Reason = authres.ResultPermError, "invalid dmarc record"
		return
	}

	policy := rec.Policy
	if usedOrg && rec.SubdomainPolicy != "" {
		policy = rec.SubdomainPolicy
	}
	res.Policy = policy

	spfAligned := res.SPF == spf.Pass && aligned(res.SPFDomain, res.FromDomain, rec.SPFAlignment)
	dkimAligned := false
	for _, d := range res.DKIM {
		if d.Value == authres.ResultPass && aligned(d.Domain, res.FromDomain, rec.DKIMAlignment) {
			dkimAligned = true
		}
	}
	if spfAligned || dkimAligned {
		res.DMARC = authres.ResultPass
		return
	}
	res.DMARC = authres.ResultFail

	// pct sampling (RFC 7489 6.6.4): messages outside the sample get the next
	// weaker policy.
	if rec.Percent != nil && *rec.Percent < 100 {
		n, err := rand.Int(rand.Reader, big.NewInt(100))
		if err == nil && n.Int64() >= int64(*rec.Percent) {
			switch policy {
			case dmarc.PolicyReject:
				policy = dmarc.PolicyQuarantine
			case dmarc.PolicyQuarantine:
				policy = dmarc.PolicyNone
			}
		}
	}
	switch policy {
	case dmarc.PolicyReject:
		if v.Enforce {
			res.Action, res.Reason = Reject, "DMARC policy reject"
		} else {
			res.Action, res.Reason = Junk, "DMARC policy reject (not enforced)"
		}
	case dmarc.PolicyQuarantine:
		res.Action, res.Reason = Junk, "DMARC policy quarantine"
	default:
		res.Reason = "DMARC policy none"
	}
}

func anyDKIMPass(res *Result, _ string) bool {
	for _, d := range res.DKIM {
		if d.Value == authres.ResultPass {
			return true
		}
	}
	return false
}

func aligned(a, b string, mode dmarc.AlignmentMode) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == "" || b == "" {
		return false
	}
	if mode == dmarc.AlignmentStrict {
		return a == b
	}
	return orgDomain(a) == orgDomain(b)
}

func orgDomain(d string) string {
	o, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(d, "."))
	if err != nil {
		return d
	}
	return o
}

func domainOf(addr string) string {
	at := strings.LastIndexByte(addr, '@')
	if at < 0 {
		return strings.ToLower(addr)
	}
	return strings.ToLower(strings.TrimSuffix(addr[at+1:], "."))
}

func trimReason(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == '"' || r == '\\' || r > 0x7e {
			return ' '
		}
		return r
	}, s)
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// PrependTrace removes forged Authentication-Results fields carrying our
// authserv-id (RFC 8601 section 5) and prepends our own trace fields.
func PrependTrace(raw []byte, hostname, authResults, received string) ([]byte, error) {
	br := bufio.NewReader(bytes.NewReader(raw))
	h, err := textproto.ReadHeader(br)
	if err != nil {
		return nil, err
	}
	fields := h.FieldsByKey("Authentication-Results")
	for fields.Next() {
		id, _, perr := authres.Parse(fields.Value())
		if perr != nil || strings.EqualFold(strings.TrimSpace(id), hostname) {
			fields.Del()
		}
	}
	if authResults != "" {
		h.Add("Authentication-Results", authResults)
	}
	if received != "" {
		h.Add("Received", received)
	}
	var out bytes.Buffer
	out.Grow(len(raw) + 512)
	if err := textproto.WriteHeader(&out, h); err != nil {
		return nil, err
	}
	if _, err := io.Copy(&out, br); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
