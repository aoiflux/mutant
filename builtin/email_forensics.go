package builtin

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/emersion/go-msgauth/dkim"
	"golang.org/x/net/publicsuffix"

	"mutant/object"
)

// dkimLookupTXT resolves DNS TXT records for DKIM public-key and DMARC policy
// lookups. It is a package variable so tests can inject an offline resolver.
var dkimLookupTXT = net.LookupTXT

func EmailParse(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	rawObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `email_parse` must be STRING, got %s", args[0].Type()))
	}

	parsed, err := mail.ReadMessage(strings.NewReader(rawObj.Value))
	if err != nil {
		return resultAndError(nil, newError("email_parse: %s", err.Error()))
	}

	headers := emailHeadersToHash(parsed.Header)
	bodyText, bodyHTML, attachments, errObj := parseEmailBodyAndAttachments(parsed.Header, parsed.Body)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(makeHashObject(map[string]object.Object{
		"from":        stringObj(parsed.Header.Get("From")),
		"to":          stringObj(parsed.Header.Get("To")),
		"subject":     stringObj(parsed.Header.Get("Subject")),
		"date":        stringObj(parsed.Header.Get("Date")),
		"message_id":  stringObj(parsed.Header.Get("Message-ID")),
		"headers":     headers,
		"text":        stringObj(bodyText),
		"html":        stringObj(bodyHTML),
		"attachments": attachments,
	}), nil)
}

func EmailHeaders(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	rawObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `email_headers` must be STRING, got %s", args[0].Type()))
	}

	parsed, err := mail.ReadMessage(strings.NewReader(rawObj.Value))
	if err != nil {
		return resultAndError(nil, newError("email_headers: %s", err.Error()))
	}

	return resultAndError(emailHeadersToHash(parsed.Header), nil)
}

func EmailAttachments(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	rawObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `email_attachments` must be STRING, got %s", args[0].Type()))
	}

	parsed, err := mail.ReadMessage(strings.NewReader(rawObj.Value))
	if err != nil {
		return resultAndError(nil, newError("email_attachments: %s", err.Error()))
	}

	_, _, attachments, errObj := parseEmailBodyAndAttachments(parsed.Header, parsed.Body)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	return resultAndError(attachments, nil)
}

func EmailSPFDKIM(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	rawObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `email_spf_dkim` must be STRING, got %s", args[0].Type()))
	}

	parsed, err := mail.ReadMessage(strings.NewReader(rawObj.Value))
	if err != nil {
		return resultAndError(nil, newError("email_spf_dkim: %s", err.Error()))
	}

	receivedSPF := parsed.Header.Get("Received-SPF")
	dkimHeader := parsed.Header.Get("DKIM-Signature")
	authHeader := parsed.Header.Get("Authentication-Results")
	fromDomain := emailFromDomain(parsed.Header.Get("From"))

	// DKIM is verified cryptographically: the body hash and the signature over
	// the canonicalized signed headers are checked against the signer's public
	// key (fetched via DNS). The top-level "dkim" field reflects that real
	// result; "dkim_reported" separately surfaces what the receiving MTA claimed.
	dkimVerdict, dkimSigs, dkimAligned := verifyDKIMSignatures(rawObj.Value, fromDomain)

	// SPF cannot be recomputed from a stored message (it depends on the SMTP
	// connecting IP and envelope sender, which are not in the message). We
	// report the result recorded by the receiving infrastructure and its source.
	spfResult, spfSource := reportedSPFResult(authHeader, receivedSPF)

	dmarcResult, dmarcPolicy := evaluateDMARC(authHeader, fromDomain, dkimAligned)

	return resultAndError(makeHashObject(map[string]object.Object{
		"dkim":                   stringObj(dkimVerdict),
		"dkim_signatures":        dkimSigs,
		"dkim_signature_present": boolObj(strings.TrimSpace(dkimHeader) != ""),
		"dkim_reported":          stringObj(authResultMethod(authHeader, "dkim")),
		"dkim_aligned":           boolObj(dkimAligned),
		"spf":                    stringObj(spfResult),
		"spf_source":             stringObj(spfSource),
		"dmarc":                  stringObj(dmarcResult),
		"dmarc_policy":           stringObj(dmarcPolicy),
		"from_domain":            stringObj(fromDomain),
		"received_spf":           stringObj(receivedSPF),
		"authentication_results": stringObj(authHeader),
	}), nil)
}

func EmailURLs(args ...object.Object) object.Object {
	if len(args) != 1 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=1", len(args)))
	}
	rawObj, ok := args[0].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `email_urls` must be STRING, got %s", args[0].Type()))
	}

	parsed, err := mail.ReadMessage(strings.NewReader(rawObj.Value))
	if err != nil {
		return resultAndError(nil, newError("email_urls: %s", err.Error()))
	}

	bodyText, bodyHTML, _, errObj := parseEmailBodyAndAttachments(parsed.Header, parsed.Body)
	if errObj != nil {
		return resultAndError(nil, errObj)
	}

	candidates := collectURLs(parsed.Header, bodyText+"\n"+bodyHTML)
	items := make([]object.Object, 0, len(candidates))
	for _, u := range candidates {
		parsedURL, pErr := url.Parse(u)
		host := ""
		scheme := ""
		if pErr == nil {
			host = strings.ToLower(parsedURL.Host)
			scheme = strings.ToLower(parsedURL.Scheme)
		}
		items = append(items, makeHashObject(map[string]object.Object{
			"url":    stringObj(u),
			"host":   stringObj(host),
			"scheme": stringObj(scheme),
		}))
	}

	return resultAndError(&object.Array{Elements: items}, nil)
}

func parseEmailBodyAndAttachments(header mail.Header, body io.Reader) (string, string, *object.Array, *object.Error) {
	contentType := header.Get("Content-Type")
	mediaType, params, _ := mime.ParseMediaType(contentType)
	contentTransfer := strings.ToLower(strings.TrimSpace(header.Get("Content-Transfer-Encoding")))

	rawBody, err := io.ReadAll(body)
	if err != nil {
		return "", "", nil, newError("email parsing: %s", err.Error())
	}

	if strings.HasPrefix(strings.ToLower(mediaType), "multipart/") {
		boundary := params["boundary"]
		if strings.TrimSpace(boundary) == "" {
			return "", "", nil, newError("email parsing: multipart body missing boundary")
		}
		return parseMultipartEmail(rawBody, boundary)
	}

	decodedBody, err := decodeBodyByTransferEncoding(rawBody, contentTransfer)
	if err != nil {
		return "", "", nil, newError("email parsing: %s", err.Error())
	}
	text := string(decodedBody)
	html := ""
	if strings.Contains(strings.ToLower(mediaType), "text/html") {
		html = text
		text = ""
	}
	return text, html, &object.Array{Elements: []object.Object{}}, nil
}

func parseMultipartEmail(rawBody []byte, boundary string) (string, string, *object.Array, *object.Error) {
	mr := multipart.NewReader(bytes.NewReader(rawBody), boundary)
	text := ""
	html := ""
	attachments := make([]object.Object, 0)

	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", nil, newError("email parsing: multipart read failed: %s", err.Error())
		}

		contentDisposition := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Disposition")))
		contentType := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Type")))
		transferEncoding := strings.ToLower(strings.TrimSpace(part.Header.Get("Content-Transfer-Encoding")))

		partData, readErr := io.ReadAll(part)
		_ = part.Close()
		if readErr != nil {
			return "", "", nil, newError("email parsing: part read failed: %s", readErr.Error())
		}

		decoded, decErr := decodeBodyByTransferEncoding(partData, transferEncoding)
		if decErr != nil {
			return "", "", nil, newError("email parsing: %s", decErr.Error())
		}

		filename := part.FileName()
		isAttachment := strings.Contains(contentDisposition, "attachment") || filename != ""
		if isAttachment {
			sha := sha256Hex(decoded)
			attachments = append(attachments, makeHashObject(map[string]object.Object{
				"filename": stringObj(filename),
				"size":     intObj(int64(len(decoded))),
				"sha256":   stringObj(sha),
				"mime":     stringObj(contentType),
			}))
			continue
		}

		if strings.Contains(contentType, "text/plain") && text == "" {
			text = string(decoded)
		} else if strings.Contains(contentType, "text/html") && html == "" {
			html = string(decoded)
		}
	}

	return text, html, &object.Array{Elements: attachments}, nil
}

func decodeBodyByTransferEncoding(raw []byte, transferEncoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(transferEncoding)) {
	case "", "7bit", "8bit", "binary":
		return raw, nil
	case "base64":
		decoder := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(raw))
		decoded, err := io.ReadAll(decoder)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	case "quoted-printable":
		qr := quotedprintable.NewReader(bytes.NewReader(raw))
		decoded, err := io.ReadAll(qr)
		if err != nil {
			return nil, err
		}
		return decoded, nil
	default:
		return raw, nil
	}
}

func emailHeadersToHash(header mail.Header) *object.Hash {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make(map[string]object.Object, len(keys))
	for _, key := range keys {
		values := header[key]
		arr := make([]object.Object, len(values))
		for i, value := range values {
			arr[i] = stringObj(value)
		}
		out[key] = &object.Array{Elements: arr}
	}
	return makeHashObject(out)
}

func collectURLs(header mail.Header, body string) []string {
	urlRe := regexp.MustCompile(`https?://[^\s<>"]+`)
	matches := map[string]struct{}{}

	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := scanner.Text()
		for _, match := range urlRe.FindAllString(line, -1) {
			trimmed := strings.TrimRight(match, ".,;)")
			matches[trimmed] = struct{}{}
		}
	}

	for _, field := range []string{"List-Unsubscribe", "Message-ID"} {
		for _, raw := range header[field] {
			for _, match := range urlRe.FindAllString(raw, -1) {
				trimmed := strings.TrimRight(match, ".,;)")
				matches[trimmed] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(matches))
	for match := range matches {
		out = append(out, match)
	}
	sort.Strings(out)
	return out
}

// verifyDKIMSignatures performs real DKIM verification of every DKIM-Signature
// in the message. It returns an overall verdict, a per-signature detail array,
// and whether at least one *valid* signature is DMARC-aligned with fromDomain.
func verifyDKIMSignatures(raw, fromDomain string) (string, *object.Array, bool) {
	verifs, verr := dkim.VerifyWithOptions(strings.NewReader(raw), &dkim.VerifyOptions{LookupTXT: dkimLookupTXT})

	elems := make([]object.Object, 0, len(verifs))
	var anyValid, anyFail, anyTemp, anyPerm, aligned bool
	for _, v := range verifs {
		valid := v.Err == nil
		errStr := ""
		if v.Err != nil {
			errStr = v.Err.Error()
			switch {
			case dkim.IsTempFail(v.Err):
				anyTemp = true
			case dkim.IsPermFail(v.Err):
				anyPerm = true
			default:
				anyFail = true
			}
		} else {
			anyValid = true
			if domainsAligned(fromDomain, v.Domain) {
				aligned = true
			}
		}
		elems = append(elems, makeHashObject(map[string]object.Object{
			"domain":     stringObj(v.Domain),
			"identifier": stringObj(v.Identifier),
			"valid":      boolObj(valid),
			"error":      stringObj(errStr),
		}))
	}

	verdict := "none"
	switch {
	case anyValid:
		verdict = "pass"
	case len(verifs) == 0:
		if verr != nil {
			verdict = "permerror"
		} else {
			verdict = "none"
		}
	case anyFail:
		verdict = "fail"
	case anyTemp:
		verdict = "temperror"
	case anyPerm:
		verdict = "permerror"
	default:
		verdict = "fail"
	}

	return verdict, &object.Array{Elements: elems}, aligned
}

// reportedSPFResult returns the SPF result as recorded by the receiving
// infrastructure (it cannot be recomputed offline), plus which header it came
// from: "authentication_results", "received_spf", or "none".
func reportedSPFResult(authHeader, receivedSPF string) (string, string) {
	if result := authResultMethod(authHeader, "spf"); result != "" {
		return result, "authentication_results"
	}
	if trimmed := strings.TrimSpace(receivedSPF); trimmed != "" {
		fields := strings.Fields(trimmed)
		if len(fields) > 0 {
			return strings.ToLower(fields[0]), "received_spf"
		}
	}
	return "none", "none"
}

// evaluateDMARC returns the DMARC verdict and the published policy for the From
// domain. If the receiving MTA already recorded a dmarc= result we surface that;
// otherwise we conservatively derive "pass" only from a valid, aligned DKIM
// signature (SPF alignment cannot be evaluated offline).
func evaluateDMARC(authHeader, fromDomain string, dkimAligned bool) (string, string) {
	policy := lookupDMARCPolicy(fromDomain)

	if reported := authResultMethod(authHeader, "dmarc"); reported != "" {
		return reported, policy
	}
	if dkimAligned {
		return "pass", policy
	}
	return "none", policy
}

// authResultMethod extracts a `method=result` token (e.g. spf=pass, dkim=fail,
// dmarc=pass) from an Authentication-Results header value.
func authResultMethod(authHeader, method string) string {
	if strings.TrimSpace(authHeader) == "" {
		return ""
	}
	re := regexp.MustCompile(`(?i)\b` + regexp.QuoteMeta(method) + `\s*=\s*([a-z]+)`)
	if m := re.FindStringSubmatch(authHeader); len(m) == 2 {
		return strings.ToLower(m[1])
	}
	return ""
}

// lookupDMARCPolicy fetches and parses the p= tag of the _dmarc TXT record for
// the domain. Returns "" when no policy is published or DNS is unavailable.
func lookupDMARCPolicy(fromDomain string) string {
	if fromDomain == "" {
		return ""
	}
	records, err := dkimLookupTXT("_dmarc." + fromDomain)
	if err != nil {
		return ""
	}
	policyRe := regexp.MustCompile(`(?i)\bp\s*=\s*([a-z]+)`)
	for _, record := range records {
		if !strings.Contains(strings.ToLower(record), "v=dmarc1") {
			continue
		}
		if m := policyRe.FindStringSubmatch(record); len(m) == 2 {
			return strings.ToLower(m[1])
		}
	}
	return ""
}

// domainsAligned reports DMARC relaxed alignment between two domains: an exact
// match, or a shared organizational domain (eTLD+1).
func domainsAligned(from, other string) bool {
	from = strings.ToLower(strings.TrimSpace(from))
	other = strings.ToLower(strings.TrimSpace(other))
	if from == "" || other == "" {
		return false
	}
	if from == other {
		return true
	}
	fromOrg, err1 := publicsuffix.EffectiveTLDPlusOne(from)
	otherOrg, err2 := publicsuffix.EffectiveTLDPlusOne(other)
	return err1 == nil && err2 == nil && fromOrg == otherOrg
}

// emailFromDomain extracts the lowercased domain from a From header value.
func emailFromDomain(fromHeader string) string {
	if addr, err := mail.ParseAddress(fromHeader); err == nil {
		if i := strings.LastIndex(addr.Address, "@"); i >= 0 {
			return strings.ToLower(addr.Address[i+1:])
		}
	}
	if i := strings.LastIndex(fromHeader, "@"); i >= 0 {
		return strings.ToLower(strings.Trim(strings.TrimSpace(fromHeader[i+1:]), "<>"))
	}
	return ""
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
