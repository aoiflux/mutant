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
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"mutant/object"
)

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

	spfHeader := parsed.Header.Get("Received-SPF")
	dkimHeader := parsed.Header.Get("DKIM-Signature")
	authHeader := parsed.Header.Get("Authentication-Results")

	spf := classifySPF(spfHeader + " " + authHeader)
	dkim := classifyDKIM(dkimHeader + " " + authHeader)
	dmarc := classifyDMARC(authHeader)

	return resultAndError(makeHashObject(map[string]object.Object{
		"spf":                    stringObj(spf),
		"dkim":                   stringObj(dkim),
		"dmarc":                  stringObj(dmarc),
		"received_spf":           stringObj(spfHeader),
		"dkim_signature_present": boolObj(strings.TrimSpace(dkimHeader) != ""),
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

func classifySPF(input string) string {
	lower := strings.ToLower(input)
	switch {
	case strings.Contains(lower, "spf=pass") || strings.Contains(lower, " pass "):
		return "pass"
	case strings.Contains(lower, "spf=fail") || strings.Contains(lower, " fail "):
		return "fail"
	case strings.Contains(lower, "spf=softfail"):
		return "softfail"
	default:
		return "unknown"
	}
}

func classifyDKIM(input string) string {
	lower := strings.ToLower(input)
	switch {
	case strings.Contains(lower, "dkim=pass") || strings.Contains(lower, " dkim-signature"):
		return "pass"
	case strings.Contains(lower, "dkim=fail"):
		return "fail"
	default:
		return "unknown"
	}
}

func classifyDMARC(input string) string {
	lower := strings.ToLower(input)
	switch {
	case strings.Contains(lower, "dmarc=pass"):
		return "pass"
	case strings.Contains(lower, "dmarc=fail"):
		return "fail"
	default:
		return "unknown"
	}
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
