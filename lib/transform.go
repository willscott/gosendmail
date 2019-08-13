package lib

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log"
	"net/mail"
	"os/exec"
	"strings"
	"time"

	dkim "github.com/toorop/go-dkim"
)

// RemoveHeader strips a single header from a byte array representing a full email
// message.
func RemoveHeader(msg *[]byte, header string) {
	// line endings.
	if bytes.Index(*msg, []byte{13, 10, 13, 10}) < 0 {
		// \n -> \r\n
		*msg = bytes.Replace(*msg, []byte{10}, []byte{13, 10}, -1)
	}

	startPtr := 0
	endPtr := bytes.Index(*msg, []byte{13, 10, 13, 10})
	if endPtr == -1 {
		log.Fatal("couldn't locate end of headers.")
	}
	out := make([]byte, 0, len(*msg))
	match := []byte(header + ":")
	for startPtr < endPtr {
		nextPtr := bytes.Index((*msg)[startPtr:], []byte{13, 10}) + 2
		// headers keep going until a line that doesn't start with space/tab
		for (*msg)[startPtr+nextPtr] == byte(' ') || (*msg)[startPtr+nextPtr] == byte('	') {
			nextPtr = nextPtr + bytes.Index((*msg)[startPtr+nextPtr:], []byte{13, 10}) + 2
		}

		if !bytes.HasPrefix((*msg)[startPtr:], match) {
			out = append(out, (*msg)[startPtr:startPtr+nextPtr]...)
		}
		startPtr += nextPtr
	}
	out = append(out, (*msg)[endPtr:]...)
	*msg = out
}

// Santitize message takes a byte buffer of an Email message, along with configuration
// for the sending domain, and uses these to transform the message into one that is
// more privacy preserving - in particular by quantizing identifying dates and
// message IDs. The byte buffer of the message is modified in-place.
func SanitizeMessage(parsed ParsedMessage, cfg *Config) error {
	// line endings.
	if bytes.Index(*parsed.Bytes, []byte{13, 10, 13, 10}) < 0 {
		// \n -> \r\n
		*parsed.Bytes = bytes.Replace(*parsed.Bytes, []byte{10}, []byte{13, 10}, -1)
	}

	// Remove potentially-revealing headers.
	removedHeaders := []string{"Date", "Message-ID", "BCC"}
	for _, h := range removedHeaders {
		RemoveHeader(parsed.Bytes, h)
	}

	// set date
	header := "Date: " + time.Now().Truncate(15*time.Minute).UTC().Format(time.RFC1123Z) + "\r\n"
	*parsed.Bytes = append([]byte(header), *parsed.Bytes...)

	// set message id
	hasher := sha256.New()
	io.Copy(hasher, parsed.Body)
	hex := hex.EncodeToString(hasher.Sum(nil))
	header = "Message-ID: <" + hex + "@" + parsed.SourceDomain + ">\r\n"
	*parsed.Bytes = append([]byte(header), *parsed.Bytes...)

	// Reload the parsed Message from the sanitized version.
	m, err := mail.ReadMessage(bytes.NewReader(*parsed.Bytes))
	if err != nil {
		return err
	}
	parsed.Message = m

	return nil
}

// SignMessage takes a message byte buffer, and adds a DKIM signature to it
// based on the configuration of the sending domain. the buffer is modified
// in place.
func SignMessage(parsed ParsedMessage, cfg *Config) error {
	// Determine which subset of headers are included in the signature.
	recommendedHeaders := []string{
		"from", "sender", "reply-to", "subject", "date", "message-id", "to", "cc",
		"mime-version", "content-type", "content-transfer-encoding", "content-id",
		"content-description", "resent-date", "resent-from", "resent-sender", "resent-to",
		"resent-cc", "resent-message-id", "in-reply-to", "references", "list-id", "list-help",
		"list-unsubscribe", "list-subscribe", "list-post", "list-owner", "list-archive"}
	recommendedSet := make(map[string]struct{}, len(recommendedHeaders))
	for _, s := range recommendedHeaders {
		recommendedSet[s] = struct{}{}
	}
	filteredHeaders := make([]string, 0)
	for h, v := range parsed.Message.Header {
		hl := strings.ToLower(h)
		if _, ok := recommendedSet[hl]; ok {
			for i := 0; i < len(v); i++ {
				filteredHeaders = append(filteredHeaders, hl)
			}
		}
	}

	// Load the key for signing.
	keycmd := strings.Split(cfg.DkimKeyCmd, " ")
	pkey, err := exec.Command(keycmd[0], keycmd[1:]...).Output()
	if err != nil {
		log.Fatalf("Could not retreive DKIM key: %v\n", err)
	}

	selector := "default"
	if cfg.DkimSelector != "" {
		selector = cfg.DkimSelector
	}

	// Sign.
	options := dkim.NewSigOptions()
	options.PrivateKey = pkey
	options.Domain = parsed.SourceDomain
	options.Selector = selector
	options.SignatureExpireIn = 0
	options.Headers = filteredHeaders
	options.AddSignatureTimestamp = false
	options.Canonicalization = "relaxed/relaxed"

	return dkim.Sign(parsed.Bytes, options)
}
