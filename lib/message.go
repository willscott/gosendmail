package lib

import (
	"bufio"
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

func splitAddress(email string) (account, host string) {
	i := strings.LastIndexByte(email, '@')
	account = email[:i]
	host = email[i+1:]
	return
}

func ReadMessage(reader io.Reader) []byte {
	scanner := bufio.NewScanner(reader)
	scanner.Split(bufio.ScanBytes)
	mailMsg := make([]byte, 0)
	for scanner.Scan() {
		mailMsg = append(mailMsg, scanner.Bytes()...)
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		log.Fatalf("reading message: %v", err)
	}
	return mailMsg
}

type ParsedMessage struct {
	Sender       string
	SourceDomain string
	Rcpt         map[string][]string
	DestDomain   []string
	*mail.Message
}

func ParseMessage(msg *[]byte) ParsedMessage {
	m, err := mail.ReadMessage(bytes.NewReader(*msg))
	if err != nil {
		log.Fatalf("reading msg: %v", err)
	}

	header := m.Header

	// parse out from
	ap := mail.AddressParser{}
	sender, err := ap.Parse(header.Get("From"))
	if err != nil {
		log.Fatal(err)
	}
	_, fromHost := splitAddress(sender.Address)

	// parse rcpt and dests from to / cc / bcc
	addrs := make([]*mail.Address, 0, 5)
	for _, f := range []string{"To", "CC", "BCC"} {
		for _, line := range header[f] {
			dests, err := ap.ParseList(line)
			if err != nil {
				log.Fatal(err)
			}
			addrs = append(addrs, dests...)
		}
	}

	rcpts := make(map[string][]string)
	for _, addr := range addrs {
		_, toHost := splitAddress(addr.Address)
		if _, ok := rcpts[toHost]; !ok {
			rcpts[toHost] = make([]string, 0)
		}
		rcpts[toHost] = append(rcpts[toHost], addr.Address)
	}
	var hosts []string
	for k := range rcpts {
		hosts = append(hosts, k)
	}

	return ParsedMessage{
		Sender:       sender.Address,
		SourceDomain: fromHost,
		Rcpt:         rcpts,
		DestDomain:   hosts,
		Message:      m,
	}
}

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

func SanitizeMessage(msg *[]byte, parsed ParsedMessage, cfg *Config) error {
	// line endings.
	if bytes.Index(*msg, []byte{13, 10, 13, 10}) < 0 {
		// \n -> \r\n
		*msg = bytes.Replace(*msg, []byte{10}, []byte{13, 10}, -1)
	}

	// Remove potentially-revealing headers.
	removedHeaders := []string{"Date", "Message-ID"}
	for _, h := range removedHeaders {
		RemoveHeader(msg, h)
	}

	// set date
	header := "Date: " + time.Now().Truncate(15*time.Minute).UTC().Format(time.RFC1123Z) + "\r\n"
	*msg = append([]byte(header), *msg...)

	// set message id
	hasher := sha256.New()
	io.Copy(hasher, parsed.Body)
	hex := hex.EncodeToString(hasher.Sum(nil))
	header = "Message-ID: <" + hex + "@" + parsed.SourceDomain + ">\r\n"
	*msg = append([]byte(header), *msg...)

	return nil
}

func SignMessage(msg *[]byte, parsed ParsedMessage, cfg *Config) error {
	// dkim sign
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

	keycmd := strings.Split(cfg.DkimKeyCmd, " ")
	pkey, err := exec.Command(keycmd[0], keycmd[1:]...).Output()
	if err != nil {
		log.Fatalf("Could not retreive DKIM key: %v\n", err)
	}

	selector := "default"
	if cfg.DkimSelector != "" {
		selector = cfg.DkimSelector
	}

	options := dkim.NewSigOptions()
	options.PrivateKey = pkey
	options.Domain = parsed.SourceDomain
	options.Selector = selector
	options.SignatureExpireIn = 0
	options.Headers = filteredHeaders
	options.AddSignatureTimestamp = false
	options.Canonicalization = "relaxed/relaxed"

	err = dkim.Sign(msg, options)
	if err != nil {
		log.Fatal(err)
	}
	return nil
}
