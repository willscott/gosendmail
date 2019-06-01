package lib

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net/mail"
	"os/exec"
	"strings"

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
	Sender string
	SourceDomain string
	Rcpt string
	DestDomain string
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

	dest, err := ap.Parse(header.Get("To"))
	if err != nil {
		log.Fatal(err)
	}

	_, toHost := splitAddress(dest.Address)

	return ParsedMessage{
		Sender: sender.Address,
		SourceDomain: fromHost,
		Rcpt: dest.Address,
		DestDomain: toHost,
		Message: m,
	}
}

func SignMessage (msg *[]byte, parsed ParsedMessage, cfg *Config) error {
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

	keycmd := strings.Split(cfg.SendCommand, " ")
	pkey, err := exec.Command(keycmd[0], keycmd[1:]...).Output();
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
