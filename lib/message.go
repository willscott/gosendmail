package lib

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net/mail"
	"os"
	"path"
	"strings"

	"github.com/spf13/viper"
)

func splitAddress(email string) (account, host string) {
	i := strings.LastIndexByte(email, '@')
	account = email[:i]
	host = email[i+1:]
	return
}

func joinAddresses(addresses []*mail.Address) string {
	out := ""
	for _, addr := range addresses {
		if addr != nil {
			if out != "" {
				out = out + ", " + addr.String()
			} else {
				out = addr.String()
			}
		}
	}
	return out
}

// ReadMessage scans a given io.Reader into a []byte.
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

// ParsedMessage represents a semi-structred email message.
type ParsedMessage struct {
	Sender       string
	SourceDomain string
	Rcpt         map[string][]string
	DestDomain   []string
	Bytes        *[]byte
	*mail.Message
}

// Hash provides an ideally stable handle for a message.
func (p ParsedMessage) Hash() string {
	hasher := sha256.New()

	// We re-parse bytes here because `msg.Body` can only be read once.
	m, err := mail.ReadMessage(bytes.NewReader(*p.Bytes))
	if err != nil {
		return ""
	}

	io.Copy(hasher, m.Body)
	return hex.EncodeToString(hasher.Sum(nil))
}

// FileName provides a stable location on disk for the message to serialize to.
func (p ParsedMessage) FileName() string {
	return path.Join(path.Dir(viper.ConfigFileUsed()), p.Hash()+".eml")
}

// UnmarshalText attempts to load a message from a textual pointer of its state.
func (p *ParsedMessage) UnmarshalText(b []byte) error {
	// attempt loading file from hash.
	hash := bytes.Index(b, []byte(" "))
	if hash == -1 {
		return errors.New("invalid cache line")
	}
	filename := path.Join(path.Dir(viper.ConfigFileUsed()), string(b[0:hash])+".eml")
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	dat, err := ioutil.ReadAll(file)
	if err != nil {
		return err
	}
	msg := ParseMessage(&dat)
	p.Bytes = &dat
	p.Sender = msg.Sender
	p.SourceDomain = msg.SourceDomain
	p.Message = msg.Message

	// set recipients.
	return p.SetRecipients(string(b[hash+1:]))
}

// MarshalText provides a textual handle of the message. The message contents is
// not included, and must be saved using `Save` for the marshal'ed handle to be
// considered durable.
func (p ParsedMessage) MarshalText() ([]byte, error) {
	// line format: <hash> <rcpts>
	return []byte(p.Hash() + " " + p.Recipients()), nil
}

// Save message to disk.
// TODO: support encryption of on-disk data.
func (p *ParsedMessage) Save() error {
	return ioutil.WriteFile(p.FileName(), *p.Bytes, 0600)
}

// Remove message data from disk if present.
func (p *ParsedMessage) Unlink() error {
	if _, err := os.Stat(p.FileName()); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(p.FileName())
}

// ParseMessage parses a byte array representating an email message
// to learn the sender, and intended recipients.
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
	defaultReceipients := joinAddresses(addrs)

	pm := ParsedMessage{
		Sender:       sender.Address,
		SourceDomain: fromHost,
		Message:      m,
		Bytes:        msg,
	}

	pm.SetRecipients(defaultReceipients)
	return pm
}

// SetRecipients sets the accounts and corresponding domains to which
// the email will be sent.
func (pm *ParsedMessage) SetRecipients(recipients string) error {
	ap := mail.AddressParser{}
	dests, err := ap.ParseList(recipients)
	if err != nil {
		return err
	}

	rcpts := make(map[string][]string)
	for _, addr := range dests {
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

	pm.Rcpt = rcpts
	pm.DestDomain = hosts
	return nil
}

// Recipients gets a comma separated list (AddressList) of recipients.
func (pm *ParsedMessage) Recipients() string {
	out := ""
	for _, dom := range pm.Rcpt {
		for _, addr := range dom {
			if out != "" {
				out = out + ", " + addr
			} else {
				out = addr
			}
		}
	}
	return out
}

// RecipientMap returns a map for identification of recipients,
// where map keys are recipients and map values are `true`.
func (pm *ParsedMessage) RecipientMap() map[string]bool {
	out := make(map[string]bool, 0)
	for _, dom := range pm.Rcpt {
		for _, addr := range dom {
			out[addr] = true
		}
	}
	return out
}

// RemoveRecipients updates the message.Recipients to no longer
// include a set of addresses specified in AddressList format.
func (pm *ParsedMessage) RemoveRecipients(other string) error {
	rcptMap := pm.RecipientMap()

	otherMsg := ParsedMessage{}
	otherMsg.SetRecipients(other)
	otherMap := otherMsg.RecipientMap()
	out := ""

	for rcpt, _ := range rcptMap {
		if _, ok := otherMap[rcpt]; !ok {
			if out != "" {
				out = out + ", " + rcpt
			} else {
				out = rcpt
			}
		}
	}
	return pm.SetRecipients(out)
}
