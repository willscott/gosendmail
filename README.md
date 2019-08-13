GoSendmail
===

A subset of sendmail functionality for modern self hosting.

Motivation
---

Traditional models of email security are designed around a
trusted mail server, and semi-trusted user agents. The mail server should
continue to perform reasonably even if an end-user machine is compromised.
For single-user domains, realistic threat models are more likely to
involve compromise of the publicly connected server, motivating a design
minimizing trust in the front server.

GoSendmail is an originating mail transfer agent for this threat model.

It is designed as a counterpoint to
[maildiranasaurus](https://github.com/flashmob/maildiranasaurus), which
receives email on a semi-trusted server.

Features
---

* Sends from an authoritative / stable IP, supporting StartTLS, and with
client certificates proving the authoritative sender.
* Mail DKIM signed with a key that isn't on the authoritative server.

Design
---
gosendmail provides two binaries which together provide:

* Santitizing / writing a message ID to identify a new message.
* DKIM signing / authorization of email.
* Finding the destination mail server(s) for the message.
* Speaking the SMTP protocol over secured TLS for delivery.

`signmail` parses stdin for mail sent via a `mutt`-like program.
It runs santization and dkim signing, and then passes the signed message
to another process, based on the sending domain. The sub-process
interaction is designed to be interoperable with the semantics of
`sendmail`. (e.g. the final email body is passed to stdin.)

`sendmail` runs on a semi-trusted server, takes an already signed message,
and performs the actual sending to remote MTSs.

Usage
---

* `go build ./cmd/sendmail ./cmd/signmail`
* copy `sendmail` to your cloud server (or build it there).
* Modify `config.json` for relevant keys and domain(s).
* Configure Mutt or your MTA to send using the `signmail` binary.
* Use the environmental variables `GOSENDMAIL_TLS` and `GOSENDMAIL_SELFSIGNED`
  when insecure mail delivery is desirable. These variable will be read by
  the sendmail binary, a can be propagated through SSH.

Configuration Options
---

Environmental Variables

* `GOSENDMAIL_TLS` - set to a false-y ("false", "0") value to skip StartTLS
* `GOSENDMAIL_SELFSIGNED` - set to a true value ("true", "1") to allow
   TLS handshakes with servers that present invalid certificates.
* `GOSENDMAIL_RECIPIENTS` - overrides the addresses the message will be sent
   to. This helps support partial resumption of remaining recipients and BCC.
   If not specified, recipients will be loaded from the To, CC, and BCC fields.

Configuration Options (signmail)

* `DkimKeyCmd` The subprocess to execute to retrieve the bytes of the dkim signing key.
* `DkimSelector` The DKIM selector, a part of the DKIM dns record. (default: 'default')
* `SendCommand` The subprocess to use to send signed messages via the semi-trusted server.

Configuration Options (sendmail)

* `DialerProxy` A URL (e.g. `socks5://...`) that connections to remote MTAs will be
   dialed through.
* `TLSCert` The certificate file for the sender (client) to use for self authentication.
* `TLSKey` The corresponding private key file for the sending client to use.
