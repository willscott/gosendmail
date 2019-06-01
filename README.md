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

GoSendmail is an originating mail transfer agent for such a threat model.

It is designed as a counterpoint to e.g.
[maildiranasaurus](https://github.com/flashmob/maildiranasaurus), which
would receive mail on such semi-trusted server.

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
to another process, routed based on the sending domain. This is
meant to be an `ssh` wrapped `sendmail` binary.

`sendmail` runs on the semi-trusted server, takes an already signed message,
and manages the actual sending to remote servers.

Usage
---

* `go build ./cmd/sendmail ./cmd/signmail`
* `sendmail` copied to cloud server.
* Modify `config.json` to point to relevant keys / domain.
* set your local MTA sendmail endpoint to the local `signmail` binary.
