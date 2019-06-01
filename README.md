GoSendmail
===

A subset of sendmail functionality designed for modern security mail sending
practices for a single user. An outbound mail transfer agent combines a
number of different functions:

* Seeting a message ID to identify a new message.
* DKIM signing / authorization of email.
* Finding the destination mail server(s) for the message.
* Speaking the SMTP protocol, hopefully with TLS for delivery.

Gosendmail splits this functionality to support sandboxing. A first command,
`signmail` will parse stdin as a mail as a traditional `sendmail` would.
It runs santization and dkim signing, and then passes the signed message
to another process, rousted based on the sending domain.

`sendmail` takes an already signed message, and manages the actual sending
to remote servers.

Why
---

A modern single-user setup often involves a cloud server operating as a
primary host for a domain. Such a server may become compromised, and often
operates with lower trust than a user's personal machine. As such, it is
desirable to minimize the cost of compromise. The design of gosendmail
is structured for the following properties:

* Mail comes from a cloud server, and the StartTLS encryption from the
mail delivery can be accompanied by a valid client certificate of the sending
domain based on a letsencrypt cert maintained on the web server.
* Mail is signed with DKIM with a key that isn't on the cloud server.
* DKIM key can be encrypted such that mail sending requires interactive
user involvement.
