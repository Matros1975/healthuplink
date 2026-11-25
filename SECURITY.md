# Security policy

## Supported versions

Security fixes go into the latest minor release of the receiver and of the Swift package. Please update to it before reporting.

## Reporting a vulnerability

Please do not open a public issue. Report privately in one of two ways:

- GitHub private vulnerability reporting: the "Report a vulnerability" button on this repository's Security tab;
- e-mail to support@front-side-solutions.com with "SECURITY" in the subject.

Say what is affected, how to reproduce it, and what an attacker gains. Please leave real health data out of the report.

You will get a first answer within 7 days. We will tell you when a fix is released. There is no bug bounty.

## Scope

- the receiver (`receiver/`), including its MCP endpoint;
- the data contract and test vectors (`contract/`);
- the Swift sealing and signing package (`swift/HealthUplinkSeal/`);
- the Health Uplink iPhone app. Its code is not public, but report problems in it the same way.

What the encryption is meant to protect, and what it is not, is described in the security write-up (`docs/security.html`, also on https://healthuplink.front-side-solutions.com/security.html).
