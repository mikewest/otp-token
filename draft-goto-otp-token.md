---
title: "The `OTP-Token` Email Header Field"
abbrev: "otp-token"
category: std

docname: draft-goto-otp-token-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "One Time Password Authentication"
keyword:
  - one-time passcode
  - otp
  - email
  - phishing
  - autofill
venue:
  github: "mikewest/otp-token"
  latest: "https://mikewest.github.io/otp-token/draft-goto-otp-token.html"

author:
 -
    fullname: Sam Goto
    organization: Google
    email: goto@google.com
 -
    fullname: Mike West
    organization: Google
    email: mkwst@google.com

normative:
  RFC5322:
  RFC5598:
  RFC6454:
  STRUCTURED-FIELDS: RFC9651
  SECURE-CONTEXTS:
    title: "Secure Contexts"
    author:
     -
       ins: M. West
       name: Mike West
    date: false
    target: https://w3c.github.io/webappsec-secure-contexts/
  WEBAUTHN:
    title: "Web Authentication: An API for accessing Public Key Credentials"
    date: false
    target: https://w3c.github.io/webauthn/

informative:
  HTML:
    title: "HTML Standard"
    date: false
    target: https://html.spec.whatwg.org/
  SMS-ONE-TIME-CODES:
    title: "Origin-bound one-time codes delivered via SMS"
    author:
     -
       ins: T.O'Connor
       name: Theresa O'Connor
     -
       ins: S. Goto
       name: Sam Goto
    date: 2021
    target: https://wicg.github.io/sms-one-time-codes/
  URL:
    title: "URL Standard"
    date: false
    target: https://url.spec.whatwg.org/
  WEBOTP:
    title: "WebOTP API"
    author:
     -
       ins: S. Goto
       name: Sam Goto
    date: false
    target: https://wicg.github.io/web-otp/
...

--- abstract

This document defines the `OTP-Token` email header field, which can be used to deliver One-Time
Passcodes (OTP) in a machine-readable and origin-bound manner alongside the human-readable message
carrying that content today. Recipient Message User Agents (rMUA) can collaborate with other
entities in the ecosystem to assist in the delivery of these codes to the context which wishes to
verify their successful delivery.


--- middle

# Introduction

Email-based OTPs are critical infrastructure in the status quo. They're used for address
verification, sign-in, authorization of high-risk transactions, and account recovery. They often
sit underneath more robust verification mechanisms, setting a relatively low security floor.

Today, actions which require verification through email will begin in one context, then hop to an
email client, where users will track down the relevant email (after waiting for delivery), memorize
a short code, hop back to the verifying context, and type it in. This flow is both frustrating and
phishable.

{{SMS-ONE-TIME-CODES}} showed that a machine-readable, origin-bound format for SMS-based OTPs is
deployable. Today, software can easily extract these codes and feed them into systems like
{{WEBOTP}} which reduce friction only after validating the origin binding.

This document extends that concept from SMS to email, and takes advantage of the fact that an
email-based delivery mechanism has both user-visible content and a header section that's cumbersome
for humans to access. The former can carry on doing what it does today: delivering a low-entropy
code addressed to humans. The latter can carry information beyond what would be reasonable to expect
a human to handle, which we can use to increase the entire system's robustness.

This machine-readable format enables three improvements:

1.  We can reduce friction for users by allowing rMUAs to collaborate with other systems, offering
    OTPs to the requesting context without requiring users to act as the messenger.

2.  We can mitigate phishing by reducing friction _only_ for context matching the origin to which
    the OTP is bound. Software can perform this check more consistently than humans.

3.  We can provide an additional signal about the way in which the OTP was delivered by encoding
    information in the header that humans are unlikely to process themselves. Relying parties can
    thereby distinguish codes transmitted through an origin-bound automated path from those which
    a user might have been tricked into typing into an attackers' form, enabling more nuanced risk
    assessment.

This document defines a format and parsing rules. Work to define the interaction between rMUAs and
the rest of the ecosystem will happen elsewhere.

## Examples

A typical email-based OTP message could contain the following header, specifying an OTP code of
123456, and binding that code to the origin `https://example.com`:

~~~header
OTP-Token: "123456"; origin="https://example.com"
~~~

Beyond that human-readable-and-therefore-phishable code, the header can also include an additional
token, meant not for the user themselves, but for the systems acting on their behalf. Because
headers are not generally rendered to users without effort, presenting this token is (imperfect)
evidence that an automated system delivered the data, enabling more nuanced risk assessment:

~~~header
OTP-Token: "123456"; origin="https://example.com"; token=:NjU0MzIx:
~~~


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document relies on {{RFC5598}} to define Recpient Mail User Agents (rMUA) and other aspects of
email infrastructure.

This document further relies on Section 3 of {{STRUCTURED-FIELDS}} to define a number of concepts
around parsing and syntax, including: String, Byte Sequence, Parameters, and the `sf-item` ABNF
rule.

This document relies on {{RFC6454}} for the definition of an origin, and on Section 6.2 of that
document for its ASCII serialization. The `serialized-origin` grammar is defined in Section 7.1.

## One-Time Passcode

A One-Time Passcode is a tuple consisting of:

*   `code`: a string, containing the human-readable OTP.
*   `origin`: an origin to which the code is bound.
*   `token`: `null` or a byte sequence carrying a machine-readable value intended for automated
    consumption.
*   `received`: a timestamp set by the rMUA when the OTP is received.


# The `OTP-Token` Header Field {#otp-token-header}

The `OTP-Token` header field delivers an origin-bound OTP, optionally including a high-entropy
token. For example:

~~~header
OTP-Token: "123456"; origin="https://example.com"; token=:NjU0MzIx:
~~~

This header is a Structured Field containing a String (Section 3.3.3 of {{STRUCTURED-FIELDS}})
representing the OTP, along with with Parameters (Section 3.1.2 of {{STRUCTURED-FIELDS}})
representing the origin to which the OTP is bound, and an optional high-entropy token.

`OTP-Token` MUST appear at most once in a message's header section. Instances appearing in the
header sections of MIME body parts MUST be ignored.

Note that headers including a `token` Parameter are likely to exceed the 998/78 character
limitations specified in Section 2.2.3 of {{RFC5322}}, and will be folded accordingly. {{parsing}}
specifies how that common case is to be handled.


## Parameters {#parameters}

The `OTP-Token` header MUST contain an `origin` Parameter, and MAY contain a `token` Parameter:

*   `origin`: This parameter represents the origin to which the OTP is bound. Its value is a String
    containing the ASCII serialization of an origin conforming to Section 6.2 of {{RFC6454}}. This
    value MUST not be the serialization of an opaque origin ("null"), MUST be a potentially
    trustworthy origin as defined in {{SECURE-CONTEXTS}}, and MUST be in canonical form (lowercase,
    default ports omitted, ASCII-only).

    Note: {{RFC6454}} and {{URL}}/{{HTML}} do not entirely agree on origins or their serialization.
    The constraints above keep them more or less aligned for the subset of origins this document
    permits; reconciliation beyond that is well outside this document's scope.


*   `token`: This parameter represents a validation token associated with the OTP that's meant for
    automated systems rather than human interaction. Its value is a Byte Sequence .

Unknown Parameters are ignored in order to make future expansion possible if necessary.


## Parsing {#parsing}

The following algorithm describes the process of parsing and validating the `OTP-Token` header into
an One-Time Passcode object, given a `message` and `receipt-timestamp`. Parsing fails if no valid
OTP is available:

1.  If `message`'s header section contains zero or more than one `OTP-Token` header, fail.
2.  Let `value` be the result of unfolding `message`'s header section's `OTP-Token` header as
    specified in Section 2.2.3 of {{RFC5322}}.
3.  Let `parsed` be the result of parsing `value` as specified in Section 4.2 of
    {{STRUCTURED-FIELDS}}, with a `field_type` of "item". If parsing `value` as a Structured Field
    fails, fail.
4.  If `parsed`'s `bare_item` is not a String, fail.
5.  If `parsed`'s `parameters` contains no item whose key is "origin", fail.
6.  Let `origin` be the value of `parsed`'s `parameters`' item whose key is "origin".
7.  Fail if any of the following conditions are true:
    *   `origin` is not a String
    *   `origin` does not conform to the `serialized-origin` grammar defined in Section 7.1
        of {{RFC6454}}.
    *   `origin` is "null"
    *   `origin` is not canonical, per {{parameters}}.
8.  Let `token` be `null`.
9.  If `parsed`'s `parameters` contains an item whose key is "token":
    1.  Fail if its value is not a Byte Sequence.
    2.  Set `token` to its value.
10. Return a new One-Time Passcode whose:
    *   `code` is `parsed`'s `bare_item`
    *   `origin` is `origin`
    *   `token` is `token`
    *   `received` is `receipt-timestamp`

Note: {{STRUCTURED-FIELDS}} has no concept of header folding. The ordering of steps 2 and 3 above is
therefore necessary to enable proper parsing of message headers.

## Syntax

The header's ABNF is as follows:

~~~abnf
otp-token = sf-item
~~~


# Security Considerations

TODO. Probably something about DKIM?

## `token` Availability?

The `token` value is a bearer token. Its usefulness rests entirely upon its general invisibility to
humans, meaning that a user tricked into inputing an OTP will not be able to easily hand it over.

While this seems accurate, it is not impossible to overcome. Users could be socially engineered into
accessing the message headers via an rMUA's "show original" affordance. Or they could be convinced
to forward the email to an attacker, headers and all. Likewise, the `token` is only as secure as the
mailbox itself.

In short, `token` can raise the bar for an attacker, but it does not absolutely prevent phishing.


## Shouldn't we focus on more robustly phishing-resistant authentication?

Authentication mechanisms like federation and {{WEBAUTHN}} are clearly the directions in which the
ecosystem should move. Improvements to OTP delivery are not arguments in the other direction. Still,
it's important to recognize that email verification often serves as a last-resort fallback mechanism
for account recovery. This document's proposal aims only to create low-cost opportunities to
mitigate some of that validation path's inherent risks.


# IANA Considerations

IANA is asked to update the Provisional Message Header Field Names registry {{RFC3864}} with the
following entry:

* Header Field Name: OTP-Token
* Protocol: mail
* Status: provisional
* Author/Change controller: Mike West
* Reference: This document
* Related information: None


# Open Questions

1.  Is specifying a single `origin` enough? Do we need scoping rules to tie OTPs to multiple
    origins? Sites rather than origins?
2.  Rather than relying on the relying party to examine the `received` timestamp, should we offer a
    `ttl`/`expires` Parameter after which the automated system would refuse to offer the OTP?
3.  Should we try to create tighter checks for the OTP's specified origin? That is, should we only
    accept origin bindings that can be authenticated via DKIM/DMARC?

And, of course, we should bikeshed the naming. `OTP-Token`, `One-Time-Passcode`,
`Super-Secret-Thing-That-Humans-Should-Not-Read`, etc.

--- back

# Acknowledgments
{:numbered="false"}

This can be considered an email-based implementation of {{SMS-ONE-TIME-CODES}}, which paved the way
to formalizing a machine-readable format for these short-lived verification codes.
