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
  RFC3864:
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

One-time passcodes delivered via email are widely used as part of flows which require verification
of a user's contact information. Sign-in/-up flows, reauth for high-risk transactions, account
recovery, and so on all might reasonably rely on verifying a user's access to a particular email
address by sending a secret code to that address, and waiting for the user to prove that they know
what code was sent by typing it into some other context.

Today, actions which require verification through email will begin in one context (say, a sign-in
form on a website), but require users to hop to another context (their rMUA) to track down the
relevant email after waiting for delivery, memorize a short code, and then hop back to the
verifying context to type it in. This flow is frustrating, as context-switching leads to confusion
and failure. It's also phishable, as users can be tricked into typing a code meant for a trusted
context into an attacker-controlled site.

{{SMS-ONE-TIME-CODES}} showed that a machine-readable, origin-bound format for SMS-based OTPs can
reduce both frustration and phishing by making it possible for software to easily extract OTPs
and feed them into systems like {{WEBOTP}} or a platform's autofill mechanism. This approach can
dramatically reduce the friction users experience, _only_ in those cases where the context into
which the code is delivered can be verified to be the destination to which the code has asserted
a binding. This doesn't prevent phishing as users can still be tricked into typing the code
manually, but it's a substantial improvement in the system's general security posture.

Leaning on that experience, this document proposes extending the core concept of a standardized
delivery format from SMS to email, taking advantage of email's distinction between headers and
user-visible content to do so.


## Examples

A typical email-based OTP message could contain a header like the following, specifying an OTP code
of 123456, and binding that code to the origin `https://example.com`:

~~~header
OTP-Token: "123456"; origin="https://example.com"
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
*   `received`: a timestamp set by the rMUA when the OTP is received.


# The `OTP-Token` Header Field {#otp-token-header}

The `OTP-Token` header field delivers an origin-bound OTP. For example:

~~~header
OTP-Token: "123456"; origin="https://example.com"
~~~

This header is a Structured Field containing a String (Section 3.3.3 of {{STRUCTURED-FIELDS}})
representing the OTP, along with Parameters (Section 3.1.2 of {{STRUCTURED-FIELDS}})
representing the origin to which the OTP is bound.

`OTP-Token` MUST appear at most once in a message's header section. Instances appearing in the
header sections of MIME body parts MUST be ignored.

Note that headers might exceed the 998/78 character limitations specified in Section 2.2.3 of
{{RFC5322}}, and will be folded accordingly. {{parsing}} specifies how that case is to be handled.


## Parameters {#parameters}

The `OTP-Token` header MUST contain an `origin` Parameter:

*   `origin`: This parameter represents the origin to which the OTP is bound. Its value is a String
    containing the ASCII serialization of an origin conforming to Section 6.2 of {{RFC6454}}. This
    value MUST not be the serialization of an opaque origin ("null"), MUST be a potentially
    trustworthy origin as defined in {{SECURE-CONTEXTS}}, and MUST be in canonical form (lowercase,
    default ports omitted, ASCII-only).

    Note: {{RFC6454}} and {{URL}}/{{HTML}} do not entirely agree on origins or their serialization.
    The constraints above keep them more or less aligned for the subset of origins this document
    permits; reconciliation beyond that is well outside this document's scope.

Unknown Parameters are ignored in order to make future expansion possible if necessary (such as the
supplemental verification tokens discussed in {{future-work}}).


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
8.  Return a new One-Time Passcode whose:
    *   `code` is `parsed`'s `bare_item`
    *   `origin` is `origin`
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


## Shouldn't we focus on more robustly phishing-resistant authentication?

Authentication mechanisms like federation and {{WEBAUTHN}} are clearly the directions in which the
ecosystem should move. Improvements to OTP delivery are not arguments in the other direction. Still,
it's important to recognize that email verification often serves as a last-resort fallback mechanism
for account recovery. This document's proposal aims only to create low-cost opportunities to
mitigate some of that validation path's inherent risks (and see {{future-work}} for discussion of
potential mechanisms to further mitigate manual phishing risks).


## Origin Binding {#origin-binding}

TODO: Say something here about identifying the initiating context's origin and how it'll all be
platform-specific. Also note that these proposals address only one piece of a larger system by
allowing automated extraction of OTPs, but leave important, platform-specific details of their
integration with the rest of the system out of scope. Those mechanisms will be defined elsewhere
(e.g. HTML defines `<input autocomplete="one-time-code">`, iOS defines `NSTextInput` with
`.oneTimeCode`, and so on), so the most we can say here is that matching origins at the boundary
points is a cricial part of any security improvement this proposal offers.


# IANA Considerations

IANA is asked to update the Provisional Message Header Field Names registry {{RFC3864}} with the
following entry:

* Header Field Name: OTP-Token
* Protocol: mail
* Status: provisional
* Author/Change controller: Mike West
* Reference: This document
* Related information: None


# Future Work {#future-work}

This document defines the simplest possible thing, matching the capabilities that the standardized
SMS format offers. Given that we have a header which isn't human-visible (at least, not without
effort), there are likely improvements we could explore that could increase the system's robustness.

## Distinguishing Automated Delivery

Origin-bound OTPs as described here are an incomplete solution to phishing only insofar as they
support systems which make it easy to hand the OTP to its asserted origin. In a perfect world,
users would become accustomed to the low-friction automation of such a system, and would see the
requiement to manually type an OTP into a page whose origin didn't match the OTPs assertion as an
indication that something was off.

While we're waiting for the ubiquity of user expectations around such systems, it might be possible
to help sites distinguish between manually-typed OTPs and those delivered via an automated system.
This distinction seems potentially useful as an additional signal for risk analysis, as the latter
can be trusted to perform security checks that the former might mistakenly bypass.

The simplest version of this distinction could add a supplemental validation token to the
`OTP-Token` header that would be difficult for a human to access:

~~~header
OTP-Token: "123456"; origin="https://example.com"; token=:NjU0MzIx:
~~~

In this model, the `token` parameter would carry a high-entropy Byte Sequence (Section 3.3.5 of
{{STRUCTURED-FIELDS}}); think of it as a second, longer OTP. Because this value resides only in
email headers, it won't be visible to users in the message body, and will therefore be difficult
to ask users to copy/paste into a form.

Automated systems could deliver this token alongside (or instead of?) the human-visible OTP after
matching the asserted origin, and refuse to hand it over in the absence of such a match. Sites
receiving OTPs could take the presence of this token as a strong signal that the entity submitting
the form had access to the entire email, not just to a portion of it that a user might have typed
elsewhere.


Because manual entry carries an inherently higher risk of phishing or relay attacks, relying
parties could treat OTP-only submissions as higher risk, potentially requiring (another) step-up
authentication, restricting sensitive actions, or tightening session lifetimes.


# Open Questions

1.  Is specifying a single `origin` enough? Do we need scoping rules to tie OTPs to multiple
    origins? Sites rather than origins?
2.  Rather than relying on the relying party to examine the `received` timestamp, should we offer a
    `ttl`/`expires` Parameter after which the automated system would refuse to offer the OTP?
3.  Should we try to create tighter checks for the OTP's specified origin? That is, should we only
    accept origin bindings that can be authenticated via DKIM/DMARC?

And, of course, we should bikeshed the header's name: `OTP-Token`, `OTP`, `One-Time-Passcode`,
`Super-Secret-Thing-That-Humans-Should-Not-Read`, etc.

--- back

# Acknowledgments
{:numbered="false"}

This can be considered an email-based implementation of {{SMS-ONE-TIME-CODES}}, which paved the way
to formalizing a machine-readable format for these short-lived verification codes.
