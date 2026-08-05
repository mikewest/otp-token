---
###
# Internet-Draft Markdown Template
#
# Rename this file from draft-todo-yourname-protocol.md to get started.
# Draft name format is "draft-<yourname>-<workgroup>-<name>.md".
#
# For initial setup, you only need to edit the first block of fields.
# Only "title" needs to be changed; delete "abbrev" if your title is short.
# Any other content can be edited, but be careful not to introduce errors.
# Some fields will be set automatically during setup if they are unchanged.
#
# Don't include "-00" or "-latest" in the filename.
# Labels in the form draft-<yourname>-<workgroup>-<name>-latest are used by
# the tools to refer to the current version; see "docname" for example.
#
# This template uses kramdown-rfc: https://github.com/cabo/kramdown-rfc
# You can replace the entire file if you prefer a different format.
# Change the file extension to match the format (.xml for XML, etc...)
#
###
title: "The `OTP-Token` Email Header Field"
abbrev: "otp-token"
category: info

docname: draft-goto-otp-token-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: AREA
workgroup: WG Working Group
keyword:
 - next generation
 - unicorn
 - AI-native
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

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

informative:
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
...

--- abstract

This document defines the `OTP-Token` email header field, which can be used to deliver One-Time
Passcodes (OTP) in a machine-readable and origin-bound manner. This header can enable Recipient
Message User Agents (rMUA) to collaborate with other entities in the ecosystem to assist users'
need to convey these OTPs to various parties that rely on their successful delivery.


--- middle

# Introduction

The mechanism defined in this document allows the mechanical processing of email-based OTPs that
are common in the ecosystem today. This opens up a number of opportunities for collaboration in
ways which might improve the overall security of this verification mechanism.

Today, the expectation is that users will begin some action which requires verification (sign in,
account creation, some high-risk transaction, etc) in one context, and then hop over to their
email client, wait for receipt of an email containing an memorizable OTP, then hop back to the
original context and input that code to verify the action. This is both frustrating and phishable,
as hopping between contexts introduces many opportunities for confusion, memorizing or copy/pasting
codes is difficult, and nothing prevents users from delivering codes to the wrong context.

{{SMS-ONE-TIME-CODES}} showed that it's possible to devise a machine-readable format for SMS-based
OTPs that can express a clear origin binding, making it possible for automated systems to extract
these codes and feed them into systems which can help users input them into the right context.

This document extends that concept from SMS to email, taking advantage of the fact that an
email-based delivery mechanism has both user-visible content and headers that are often somewhat
complicated for users to access. The former can be used in exactly the way that it's used today,
crafting a message for humans that aims to help them verify themselves. The latter can feed
information to autofill systems that can directly support users' efforts to do so, while also
encoding additional information that users would have a hard time dealing with. The additional
information can help support risk-based evaluation systems in ways we'll discuss below.

## Examples

A typical email-based OTP message could contain the following header, specifying an OTP code of
123456, and binding that code to the origin `https://example.com`. rMUAs can collaborate with
other user agents to pass that code on in ways that can smooth the users' path towards
verification:

~~~header
OTP-Token: "123456"; origin="https://example.com"
~~~

Beyond the traditional OTP, which is suprisingly phishable, this mechanism could also include
an additional token, meant not for the user themselves, but for the systems which input the
OTP code on their behalf. Given that this token is delivered out-of-band with the visible email
content, it can be reasonable assumed to be available only when an automated system acting on the
users' behalf has delivered the OTP. This could enable differential risk assessments to assign
more granular levels of trust to user verifications:

~~~header
OTP-Token: "123456"; origin="https://example.com"; \
           token=:SGVsbG8sIHdvcmxkIQ==:
~~~


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document relies on {{RFC5598}} to define Recpient Mail User Agents (rMUA) and other aspects of
email infrastructure.

This document further relies on Section 3 of {{STRUCTURED-FIELDS}} to define a number of concepts
around parsing and syntax, including: String, Byte Sequence, Parameters, and the `sf-item` ABNF
rule.

The `serialized-origin` grammar is defined in Section 7.1 of {{RFC6454}}.


# The `OTP-Token` Header Field {#otp-token-header}

The `OTP-Token` header field delivers an origin-bound OTP, optionally including a high-entropy
token. For example:

~~~header
OTP-Token: "123456"; origin="https://example.com"; token=:SGVsbG8sIHdvcmxkIQ==:
~~~

This header is a Structured Field containing a String (Section 3.3.3 of {{STRUCTURED-FIELDS}})
representing the OTP, along with with Parameters (Section 3.1.2 of {{STRUCTURED-FIELDS}})
representing the origin to which the OTP is bound, and an optional high-entropy token.

## Parameters

The `OTP-Token` header MUST contain an `origin` Parameter, and MAY contain a `token` Parameter:

*   `origin`: This parameter represents the origin to which the OTP is bound. Its value is a String
    containing the ASCII serialization of an origin conforming to Section 6.2 of {{RFC6454}}.

*   `token`: This parameter represents a validation token associated with the OTP that's meant for
    automated systems rather than human interaction. Its value is a Byte Sequence .

Unknown Parameters are ignored in order to make future expansion possible if necessary.


## Parsing

OTPs are a tuple consisting of an `otp` (a string), an `origin` (a string), and an optional `token`
(`null` or a byte sequence).

The following algorithm describes the process of parsing and validating the `OTP-Token` header into
an OTP object, given the header section of a message. Parsing fails if no valid OTP is available:

1.  If the header section contains more than one `OTP-Token` header, or does not contain any
    `OTP-Token` header, fail parsing.
2.  Let `parsed` be the result of parsing the header section's `OTP-Token` header as specified in
    Section 4.2 of {{STRUCTURED-FIELDS}}, using the field's value as `input_bytes`, and a
    `field_type` of "item".
3.  If parsing fails, fail parsing.
4.  If `parsed`'s `bare_item` is not a String, fail parsing.
5.  Fail parsing if `parsed`'s `parameters`:
    *   contains no item whose key is `origin`
    *   contains an item whose key is `token` and whose value is not a Byte Sequence,
    *   contains an item whose key is `origin` and whose value is not a String conforming to the
        `serialized-origin` grammar defined in Section 7.1 of {{RFC6454}}
7.  Let `result` be a new OTP whose:
    *   `otp` is `parsed`'s `bare_item`
    *   `origin` is the value of the item in `parsed`'s `parameters` whose key is `origin`
    *   `token` is the value of the item in `parsed`'s `parameters` whose key is `token`, or `null`
        if no such item is present.
8.  Return `result`.


## Syntax

The header's ABNF is as follows:

~~~abnf
otp-token = sf-item
~~~


# Security Considerations

TODO. Probably something about DKIM?


# IANA Considerations

IANA is asked to update the Provisional Message Header Field Names registry {{RFC5322}} with the
following entry:

* Header Field Name: OTP-Token
* Template:
* Protocol: mail
* Status:
* Trace:
* Reference: This document


--- back

# Acknowledgments
{:numbered="false"}

This can be considered an email-based implementation of {{SMS-ONE-TIME-CODES}}, which paved the way
to formalizing a machine-readable format for these short-lived verification codes.
