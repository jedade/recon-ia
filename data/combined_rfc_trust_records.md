# RFC 7208 — SPF — Sender Policy Framework

```






Internet Engineering Task Force (IETF)                      S. Kitterman
Request for Comments: 7208                  Kitterman Technical Services
Obsoletes: 4408                                               April 2014
Category: Standards Track
ISSN: 2070-1721


                     Sender Policy Framework (SPF)
           for Authorizing Use of Domains in Email, Version 1

Abstract

   Email on the Internet can be forged in a number of ways.  In
   particular, existing protocols place no restriction on what a sending
   host can use as the "MAIL FROM" of a message or the domain given on
   the SMTP HELO/EHLO commands.  This document describes version 1 of
   the Sender Policy Framework (SPF) protocol, whereby ADministrative
   Management Domains (ADMDs) can explicitly authorize the hosts that
   are allowed to use their domain names, and a receiving host can check
   such authorization.

   This document obsoletes RFC 4408.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 5741.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc7208.















Kitterman                    Standards Track                    [Page 1]

RFC 7208              Sender Policy Framework (SPF)           April 2014


Copyright Notice

   Copyright (c) 2014 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.

   This document may contain material from IETF Documents or IETF
   Contributions published or made publicly available before November
   10, 2008.  The person(s) controlling the copyright in some of this
   material may not have granted the IETF Trust the right to allow
   modifications of such material outside the IETF Standards Process.
   Without obtaining an adequate license from the person(s) controlling
   the copyright in such materials, this document may not be modified
   outside the IETF Standards Process, and derivative works of it may
   not be created outside the IETF Standards Process, except to format
   it for publication as an RFC or to translate it into languages other
   than English.

Table of Contents

   1. Introduction ....................................................5
      1.1. Terminology ................................................5
           1.1.1. Key Words ...........................................5
           1.1.2. Imported Definitions ................................5
           1.1.3. MAIL FROM Definition ................................6
           1.1.4. HELO Definition .....................................6
      1.2. check_host() ...............................................6
   2. Operational Overview ............................................6
      2.1. Publishing Authorization ...................................6
      2.2. Checking Authorization .....................................7
      2.3. The "HELO" Identity ........................................8
      2.4. The "MAIL FROM" Identity ...................................9
      2.5. Location of Checks .........................................9
      2.6. Results of Evaluation ......................................9
           2.6.1. None ...............................................10
           2.6.2. Neutral ............................................10
           2.6.3. Pass ...............................................10
           2.6.4. Fail ...............................................10




Kitterman                    Standards Track                    [Page 2]

RFC 7208              Sender Policy Framework (SPF)           April 2014


           2.6.5. Softfail ...........................................10
           2.6.6. Temperror ..........................................10
           2.6.7. Permerror ..........................................10
   3. SPF Records ....................................................11
      3.1. DNS Resource Records ......................................11
      3.2. Multiple DNS Records ......................................12
      3.3. Multiple Strings in a Single DNS Record ...................12
      3.4. Record Size ...............................................13
      3.5. Wildcard Records ..........................................13
   4. The check_host() Function ......................................14
      4.1. Arguments .................................................14
      4.2. Results ...................................................15
      4.3. Initial Processing ........................................15
      4.4. Record Lookup .............................................15
      4.5. Selecting Records .........................................15
      4.6. Record Evaluation .........................................16
           4.6.1. Term Evaluation ....................................16
           4.6.2. Mechanisms .........................................16
           4.6.3. Modifiers ..........................................17
           4.6.4. DNS Lookup Limits ..................................17
      4.7. Default Result ............................................18
      4.8. Domain Specification ......................................19
   5. Mechanism Definitions ..........................................20
      5.1. "all" .....................................................21
      5.2. "include" .................................................21
      5.3. "a" .......................................................23
      5.4. "mx" ......................................................23
      5.5. "ptr" (do not use) ........................................23
      5.6. "ip4" and "ip6" ...........................................25
      5.7. "exists" ..................................................25
   6. Modifier Definitions ...........................................26
      6.1. redirect: Redirected Query ................................26
      6.2. exp: Explanation ..........................................27
   7. Macros .........................................................28
      7.1. Formal Specification ......................................29
      7.2. Macro Definitions .........................................29
      7.3. Macro Processing Details ..................................30
      7.4. Expansion Examples ........................................32
   8. Result Handling ................................................33
      8.1. None ......................................................34
      8.2. Neutral ...................................................34
      8.3. Pass ......................................................34
      8.4. Fail ......................................................35
      8.5. Softfail ..................................................35
      8.6. Temperror .................................................36
      8.7. Permerror .................................................36





Kitterman                    Standards Track                    [Page 3]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   9. Recording the Result ...........................................36
      9.1. The Received-SPF Header Field .............................37
      9.2. SPF Results in the Authentication-Results Header Field ....39
   10. Effects on Infrastructure .....................................39
      10.1. Sending Domains ..........................................40
           10.1.1. DNS Resource Considerations .......................40
           10.1.2. Administrator's Considerations ....................41
           10.1.3. Bounces ...........................................41
      10.2. Receivers ................................................42
      10.3. Mediators ................................................42
   11. Security Considerations .......................................43
      11.1. Processing Limits ........................................43
      11.2. SPF-Authorized Email May Contain Other False Identities ..44
      11.3. Spoofed DNS and IP Data ..................................44
      11.4. Cross-User Forgery .......................................44
      11.5. Untrusted Information Sources ............................45
           11.5.1. Recorded Results ..................................45
           11.5.2. External Explanations .............................45
           11.5.3. Macro Expansion ...................................46
      11.6. Privacy Exposure .........................................46
      11.7. Delivering Mail Producing a "Fail" Result ................46
   12. Collected ABNF ................................................46
   13. Contributors and Acknowledgements .............................48
   14. IANA Considerations ...........................................49
      14.1. The SPF DNS Record Type ..................................49
      14.2. The Received-SPF Mail Header Field .......................50
      14.3. SPF Modifier Registry ....................................50
   15. References ....................................................50
      15.1. Normative References .....................................50
      15.2. Informative References ...................................51
   Appendix A. Extended Examples .....................................54
     A.1. Simple Examples ............................................55
     A.2. Multiple Domain Example ....................................56
     A.3. DNS Blacklist (DNSBL) Style Example ........................56
     A.4. Multiple Requirements Example ..............................57
   Appendix B. Changes in Implementation Requirements from RFC 4408 ..57
   Appendix C. Further Testing Advice ................................58
   Appendix D. SPF/Mediator Interactions .............................59
     D.1. Originating ADMDs ..........................................59
     D.2. Mediators ..................................................60
     D.3. Receiving ADMDs ............................................60
   Appendix E. Mail Services .........................................61
   Appendix F. MTA Relays ............................................61
   Appendix G. Local Policy Considerations ...........................62
     G.1. Policy for SPF Pass ........................................62
     G.2. Policy for SPF Fail ........................................62
     G.3. Policy for SPF Permerror ...................................63
     G.4. Policy for SPF Temperror ...................................63



Kitterman                    Standards Track                    [Page 4]

RFC 7208              Sender Policy Framework (SPF)           April 2014


1.  Introduction

   The current email infrastructure has the property that any host
   injecting mail into the system can use any DNS domain name it wants
   in each of the various identifiers specified by [RFC5321] and
   [RFC5322].  Although this feature is desirable in some circumstances,
   it is a major obstacle to reducing Unsolicited Bulk Email (UBE, aka
   spam).  Furthermore, ADMDs (as described in [RFC5598]) are
   understandably concerned about the ease with which other entities can
   make use of their domain names, often with malicious intent.

   This document defines a protocol by which ADMDs can authorize hosts
   to use their domain names in the "MAIL FROM" or "HELO" identities.
   Compliant ADMDs publish Sender Policy Framework (SPF) records in the
   DNS specifying which hosts are permitted to use their names, and
   compliant mail receivers use the published SPF records to test the
   authorization of sending Mail Transfer Agents (MTAs) using a given
   "HELO" or "MAIL FROM" identity during a mail transaction.

   An additional benefit to mail receivers is that after the use of an
   identity is verified, local policy decisions about the mail can be
   made based on the sender's domain, rather than the host's IP address.
   This is advantageous because reputation of domain names is likely to
   be more accurate than reputation of host IP addresses since domains
   are likely to be more stable over a longer period.  Furthermore, if a
   claimed identity fails verification, local policy can take stronger
   action against such email, such as rejecting it.

1.1.  Terminology

1.1.1.  Key Words

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   [RFC2119].

1.1.2.  Imported Definitions

   ABNF (Augmented Backus-Naur Form) ABNF is defined in [RFC5234], as
   are the tokens "ALPHA", "DIGIT", and "SP" (space).

   The tokens "Local-part", "Domain", and "Mailbox" are defined in
   [RFC5321].

   "dot-atom", "quoted-string", "comment", "CFWS" (comment folded white
   space), "FWS" (folded white space), and "CRLF" (carriage-return/
   line-feed) are defined in [RFC5322].



Kitterman                    Standards Track                    [Page 5]

RFC 7208              Sender Policy Framework (SPF)           April 2014


1.1.3.  MAIL FROM Definition

   This document is concerned with the identity of the sender of a mail
   message, as referred to in [RFC5321]:

      The transaction starts with a MAIL command that gives the sender
      identification.

   Since there are many other names for this identity, it is important
   to choose a name that is:

   1.  commonly used

   2.  well defined

   As such, throughout this document the term "MAIL FROM" will be used,
   which is defined as the RFC5321.MailFrom (reverse-path) identity
   described in [RFC5598].

1.1.4.  HELO Definition

   This document also makes use of the HELO/EHLO identity.  The "HELO"
   identity derives from either the SMTP HELO or EHLO command (see
   [RFC5321]).  Since HELO and EHLO can, in many cases, be used
   interchangeably, they are identified commonly as "HELO" in this
   document.  This means RFC5321.HELO/.EHLO as defined in [RFC5598].
   These commands supply the identity of the SMTP client (sending host)
   for the SMTP session.

1.2.  check_host()

   Section 4 introduces an algorithm to evaluate an SPF policy against
   an arriving email transaction.  In an early implementation, this
   algorithm was encoded in a function called check_host().  That name
   is used in this document as symbolic of the SPF evaluation algorithm,
   but of course implementers are not required to use this name.

2.  Operational Overview

2.1.  Publishing Authorization

   An SPF-compliant domain publishes valid SPF records as described in
   Section 3.  These records authorize the use of the relevant domain
   names in the "HELO" and "MAIL FROM" identities by the MTAs specified
   therein.






Kitterman                    Standards Track                    [Page 6]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   SPF results can be used to make both positive (source is authorized)
   and negative (source is not authorized) determinations.  If ADMDs
   choose to publish SPF records and want to support receivers making
   negative authorization determinations, it is necessary for them to
   publish records that end in "-all", or redirect to other records that
   do; otherwise, no definitive determination of authorization can be
   made.  Potential issues and mitigations associated with negative
   determinations are discussed in Section 10.

   ADMDs that wish to declare that no hosts are authorized to use their
   DNS domain names in the HELO or MAIL FROM commands during SMTP
   sessions can publish SPF records that say so for domain names that
   are neither used in the domain part of email addresses nor expected
   to originate mail.

   When changing SPF records, care has to be taken to ensure that there
   is a transition period so that the old policy remains valid until all
   legitimate email can reasonably expect to have been checked.
   [RFC5321], Section 4.5.4.1 discusses how long a message might be in
   transit.  While offline checks are possible, the closer to the
   original transmission time checks are performed, the more likely they
   are to get an SPF result that matches the sending ADMD intent at the
   time the message was sent.

2.2.  Checking Authorization

   A mail receiver can perform a set of SPF checks for each mail message
   it receives.  An SPF check tests the authorization of a client host
   to emit mail with a given identity.  Typically, such checks are done
   by a receiving MTA, but can be performed elsewhere in the mail
   processing chain so long as the required information is available and
   reliable.  The "MAIL FROM" and "HELO" identities are checked as
   described in Sections 2.4 and 2.3, respectively.

   Without explicit approval of the publishing ADMD, checking other
   identities against SPF version 1 records is NOT RECOMMENDED because
   there are cases that are known to give incorrect results.  For
   example, almost all mailing lists rewrite the "MAIL FROM" identity
   (see Section 10.3), but some do not change any other identities in
   the message.  Documents that define other identities will have to
   define the method for explicit approval.

   It is possible that mail receivers will use the SPF check as part of
   a larger set of tests on incoming mail.  The results of other tests
   might influence whether or not a particular SPF check is performed.
   For example, finding the sending host's IP address on a local
   whitelist might cause all other tests to be skipped and all mail from
   that host to be accepted.



Kitterman                    Standards Track                    [Page 7]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   When a mail receiver decides to perform an SPF check, it has to use a
   correctly implemented check_host() function (Section 4) evaluated
   with the correct parameters.  Although the test as a whole is
   optional, once it has been decided to perform a test it has to be
   performed as specified so that the correct semantics are preserved
   between publisher and receiver.

   To make the test, the mail receiver MUST evaluate the check_host()
   function with the arguments described in Section 4.1.

   Although invalid, malformed, or non-existent domains cause SPF checks
   to return "none" because no SPF record can be found, it has long been
   the policy of many MTAs to reject email from such domains, especially
   in the case of invalid "MAIL FROM".  Rejecting email will prevent one
   method of circumventing of SPF records.

   Implementations have to take care to correctly extract the <domain>
   from the data given with the SMTP MAIL FROM command as many MTAs will
   still accept such things as source routes (see Appendix C of
   [RFC5321]), the %-hack (see [RFC1123]), and bang paths (see
   [RFC1983]).  These archaic features have been maliciously used to
   bypass security systems.

2.3.  The "HELO" Identity

   It is RECOMMENDED that SPF verifiers not only check the "MAIL FROM"
   identity but also separately check the "HELO" identity by applying
   the check_host() function (Section 4) to the "HELO" identity as the
   <sender>.  Checking "HELO" promotes consistency of results and can
   reduce DNS resource usage.  If a conclusive determination about the
   message can be made based on a check of "HELO", then the use of DNS
   resources to process the typically more complex "MAIL FROM" can be
   avoided.  Additionally, since SPF records published for "HELO"
   identities refer to a single host, when available, they are a very
   reliable source of host authorization status.  Checking "HELO" before
   "MAIL FROM" is the RECOMMENDED sequence if both are checked.

   Note that requirements for the domain presented in the EHLO or HELO
   command are not always clear to the sending party, and SPF verifiers
   have to be prepared for the identity to be an IP address literal (see
   [RFC5321], Section 4.1.3) or simply be malformed.  This SPF check can
   only be performed when the "HELO" string is a valid, multi-label
   domain name.








Kitterman                    Standards Track                    [Page 8]

RFC 7208              Sender Policy Framework (SPF)           April 2014


2.4.  The "MAIL FROM" Identity

   SPF verifiers MUST check the "MAIL FROM" identity if a "HELO" check
   either has not been performed or has not reached a definitive policy
   result by applying the check_host() function to the "MAIL FROM"
   identity as the <sender>.

   [RFC5321] allows the reverse-path to be null (see Section 4.5.5 in
   [RFC5321]).  In this case, there is no explicit sender mailbox, and
   such a message can be assumed to be a notification message from the
   mail system itself.  When the reverse-path is null, this document
   defines the "MAIL FROM" identity to be the mailbox composed of the
   local-part "postmaster" and the "HELO" identity (which might or might
   not have been checked separately before).

2.5.  Location of Checks

   The authorization check SHOULD be performed during the processing of
   the SMTP transaction that receives the mail.  This reduces the
   complexity of determining the correct IP address to use as an input
   to check_host() and allows errors to be returned directly to the
   sending MTA by way of SMTP replies.  Appendix D of [RFC7001] provides
   a more thorough discussion of this topic.

   The authorization check is performed during the SMTP transaction at
   the time of the MAIL command, and uses the MAIL FROM value and the
   client IP address.  Performing the check at later times or with other
   input can cause problems such as the following:

   o  It might be difficult to accurately extract the required
      information from potentially deceptive headers.

   o  Legitimate email might fail the authorization check because the
      sender's policy has since changed.

   Generating non-delivery notifications to forged identities that have
   failed the authorization check often constitutes backscatter, i.e.,
   nuisance rejection notices that are not actionable.  Operators are
   strongly advised to avoid such practices.  Section 2 of [RFC3834]
   describes backscatter and the problems it causes.

2.6.  Results of Evaluation

   Section 4 defines check_host(), a model function definition that uses
   the inputs defined above and the sender's policy published in the DNS
   to reach a conclusion about client authorization.  An SPF verifier
   implements something semantically equivalent to the function defined
   there.



Kitterman                    Standards Track                    [Page 9]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   This section enumerates and briefly defines the possible outputs of
   that function.  Note, however, that the protocol establishes no
   normative requirements for handling any particular result.
   Discussion of handling options for each result can be found in
   Section 8.

2.6.1.  None

   A result of "none" means either (a) no syntactically valid DNS domain
   name was extracted from the SMTP session that could be used as the
   one to be authorized, or (b) no SPF records were retrieved from
   the DNS.

2.6.2.  Neutral

   A "neutral" result means the ADMD has explicitly stated that it is
   not asserting whether the IP address is authorized.

2.6.3.  Pass

   A "pass" result is an explicit statement that the client is
   authorized to inject mail with the given identity.

2.6.4.  Fail

   A "fail" result is an explicit statement that the client is not
   authorized to use the domain in the given identity.

2.6.5.  Softfail

   A "softfail" result is a weak statement by the publishing ADMD that
   the host is probably not authorized.  It has not published a
   stronger, more definitive policy that results in a "fail".

2.6.6.  Temperror

   A "temperror" result means the SPF verifier encountered a transient
   (generally DNS) error while performing the check.  A later retry may
   succeed without further DNS operator action.

2.6.7.  Permerror

   A "permerror" result means the domain's published records could not
   be correctly interpreted.  This signals an error condition that
   definitely requires DNS operator intervention to be resolved.






Kitterman                    Standards Track                   [Page 10]

RFC 7208              Sender Policy Framework (SPF)           April 2014


3.  SPF Records

   An SPF record is a DNS record that declares which hosts are, and are
   not, authorized to use a domain name for the "HELO" and "MAIL FROM"
   identities.  Loosely, the record partitions hosts into permitted and
   not-permitted sets (though some hosts might fall into neither
   category).

   The SPF record is expressed as a single string of text found in the
   RDATA of a single DNS TXT resource record; multiple SPF records are
   not permitted for the same owner name.  The record format and the
   process for selecting records are described below in Section 4.  An
   example record is the following:

      v=spf1 +mx a:colo.example.com/28 -all

   This record has a version of "spf1" and three directives: "+mx",
   "a:colo.example.com/28" (the "+" is implied), and "-all".

   Each SPF record is placed in the DNS tree at the owner name it
   pertains to, not in a subdomain under the owner name.  This is
   similar to how SRV records [RFC2782] are done.

   The example in this section might be published via these lines in a
   domain zone file:

      example.com.          TXT "v=spf1 +mx a:colo.example.com/28 -all"

   Since TXT records have multiple uses, beware of other TXT records
   published there for other purposes.  They might cause problems with
   size limits (see Section 3.4), and care has to be taken to ensure
   that only SPF records are used for SPF processing.

   ADMDs publishing SPF records ought to keep the amount of DNS
   information needed to evaluate a record to a minimum.  Sections 4.6.4
   and 10.1.1 provide some suggestions about "include" mechanisms and
   chained "redirect" modifiers.

3.1.  DNS Resource Records

   SPF records MUST be published as a DNS TXT (type 16) Resource Record
   (RR) [RFC1035] only.  The character content of the record is encoded
   as [US-ASCII].  Use of alternative DNS RR types was supported in
   SPF's experimental phase but has been discontinued.

   In 2003, when SPF was first being developed, the requirements for
   assignment of a new DNS RR type were considerably more stringent than
   they are now.  Additionally, support for easy deployment of new DNS



Kitterman                    Standards Track                   [Page 11]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   RR types was not widely deployed in DNS servers and provisioning
   systems.  As a result, developers of SPF found it easier and more
   practical to use the TXT RR type for SPF records.

   In its review of [RFC4408], the SPFbis working group concluded that
   its dual RR type transition model was fundamentally flawed since it
   contained no common RR type that implementers were required to serve
   and required to check.  Many alternatives were considered to resolve
   this issue, but ultimately the working group concluded that
   significant migration to the SPF RR type in the foreseeable future
   was very unlikely and that the best solution for resolving this
   interoperability issue was to drop support for the SPF RR type from
   SPF version 1.  See Appendix A of [RFC6686] for further information.

   The circumstances surrounding SPF's initial deployment a decade ago
   are unique.  If a future update to SPF were developed that did not
   reuse existing SPF records, it could use the SPF RR type.  SPF's use
   of the TXT RR type for structured data should in no way be taken as
   precedent for future protocol designers.  Further discussion of
   design considerations when using new DNS RR types can be found in
   [RFC5507].

3.2.  Multiple DNS Records

   A domain name MUST NOT have multiple records that would cause an
   authorization check to select more than one record.  See Section 4.5
   for the selection rules.

3.3.  Multiple Strings in a Single DNS Record

   As defined in [RFC1035], Sections 3.3 and 3.3.14, a single text DNS
   record can be composed of more than one string.  If a published
   record contains multiple character-strings, then the record MUST be
   treated as if those strings are concatenated together without adding
   spaces.  For example:

      IN TXT "v=spf1 .... first" "second string..."

   is equivalent to:

      IN TXT "v=spf1 .... firstsecond string..."

   TXT records containing multiple strings are useful in constructing
   records that would exceed the 255-octet maximum length of a
   character-string within a single TXT record.






Kitterman                    Standards Track                   [Page 12]

RFC 7208              Sender Policy Framework (SPF)           April 2014


3.4.  Record Size

   The published SPF record for a given domain name SHOULD remain small
   enough that the results of a query for it will fit within 512 octets.
   Otherwise, there is a possibility of exceeding a DNS protocol limit.
   This UDP limit is defined in [RFC1035], Section 2.3.4, although it
   was raised by [RFC2671].  Staying below 512 octets ought to prevent
   older DNS implementations from failing over to TCP and will work with
   UDP in the absence of EDNS0 [RFC6891] support.  Since the answer size
   is dependent on many things outside the scope of this document, it is
   only possible to give this guideline: If the size of the DNS message,
   the combined length of the DNS name and the text of all the records
   of a given type is under 450 octets, then DNS answers ought to fit in
   UDP packets.  Records that are too long to fit in a single UDP packet
   could be silently ignored by SPF verifiers due to firewall and other
   issues that interfere with the operation of DNS over TCP or using
   ENDS0.

   Note that when computing the sizes for replies to queries of the TXT
   format, one has to take into account any other TXT records published
   at the domain name.  Similarly, the sizes for replies to all queries
   related to SPF have to be evaluated to fit in a single 512-octet UDP
   packet (i.e., DNS message size limited to 450 octets).

3.5.  Wildcard Records

   Use of wildcard records for publishing is discouraged, and care has
   to be taken if they are used.  If a zone includes wildcard MX
   records, it might want to publish wildcard declarations, subject to
   the same requirements and problems.  In particular, the declaration
   MUST be repeated for any host that has any RR records at all, and for
   subdomains thereof.  Consider the example in [RFC1034],
   Section 4.3.3.  Based on that, we can do the following:

      EXAMPLE.COM.          MX      10      A.EXAMPLE.COM
      EXAMPLE.COM.          TXT     "v=spf1 a:A.EXAMPLE.COM -all"

      *.EXAMPLE.COM.        MX      10      A.EXAMPLE.COM
      *.EXAMPLE.COM.        TXT     "v=spf1 a:A.EXAMPLE.COM -all"

      A.EXAMPLE.COM.        A       203.0.113.1
      A.EXAMPLE.COM.        MX      10      A.EXAMPLE.COM
      A.EXAMPLE.COM.        TXT     "v=spf1 a:A.EXAMPLE.COM -all"

      *.A.EXAMPLE.COM.      MX      10      A.EXAMPLE.COM
      *.A.EXAMPLE.COM.      TXT     "v=spf1 a:A.EXAMPLE.COM -all"





Kitterman                    Standards Track                   [Page 13]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   SPF records have to be listed twice for every name within the zone:
   once for the name, and once with a wildcard to cover the tree under
   the name, in order to cover all domains in use in outgoing mail.

4.  The check_host() Function

   This description is not an application programming interface
   definition, but rather a function description used to illustrate the
   algorithm.  A compliant SPF implementation MUST produce results
   semantically equivalent to this description.

   The check_host() function fetches SPF records, parses them, and
   evaluates them to determine whether a particular host is or is not
   permitted to send mail with a given identity.  Receiving ADMDs that
   perform this check MUST correctly evaluate the check_host() function
   as described here.

   Implementations MAY use a different algorithm than the canonical
   algorithm defined here, so long as the results are the same in all
   cases.

4.1.  Arguments

   The check_host() function takes these arguments:

   <ip>     - the IP address of the SMTP client that is emitting
              the mail, either IPv4 or IPv6.

   <domain> - the domain that provides the sought-after authorization
              information; initially, the domain portion of the
              "MAIL FROM" or "HELO" identity.

   <sender> - the "MAIL FROM" or "HELO" identity.

   For recursive evaluations, the domain portion of <sender> might not
   be the same as the <domain> argument when check_host() is initially
   evaluated.  In most other cases it will be the same (see Section 5.2
   below).  The overall DNS lookup limit for SPF terms described below
   in Section 4.6.4 must be tracked as a single global limit for all
   evaluations, not just for a single instance of a recursive
   evaluation.

   Note that the <domain> argument might not be a well-formed domain
   name.  For example, if the reverse-path was null, then the EHLO/HELO
   domain is used, with its associated problems (see Section 2.3).  In
   these cases, check_host() is defined in Section 4.3 to return a
   "none" result.




Kitterman                    Standards Track                   [Page 14]

RFC 7208              Sender Policy Framework (SPF)           April 2014


4.2.  Results

   The check_host() function can return one of several results described
   in Section 2.6.  Based on the result, the action to be taken is
   determined by the local policies of the receiver.  This is discussed
   in Section 8.

4.3.  Initial Processing

   If the <domain> is malformed (e.g., label longer than 63 characters,
   zero-length label not at the end, etc.) or is not a multi-label
   domain name, or if the DNS lookup returns "Name Error" (RCODE 3, also
   known as "NXDOMAIN" [RFC2308]), check_host() immediately returns the
   result "none".  DNS RCODEs are defined in [RFC1035].  Properly formed
   domains are fully qualified domains as defined in [RFC1983].  That
   is, in the DNS they are implicitly qualified relative to the root
   (see Section 3.1 of [RFC1034]).  Internationalized domain names MUST
   be encoded as A-labels, as described in Section 2.3 of [RFC5890].

   If the <sender> has no local-part, substitute the string "postmaster"
   for the local-part.

4.4.  Record Lookup

   In accordance with how the records are published (see Section 3
   above), a DNS query needs to be made for the <domain> name, querying
   for type TXT only.

   If the DNS lookup returns a server failure (RCODE 2) or some other
   error (RCODE other than 0 or 3), or if the lookup times out, then
   check_host() terminates immediately with the result "temperror".

4.5.  Selecting Records

   Records begin with a version section:

   record           = version terms *SP
   version          = "v=spf1"

   Starting with the set of records that were returned by the lookup,
   discard records that do not begin with a version section of exactly
   "v=spf1".  Note that the version section is terminated by either an
   SP character or the end of the record.  As an example, a record with
   a version section of "v=spf10" does not match and is discarded.

   If the resultant record set includes no records, check_host()
   produces the "none" result.  If the resultant record set includes
   more than one record, check_host() produces the "permerror" result.



Kitterman                    Standards Track                   [Page 15]

RFC 7208              Sender Policy Framework (SPF)           April 2014


4.6.  Record Evaluation

   The check_host() function parses and interprets the SPF record to
   find a result for the current test.  The syntax of the record is
   validated first, and if there are any syntax errors anywhere in the
   record, check_host() returns immediately with the result "permerror",
   without further interpretation or evaluation.

4.6.1.  Term Evaluation

   There are two types of terms: mechanisms (defined in Section 5) and
   modifiers (defined in Section 6).  A record contains an ordered list
   of these as specified in the following Augmented Backus-Naur Form
   (ABNF).

   terms            = *( 1*SP ( directive / modifier ) )

   directive        = [ qualifier ] mechanism
   qualifier        = "+" / "-" / "?" / "~"
   mechanism        = ( all / include
                      / a / mx / ptr / ip4 / ip6 / exists )
   modifier         = redirect / explanation / unknown-modifier
   unknown-modifier = name "=" macro-string
                      ; where name is not any known modifier

   name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )

   Most mechanisms allow a ":" or "/" character after the name.

   Modifiers always contain an equals ('=') character immediately after
   the name, and before any ":" or "/" characters that might be part of
   the macro-string.

   Terms that do not contain any of "=", ":", or "/" are mechanisms, as
   defined in Section 5.

   As per the definition of the ABNF notation in [RFC5234], mechanism
   and modifier names are case-insensitive.

4.6.2.  Mechanisms

   Each mechanism is considered in turn from left to right.  If there
   are no more mechanisms, the result is the default result as described
   in Section 4.7.

   When a mechanism is evaluated, one of three things can happen: it can
   match, not match, or return an exception.




Kitterman                    Standards Track                   [Page 16]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   If it matches, processing ends and the qualifier value is returned as
   the result of that record.  If it does not match, processing
   continues with the next mechanism.  If it returns an exception,
   mechanism processing ends and the exception value is returned.

   The possible qualifiers, and the results they cause check_host() to
   return, are as follows:

      "+" pass
      "-" fail
      "~" softfail
      "?" neutral

   The qualifier is optional and defaults to "+".

   When a mechanism matches and the qualifier is "-", then a "fail"
   result is returned and the explanation string is computed as
   described in Section 6.2.

   The specific mechanisms are described in Section 5.

4.6.3.  Modifiers

   Modifiers are not mechanisms.  They do not return match or not-match.
   Instead, they provide additional information.  Although modifiers do
   not directly affect the evaluation of the record, the "redirect"
   modifier has an effect after all the mechanisms have been evaluated.

4.6.4.  DNS Lookup Limits

   Some mechanisms and modifiers (collectively, "terms") cause DNS
   queries at the time of evaluation, and some do not.  The following
   terms cause DNS queries: the "include", "a", "mx", "ptr", and
   "exists" mechanisms, and the "redirect" modifier.  SPF
   implementations MUST limit the total number of those terms to 10
   during SPF evaluation, to avoid unreasonable load on the DNS.  If
   this limit is exceeded, the implementation MUST return "permerror".
   The other terms -- the "all", "ip4", and "ip6" mechanisms, and the
   "exp" modifier -- do not cause DNS queries at the time of SPF
   evaluation (the "exp" modifier only causes a lookup at a later time),
   and their use is not subject to this limit.

   When evaluating the "mx" mechanism, the number of "MX" resource
   records queried is included in the overall limit of 10 mechanisms/
   modifiers that cause DNS lookups as described above.  In addition to
   that limit, the evaluation of each "MX" record MUST NOT result in





Kitterman                    Standards Track                   [Page 17]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   querying more than 10 address records -- either "A" or "AAAA"
   resource records.  If this limit is exceeded, the "mx" mechanism MUST
   produce a "permerror" result.

   When evaluating the "ptr" mechanism or the %{p} macro, the number of
   "PTR" resource records queried is included in the overall limit of 10
   mechanisms/modifiers that cause DNS lookups as described above.  In
   addition to that limit, the evaluation of each "PTR" record MUST NOT
   result in querying more than 10 address records -- either "A" or
   "AAAA" resource records.  If this limit is exceeded, all records
   other than the first 10 MUST be ignored.

   The reason for the disparity is that the set of and contents of the
   MX record are under control of the publishing ADMD, while the set of
   and contents of PTR records are under control of the owner of the IP
   address actually making the connection.

   These limits are per mechanism or macro in the record, and are in
   addition to the lookup limits specified above.

   MTAs or other processors SHOULD impose a limit on the maximum amount
   of elapsed time to evaluate check_host().  Such a limit SHOULD allow
   at least 20 seconds.  If such a limit is exceeded, the result of
   authorization SHOULD be "temperror".

   As described at the end of Section 11.1, there may be cases where it
   is useful to limit the number of "terms" for which DNS queries return
   either a positive answer (RCODE 0) with an answer count of 0, or a
   "Name Error" (RCODE 3) answer.  These are sometimes collectively
   referred to as "void lookups".  SPF implementations SHOULD limit
   "void lookups" to two.  An implementation MAY choose to make such a
   limit configurable.  In this case, a default of two is RECOMMENDED.
   Exceeding the limit produces a "permerror" result.

4.7.  Default Result

   If none of the mechanisms match and there is no "redirect" modifier,
   then the check_host() returns a result of "neutral", just as if
   "?all" were specified as the last directive.  If there is a
   "redirect" modifier, check_host() proceeds as defined in Section 6.1.

   It is better to use either a "redirect" modifier or an "all"
   mechanism to explicitly terminate processing.  Although there is an
   implicit "?all" at the end of every record that is not explicitly
   terminated, it aids debugging efforts when it is explicitly provided.






Kitterman                    Standards Track                   [Page 18]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   For example:

      v=spf1 +mx -all

   or

      v=spf1 +mx redirect=_spf.example.com

4.8.  Domain Specification

   Several of these mechanisms and modifiers have a <domain-spec>
   section.  The <domain-spec> string is subject to macro expansion (see
   Section 7).  The resulting string is the common presentation form of
   a fully qualified DNS name: a series of labels separated by periods.
   This domain is called the <target-name> in the rest of this document.

   Note: The result of the macro expansion is not subject to any further
   escaping.  Hence, this facility cannot produce all characters that
   are legal in a DNS label (e.g., the control characters).  However,
   this facility is powerful enough to express legal host names and
   common utility labels (such as "_spf") that are used in DNS.

   For several mechanisms, the <domain-spec> is optional.  If it is not
   provided, the <domain> from the check_host() arguments (see
   Section 4.1) is used as the <target-name>.  "domain" and
   <domain-spec> are syntactically identical after macro expansion.
   "domain" is an input value for check_host(), while <domain-spec> is
   computed by check_host().

   The result of evaluating check_host() with a syntactically invalid
   domain is undefined.

   Note: This document and its predecessors make no provisions for
   defining correct handling of a syntactically invalid <domain-spec>
   (which might be the result of macro expansion), per [RFC1035].
   Examples include names with empty labels, such as "foo..example.com",
   and labels that are longer than 63 characters.  Some implementations
   choose to treat such errors as not-match and therefore ignore such
   names, while others return a "permerror" exception.












Kitterman                    Standards Track                   [Page 19]

RFC 7208              Sender Policy Framework (SPF)           April 2014


5.  Mechanism Definitions

   This section defines two types of mechanisms: basic language
   framework mechanisms and designated sender mechanisms.

   Basic mechanisms contribute to the language framework.  They do not
   specify a particular type of authorization scheme.  The basic
   mechanisms are as follows:

      all
      include

   Designated sender mechanisms are used to identify a set of <ip>
   addresses as being permitted or not permitted to use the <domain> for
   sending mail.  The designated sender mechanisms are as follows:

      a
      mx
      ptr (do not use)
      ip4
      ip6
      exists

   The following conventions apply to all mechanisms that perform a
   comparison between <ip> and an IP address at any point:

   If no CIDR prefix length is given in the directive, then <ip> and the
   IP address are compared for equality.  (Here, CIDR is Classless
   Inter-Domain Routing, described in [RFC4632].)

   If a CIDR prefix length is specified, then only the specified number
   of high-order bits of <ip> and the IP address are compared for
   equality.

   When any mechanism fetches host addresses to compare with <ip>, when
   <ip> is an IPv4, "A" records are fetched; when <ip> is an IPv6
   address, "AAAA" records are fetched.  SPF implementations on IPv6
   servers need to handle both "AAAA" and "A" records, for clients on
   IPv4-mapped IPv6 addresses [RFC4291].  IPv4 <ip> addresses are only
   listed in an SPF record using the "ip4" mechanism.

   Several mechanisms rely on information fetched from the DNS.  For
   these DNS queries, except where noted, if the DNS server returns an
   error (RCODE other than 0 or 3) or the query times out, the mechanism
   stops and the topmost check_host() returns "temperror".  If the
   server returns "Name Error" (RCODE 3), then evaluation of the
   mechanism continues as if the server returned no error (RCODE 0) and
   zero answer records.



Kitterman                    Standards Track                   [Page 20]

RFC 7208              Sender Policy Framework (SPF)           April 2014


5.1.  "all"

   all              = "all"

   The "all" mechanism is a test that always matches.  It is used as the
   rightmost mechanism in a record to provide an explicit default.

   For example:

      v=spf1 a mx -all

   Mechanisms after "all" will never be tested.  Mechanisms listed after
   "all" MUST be ignored.  Any "redirect" modifier (Section 6.1) MUST be
   ignored when there is an "all" mechanism in the record, regardless of
   the relative ordering of the terms.

5.2.  "include"

   include          = "include"  ":" domain-spec

   The "include" mechanism triggers a recursive evaluation of
   check_host().

   1.  The <domain-spec> is expanded as per Section 7.

   2.  check_host() is evaluated with the resulting string as the
       <domain>.  The <ip> and <sender> arguments remain the same as in
       the current evaluation of check_host().

   3.  The recursive evaluation returns match, not-match, or an error.

   4.  If it returns match, then the appropriate result for the
       "include" mechanism is used (e.g., include or +include produces a
       "pass" result and -include produces "fail").

   5.  If it returns not-match or an error, the parent check_host()
       resumes processing as per the table below, with the previous
       value of <domain> restored.

   In hindsight, the name "include" was poorly chosen.  Only the
   evaluated result of the referenced SPF record is used, rather than
   literally including the mechanisms of the referenced record in the
   first.  For example, evaluating a "-all" directive in the referenced
   record does not terminate the overall processing and does not
   necessarily result in an overall "fail".  (Better names for this
   mechanism would have been "if-match", "on-match", etc.)





Kitterman                    Standards Track                   [Page 21]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   The "include" mechanism makes it possible for one domain to designate
   multiple administratively independent domains.  For example, a vanity
   domain "example.net" might send mail using the servers of
   administratively independent domains example.com and example.org.

   Example.net could say

      IN TXT "v=spf1 include:example.com include:example.org -all"

   This would direct check_host() to, in effect, check the records of
   example.com and example.org for a "pass" result.  Only if the host
   were not permitted for either of those domains would the result be
   "fail".

   Whether this mechanism matches, does not match, or returns an
   exception depends on the result of the recursive evaluation of
   check_host():

   +---------------------------------+---------------------------------+
   | A recursive check_host() result | Causes the "include" mechanism  |
   | of:                             | to:                             |
   +---------------------------------+---------------------------------+
   | pass                            | match                           |
   |                                 |                                 |
   | fail                            | not match                       |
   |                                 |                                 |
   | softfail                        | not match                       |
   |                                 |                                 |
   | neutral                         | not match                       |
   |                                 |                                 |
   | temperror                       | return temperror                |
   |                                 |                                 |
   | permerror                       | return permerror                |
   |                                 |                                 |
   | none                            | return permerror                |
   +---------------------------------+---------------------------------+

   The "include" mechanism is intended for crossing administrative
   boundaries.  When remaining within one administrative authority,
   "include" is usually not the best choice.  For example, if
   example.com and example.org were managed by the same entity, and if
   the permitted set of hosts for both domains was "mx:example.com", it
   would be possible for example.org to specify "include:example.com",
   but it would be preferable to specify "redirect=example.com" or even
   "mx:example.com".






Kitterman                    Standards Track                   [Page 22]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   With the "include" mechanism, an administratively external set of
   hosts can be authorized, but determination of sender policy is still
   a function of the original domain's SPF record (as determined by the
   "all" mechanism in that record).  The "redirect" modifier is more
   suitable for consolidating both authorizations and policy into a
   common set to be shared within an ADMD.  Redirect is much more like a
   common code element to be shared among records in a single ADMD.  It
   is possible to control both authorized hosts and policy for an
   arbitrary number of domains from a single record.

5.3.  "a"

   This mechanism matches if <ip> is one of the <target-name>'s IP
   addresses.  For clarity, this means the "a" mechanism also matches
   AAAA records.

   a                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]

   An address lookup is done on the <target-name> using the type of
   lookup (A or AAAA) appropriate for the connection type (IPv4 or
   IPv6).  The <ip> is compared to the returned address(es).  If any
   address matches, the mechanism matches.

5.4.  "mx"

   This mechanism matches if <ip> is one of the MX hosts for a domain
   name.

   mx               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]

   check_host() first performs an MX lookup on the <target-name>.  Then
   it performs an address lookup on each MX name returned.  The <ip> is
   compared to each returned IP address.  To prevent denial-of-service
   (DoS) attacks, the processing limits defined in Section 4.6.4 MUST be
   followed.  If the MX lookup limit is exceeded, then "permerror" is
   returned and the evaluation is terminated.  If any address matches,
   the mechanism matches.

   Note regarding implicit MXes: If the <target-name> has no MX record,
   check_host() MUST NOT apply the implicit MX rules of [RFC5321] by
   querying for an A or AAAA record for the same name.

5.5.  "ptr" (do not use)

   This mechanism tests whether the DNS reverse-mapping for <ip> exists
   and correctly points to a domain name within a particular domain.
   This mechanism SHOULD NOT be published.  See the note at the end of
   this section for more information.



Kitterman                    Standards Track                   [Page 23]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   ptr              = "ptr"    [ ":" domain-spec ]

   The <ip>'s name is looked up using this procedure:

   o  Perform a DNS reverse-mapping for <ip>: Look up the corresponding
      PTR record in "in-addr.arpa." if the address is an IPv4 address
      and in "ip6.arpa." if it is an IPv6 address.

   o  For each record returned, validate the domain name by looking up
      its IP addresses.  To prevent DoS attacks, the PTR processing
      limits defined in Section 4.6.4 MUST be applied.  If they are
      exceeded, processing is terminated and the mechanism does not
      match.

   o  If <ip> is among the returned IP addresses, then that domain name
      is validated.

   Check all validated domain names to see if they either match the
   <target-name> domain or are a subdomain of the <target-name> domain.
   If any do, this mechanism matches.  If no validated domain name can
   be found, or if none of the validated domain names match or are a
   subdomain of the <target-name>, this mechanism fails to match.  If a
   DNS error occurs while doing the PTR RR lookup, then this mechanism
   fails to match.  If a DNS error occurs while doing an A RR lookup,
   then that domain name is skipped and the search continues.

   This mechanism matches if

   o  the <target-name> is a subdomain of a validated domain name, or

   o  the <target-name> and a validated domain name are the same.

   For example, "mail.example.com" is within the domain "example.com",
   but "mail.bad-example.com" is not.

   Note: This mechanism is slow, it is not as reliable as other
   mechanisms in cases of DNS errors, and it places a large burden on
   the .arpa name servers.  If used, proper PTR records have to be in
   place for the domain's hosts and the "ptr" mechanism SHOULD be one of
   the last mechanisms checked.  After many years of SPF deployment
   experience, it has been concluded that it is unnecessary and more
   reliable alternatives should be used instead.  It is, however, still
   in use as part of the SPF protocol, so compliant check_host()
   implementations MUST support it.







Kitterman                    Standards Track                   [Page 24]

RFC 7208              Sender Policy Framework (SPF)           April 2014


5.6.  "ip4" and "ip6"

   These mechanisms test whether <ip> is contained within a given
   IP network.

   ip4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
   ip6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]

   ip4-cidr-length  = "/" ("0" / %x31-39 0*1DIGIT) ; value range 0-32
   ip6-cidr-length  = "/" ("0" / %x31-39 0*2DIGIT) ; value range 0-128
   dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]

   ip4-network      = qnum "." qnum "." qnum "." qnum
   qnum             = DIGIT                 ; 0-9
                      / %x31-39 DIGIT       ; 10-99
                      / "1" 2DIGIT          ; 100-199
                      / "2" %x30-34 DIGIT   ; 200-249
                      / "25" %x30-35        ; 250-255
            ; as per conventional dotted-quad notation, e.g., 192.0.2.0

   ip6-network      = <as per Section 2.2 of [RFC4291]>
            ; e.g., 2001:db8::cd30

   The <ip> is compared to the given network.  If CIDR prefix length
   high-order bits match, the mechanism matches.

   If ip4-cidr-length is omitted, it is taken to be "/32".  If
   ip6-cidr-length is omitted, it is taken to be "/128".  It is not
   permitted to omit parts of the IP address instead of using CIDR
   notations.  That is, use 192.0.2.0/24 instead of 192.0.2.

5.7.  "exists"

   This mechanism is used to construct an arbitrary domain name that is
   used for a DNS A record query.  It allows for complicated schemes
   involving arbitrary parts of the mail envelope to determine what is
   permitted.

   exists           = "exists"   ":" domain-spec

   The <domain-spec> is expanded as per Section 7.  The resulting domain
   name is used for a DNS A RR lookup (even when the connection type is
   IPv6).  If any A record is returned, this mechanism matches.

   Domains can use this mechanism to specify arbitrarily complex
   queries.  For example, suppose example.com publishes the record:

      v=spf1 exists:%{ir}.%{l1r+-}._spf.%{d} -all



Kitterman                    Standards Track                   [Page 25]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   The <target-name> might expand to
   "1.2.0.192.someuser._spf.example.com".  This makes fine-grained
   decisions possible at the level of the user and client IP address.

6.  Modifier Definitions

   Modifiers are name/value pairs that provide additional information.
   Modifiers always have an "=" separating the name and the value.

   The modifiers defined in this document ("redirect" and "exp") SHOULD
   appear at the end of the record, after all mechanisms, though
   syntactically they can appear anywhere in the record.  Ordering of
   these two modifiers does not matter.  These two modifiers MUST NOT
   appear in a record more than once each.  If they do, then
   check_host() exits with a result of "permerror".

   Unrecognized modifiers MUST be ignored no matter where, or how often,
   they appear in a record.  This allows implementations conforming to
   this document to gracefully handle records with modifiers that are
   defined in other specifications.

6.1.  redirect: Redirected Query

   The "redirect" modifier is intended for consolidating both
   authorizations and policy into a common set to be shared within a
   single ADMD.  It is possible to control both authorized hosts and
   policy for an arbitrary number of domains from a single record.

   redirect         = "redirect" "=" domain-spec

   If all mechanisms fail to match, and a "redirect" modifier is
   present, then processing proceeds as follows:

   The <domain-spec> portion of the redirect section is expanded as per
   the macro rules in Section 7.  Then check_host() is evaluated with
   the resulting string as the <domain>.  The <ip> and <sender>
   arguments remain the same as in the current evaluation of
   check_host().

   The result of this new evaluation of check_host() is then considered
   the result of the current evaluation with the exception that if no
   SPF record is found, or if the <target-name> is malformed, the result
   is a "permerror" rather than "none".

   Note that the newly queried domain can itself specify redirect
   processing.





Kitterman                    Standards Track                   [Page 26]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   This facility is intended for use by organizations that wish to apply
   the same record to multiple domains.  For example:

     la.example.com. TXT "v=spf1 redirect=_spf.example.com"
     ny.example.com. TXT "v=spf1 redirect=_spf.example.com"
     sf.example.com. TXT "v=spf1 redirect=_spf.example.com"
   _spf.example.com. TXT "v=spf1 mx:example.com -all"

   In this example, mail from any of the three domains is described by
   the same record.  This can be an administrative advantage.

   Note: In general, the domain "A" cannot reliably use a redirect to
   another domain "B" not under the same administrative control.  Since
   the <sender> stays the same, there is no guarantee that the record at
   domain "B" will correctly work for mailboxes in domain "A",
   especially if domain "B" uses mechanisms involving local-parts.  An
   "include" directive will generally be more appropriate.

   For clarity, any "redirect" modifier SHOULD appear as the very last
   term in a record.  Any "redirect" modifier MUST be ignored if there
   is an "all" mechanism anywhere in the record.

6.2.  exp: Explanation

   explanation      = "exp" "=" domain-spec

   If check_host() results in a "fail" due to a mechanism match (such as
   "-all"), and the "exp" modifier is present, then the explanation
   string returned is computed as described below.  If no "exp" modifier
   is present, then either a default explanation string or an empty
   explanation string MUST be returned to the calling application.

   The <domain-spec> is macro expanded (see Section 7) and becomes the
   <target-name>.  The DNS TXT RRset for the <target-name> is fetched.

   If there are any DNS processing errors (any RCODE other than 0), or
   if no records are returned, or if more than one record is returned,
   or if there are syntax errors in the explanation string, then proceed
   as if no "exp" modifier was given.

   The fetched TXT record's strings are concatenated with no spaces, and
   then treated as an explain-string, which is macro-expanded.  This
   final result is the explanation string.  Implementations MAY limit
   the length of the resulting explanation string to allow for other
   protocol constraints and/or reasonable processing limits.  Since the
   explanation string is intended for an SMTP response and Section 2.4
   of [RFC5321] says that responses are in [US-ASCII], the explanation
   string MUST be limited to [US-ASCII].



Kitterman                    Standards Track                   [Page 27]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   Software evaluating check_host() can use this string to communicate
   information from the publishing domain in the form of a short message
   or URL.  Software SHOULD make it clear that the explanation string
   comes from a third party.  For example, it can prepend the macro
   string "%{o} explains: " to the explanation, as shown in the example
   in Section 8.4.

   Suppose example.com has this record:

      v=spf1 mx -all exp=explain._spf.%{d}

   Here are some examples of possible explanation TXT records at
   explain._spf.example.com:

      "Mail from example.com should only be sent by its own servers."

         -- a simple, constant message

      "%{i} is not one of %{d}'s designated mail servers."

         -- a message with a little more information, including the
            IP address that failed the check

      "See http://%{d}/why.html?s=%{S}&i=%{I}"

         -- a complicated example that constructs a URL with the
            arguments to check_host() so that a web page can be
            generated with detailed, custom instructions

   Note: During recursion into an "include" mechanism, an "exp" modifier
   from the <target-name> MUST NOT be used.  In contrast, when executing
   a "redirect" modifier, an "exp" modifier from the original domain
   MUST NOT be used.  This is because "include" is meant to cross
   administrative boundaries and the explanation provided should be the
   one from the receiving ADMD, while "redirect" is meant to operate as
   a tool to consolidate policy records within an ADMD so the redirected
   explanation is the one that ought to have priority.

7.  Macros

   When evaluating an SPF policy record, certain character sequences are
   intended to be replaced by parameters of the message or of the
   connection.  These character sequences are referred to as "macros".








Kitterman                    Standards Track                   [Page 28]

RFC 7208              Sender Policy Framework (SPF)           April 2014


7.1.  Formal Specification

   The ABNF description for a macro is as follows:

   domain-spec      = macro-string domain-end
   domain-end       = ( "." toplabel [ "." ] ) / macro-expand

   toplabel         = ( *alphanum ALPHA *alphanum ) /
                      ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
   alphanum         = ALPHA / DIGIT

   explain-string   = *( macro-string / SP )

   macro-string     = *( macro-expand / macro-literal )
   macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
                      / "%%" / "%_" / "%-"
   macro-literal    = %x21-24 / %x26-7E
                      ; visible characters except "%"
   macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
                      "c" / "r" / "t" / "v"
   transformers     = *DIGIT [ "r" ]
   delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="

   The "toplabel" construction is subject to the letter-digit-hyphen
   (LDH) rule plus additional top-level domain (TLD) restrictions.  See
   Section 2 of [RFC3696] for background.

   Some special cases:

   o  A literal "%" is expressed by "%%".

   o  "%_" expands to a single " " space.

   o  "%-" expands to a URL-encoded space, viz., "%20".

7.2.  Macro Definitions

   The following macro letters are expanded in term arguments:

      s = <sender>
      l = local-part of <sender>
      o = domain of <sender>
      d = <domain>
      i = <ip>
      p = the validated domain name of <ip> (do not use)
      v = the string "in-addr" if <ip> is ipv4, or "ip6" if <ip> is ipv6
      h = HELO/EHLO domain




Kitterman                    Standards Track                   [Page 29]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   <domain>, <sender>, and <ip> are defined in Section 4.1.

   The following macro letters are allowed only in "exp" text:

      c = SMTP client IP (easily readable format)
      r = domain name of host performing the check
      t = current timestamp

7.3.  Macro Processing Details

   A '%' character not followed by a '{', '%', '-', or '_' character is
   a syntax error.  So:

      -exists:%(ir).sbl.example.org

   is incorrect and will cause check_host() to yield a "permerror".
   Instead, the following is legal:

      -exists:%{ir}.sbl.example.org

   Optional transformers are the following:

      *DIGIT = zero or more digits

      'r'    = reverse value, splitting on dots by default

   If transformers or delimiters are provided, the replacement value for
   a macro letter is split into parts separated by one or more of the
   specified delimiter characters.  After performing any reversal
   operation and/or removal of left-hand parts, the parts are rejoined
   using "." and not the original splitting characters.

   By default, strings are split on "." (dots).  Note that no special
   treatment is given to leading, trailing, or consecutive delimiters in
   input strings, and so the list of parts might contain empty strings.
   Some older implementations of SPF prohibit trailing dots in domain
   names, so trailing dots SHOULD NOT be published, although they MUST
   be accepted by implementations conforming to this document.  Macros
   can specify delimiter characters that are used instead of ".".

   The "r" transformer indicates a reversal operation: if the client IP
   address were 192.0.2.1, the macro %{i} would expand to "192.0.2.1"
   and the macro %{ir} would expand to "1.2.0.192".

   The DIGIT transformer indicates the number of right-hand parts to
   use, after optional reversal.  If a DIGIT is specified, the value
   MUST be nonzero.  If no DIGITs are specified, or if the value
   specifies more parts than are available, all the available parts are



Kitterman                    Standards Track                   [Page 30]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   used.  If the DIGIT was 5, and only 3 parts were available, the macro
   interpreter would pretend the DIGIT was 3.  Implementations MUST
   support at least a value of 127, as that is the maximum number of
   labels in a domain name (less the zero-length label at the end).

   The "s" macro expands to the <sender> argument.  It is an email
   address with a local-part, an "@" character, and a domain.  The "l"
   macro expands to just the local-part.  The "o" macro expands to just
   the domain part.  Note that these values remain the same during
   recursive and chained evaluations due to "include" and/or "redirect".
   Note also that if the original <sender> had no local-part, the
   local-part was set to "postmaster" in initial processing (see
   Section 4.3).

   For IPv4 addresses, both the "i" and "c" macros expand to the
   standard dotted-quad format.

   For IPv6 addresses, the "i" macro expands to a dot-format address; it
   is intended for use in %{ir}.  The "c" macro can expand to any of the
   hexadecimal colon-format addresses specified in Section 2.2 of
   [RFC4291].  It is intended for humans to read.

   The "p" macro expands to the validated domain name of <ip>.  The
   procedure for finding the validated domain name is defined in
   Section 5.5.  If the <domain> is present in the list of validated
   domains, it SHOULD be used.  Otherwise, if a subdomain of the
   <domain> is present, it SHOULD be used.  Otherwise, any name from the
   list can be used.  If there are no validated domain names or if a DNS
   error occurs, the string "unknown" is used.

   This macro SHOULD NOT be published (see Section 5.5 for the
   discussion).

   The "h" macro expands to the parameter that was provided to the SMTP
   server via the HELO or EHLO SMTP verb.  For sessions where that verb
   was provided more than once, the most recent instance is used.

   The "r" macro expands to the name of the receiving MTA.  This SHOULD
   be a fully qualified domain name, but if one does not exist (as when
   the checking is done by a Mail User Agent (MUA)) or if policy
   restrictions dictate otherwise, the word "unknown" SHOULD be
   substituted.  The domain name can be different from the name found in
   the MX record that the client MTA used to locate the receiving MTA.








Kitterman                    Standards Track                   [Page 31]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   The "t" macro expands to the decimal representation of the
   approximate number of seconds since the Epoch (Midnight, January 1,
   1970, UTC) at the time of the evaluation.  This is the same value as
   the value that is returned by the Portable Operating System Interface
   (POSIX) time() function in most standards-compliant libraries.

   When the result of macro expansion is used in a domain name query, if
   the expanded domain name exceeds 253 characters (the maximum length
   of a domain name in this format), the left side is truncated to fit,
   by removing successive domain labels (and their following dots) until
   the total length does not exceed 253 characters.

   Uppercase macros expand exactly as their lowercase equivalents, and
   are then URL escaped.  URL escaping MUST be performed for characters
   not in the "unreserved" set, which is defined in [RFC3986].

   Care has to be taken by the sending ADMD so that macro expansion for
   legitimate email does not exceed the 63-character limit on DNS
   labels.  The local-part of email addresses, in particular, can have
   more than 63 characters between dots.

   To minimize DNS lookup resource requirements, it is better if sending
   ADMDs avoid using the "s", "l", "o", or "h" macros in conjunction
   with any mechanism directive.  Although these macros are powerful and
   allow per-user records to be published, they severely limit the
   ability of implementations to cache results of check_host() and they
   reduce the effectiveness of DNS caches.

   If no directive processed during the evaluation of check_host()
   contains an "s", "l", "o", or "h" macro, then the results of the
   evaluation can be cached on the basis of <domain> and <ip> alone for
   as long as the DNS record involved with the shortest Time to Live
   (TTL) has not expired.

7.4.  Expansion Examples

   The <sender> is strong-bad@email.example.com.  The IPv4 SMTP client
   IP is 192.0.2.3.  The IPv6 SMTP client IP is 2001:db8::cb01.  The PTR
   domain name of the client IP is mx.example.org.












Kitterman                    Standards Track                   [Page 32]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   macro                       expansion
   -------  ----------------------------
   %{s}     strong-bad@email.example.com
   %{o}                email.example.com
   %{d}                email.example.com
   %{d4}               email.example.com
   %{d3}               email.example.com
   %{d2}                     example.com
   %{d1}                             com
   %{dr}               com.example.email
   %{d2r}                  example.email
   %{l}                       strong-bad
   %{l-}                      strong.bad
   %{lr}                      strong-bad
   %{lr-}                     bad.strong
   %{l1r-}                        strong

   macro-string                                               expansion
   --------------------------------------------------------------------
   %{ir}.%{v}._spf.%{d2}             3.2.0.192.in-addr._spf.example.com
   %{lr-}.lp._spf.%{d2}                  bad.strong.lp._spf.example.com

   %{lr-}.lp.%{ir}.%{v}._spf.%{d2}
                       bad.strong.lp.3.2.0.192.in-addr._spf.example.com

   %{ir}.%{v}.%{l1r-}.lp._spf.%{d2}
                           3.2.0.192.in-addr.strong.lp._spf.example.com

   %{d2}.trusted-domains.example.net
                                example.com.trusted-domains.example.net

   IPv6:
   %{ir}.%{v}._spf.%{d2}                               1.0.b.c.0.0.0.0.
   0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com

8.  Result Handling

   This section provides guidance for SPF verifier operators in response
   to the various possible outputs of check_host() on a message.
   Definitions of SPF results are presented in Section 2.6; this section
   provides more detail on each for use in developing local policy for
   message handling.

   Every operating environment is different.  There are some receivers
   for whom strict adherence to SPF is appropriate, and definitive
   treatment of messages that are evaluated to be explicitly
   unauthorized ("fail" and sometimes "softfail") is the norm.  There
   are others for which the "false negative" cases are more of a



Kitterman                    Standards Track                   [Page 33]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   concern.  This concern is typically handled by merely recording the
   result in the header and allowing the message to pass on for
   additional processing.  There are still others where SPF is one of
   several inputs to the message-handling decision.  As such, there is
   no comprehensive normative requirement for message handling in
   response to any particular result.  This section is provided to
   present a complete picture of the likely cause of each result and,
   where available, the experience gained during experimental
   deployment.

   There are essentially two classes of handling choices:

   o  Handling within the SMTP session that attempted to deliver the
      message, such as by returning a permanent SMTP error (rejection)
      or temporary SMTP error ("try again later");

   o  Permitting the message to pass (a successful SMTP reply code) and
      adding an additional header field that indicates the result
      returned by check_host() and other salient details; this is
      discussed in more detail in Section 9.

8.1.  None

   With a "none" result, the SPF verifier has no information at all
   about the authorization or lack thereof of the client to use the
   checked identity or identities.  The check_host() function completed
   without errors but was not able to reach any conclusion.

8.2.  Neutral

   A "neutral" result indicates that although a policy for the identity
   was discovered, there is no definite assertion (positive or negative)
   about the client.

   A "neutral" result MUST be treated exactly like the "none" result;
   the distinction exists only for informational purposes.  Treating
   "neutral" more harshly than "none" would discourage ADMDs from
   testing the use of SPF records (see Section 10.1).

8.3.  Pass

   A "pass" result means the client is authorized to inject mail with
   the given identity.  The domain can now, in the sense of reputation,
   be considered responsible for sending the message.  Further policy
   checks can now proceed with confidence in the legitimate use of the
   identity.  This is further discussed in Appendix G.1.





Kitterman                    Standards Track                   [Page 34]

RFC 7208              Sender Policy Framework (SPF)           April 2014


8.4.  Fail

   A "fail" result is an explicit statement that the client is not
   authorized to use the domain in the given identity.  Disposition of
   SPF fail messages is a matter of local policy.  See Appendix G.2 for
   considerations on developing local policy.

   If the checking software chooses to reject the mail during the SMTP
   transaction, then it SHOULD use an SMTP reply code of 550 (see
   [RFC5321]) and, if supported, the 5.7.1 enhanced status code (see
   [RFC3463], Section 3.8), in addition to an appropriate reply text.
   The check_host() function will return either a default explanation
   string or one from the domain that published the SPF records (see
   Section 6.2).  If the information does not originate with the
   checking software, it is good to make it clear that the text is
   provided by the sender's domain.  For example:

       550 5.7.1 SPF MAIL FROM check failed:
       550 5.7.1 The domain example.com explains:
       550 5.7.1 Please see http://www.example.com/mailpolicy.html

   If the checking software chooses not to reject the mail during the
   SMTP transaction, then it SHOULD add a Received-SPF or
   Authentication-Results header field (see Section 9) to communicate
   this result to downstream message processors.  While this is true for
   all SPF results, it is of particular importance for "fail" results
   since the message is explicitly not authorized by the ADMD.

8.5.  Softfail

   A "softfail" result ought to be treated as somewhere between "fail"
   and "neutral"/"none".  The ADMD believes the host is not authorized
   but is not willing to make a strong policy statement.  Receiving
   software SHOULD NOT reject the message based solely on this result,
   but MAY subject the message to closer scrutiny than normal.

   The ADMD wants to discourage the use of this host and thus desires
   limited feedback when a "softfail" result occurs.  For example, the
   recipient's MUA could highlight the "softfail" status, or the
   receiving MTA could give the sender a message using greylisting
   [RFC6647], with a note the first time the message is received, but
   accept it on a later attempt based on receiver policy.









Kitterman                    Standards Track                   [Page 35]

RFC 7208              Sender Policy Framework (SPF)           April 2014


8.6.  Temperror

   A "temperror" result means the SPF verifier encountered a transient
   (generally DNS) error while performing the check.  Checking software
   can choose to accept or temporarily reject the message.  If the
   message is rejected during the SMTP transaction for this reason, the
   software SHOULD use an SMTP reply code of 451 and, if supported, the
   4.4.3 enhanced status code (see Section 3.5 of [RFC3463]).  These
   errors can be caused by problems in either the sender's or receiver's
   DNS software.  See Appendix G.4 for considerations on developing
   local policy.

8.7.  Permerror

   A "permerror" result means the domain's published records could not
   be correctly interpreted.  This signals an error condition that
   definitely requires DNS operator intervention to be resolved.  If the
   message is rejected during the SMTP transaction for this reason, the
   software SHOULD use an SMTP reply code of 550 and, if supported, the
   5.5.2 enhanced status code (see [RFC3463], Section 3.6).  Be aware
   that if the ADMD uses macros (Section 7), it is possible that this
   result is due to the checked identities having an unexpected format.
   It is also possible that this result is generated by certain SPF
   verifiers due to the input arguments having an unexpected format; see
   Section 4.8.  See Appendix G.3 for considerations on developing local
   policy.

9.  Recording the Result

   To provide downstream agents, such as MUAs, with the information they
   might need in terms of evaluating or representing the apparent safety
   of the message content, it is RECOMMENDED that SMTP receivers record
   the result of SPF processing in the message header.  For SPF verifier
   operators that choose to record SPF results in the header of the
   message for processing by internal filters or MUAs, two methods are
   presented: Section 9.1 defines the Received-SPF field, which is the
   results field originally defined for SPF use.  Section 9.2 discusses
   the Authentication-Results header field [RFC7001], which was
   specified more recently and is designed for use by SPF and other
   authentication methods.

   Both are in common use, and hence both are included here.  However,
   it is important to note that they were designed to serve slightly
   different purposes.  Received-SPF is intended to include enough
   information to enable reconstruction of the SPF evaluation of the
   message, while Authentication-Results is designed only to relay the
   result itself and related output details of likely use to end users
   (e.g., what property of the message was actually authenticated and



Kitterman                    Standards Track                   [Page 36]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   what it contained), leaving reconstructive work to the purview of
   system logs and the Received field contents.  Also, Received-SPF
   relies on compliance of agents within the receiving ADMD to adhere to
   the header field ordering rules of [RFC5321] and [RFC5322], while
   Authentication-Results includes some provisions to protect against
   non-compliant implementations.

   An SPF verifier operator could choose to use both to serve different
   downstream agents.  In such cases, care needs to be taken to ensure
   that both fields are conveying the same details, or unexpected
   results can occur.

9.1.  The Received-SPF Header Field

   The Received-SPF header field is a trace field (see [RFC5322],
   Section 3.6.7) and SHOULD be prepended to the existing header, above
   the Received: field that is generated by the SMTP receiver.  It MUST
   appear above all other Received-SPF fields in the message.  The
   header field has the following format:

   header-field     = "Received-SPF:" [CFWS] result FWS [comment FWS]
                      [ key-value-list ] CRLF

   result           = "pass" / "fail" / "softfail" / "neutral" /
                      "none" / "temperror" / "permerror"

   key-value-list   = key-value-pair *( ";" [CFWS] key-value-pair )
                      [";"]

   key-value-pair   = key [CFWS] "=" ( dot-atom / quoted-string )

   key              = "client-ip" / "envelope-from" / "helo" /
                      "problem" / "receiver" / "identity" /
                       "mechanism" / name

   identity         = "mailfrom"   ; for the "MAIL FROM" identity
                      / "helo"     ; for the "HELO" identity
                      / name       ; other identities

   dot-atom         = <unquoted word as per [RFC5322]>
   quoted-string    = <quoted string as per [RFC5322]>
   comment          = <comment string as per [RFC5322]>
   CFWS             = <comment or folding white space as per [RFC5322]>
   FWS              = <folding white space as per [RFC5322]>
   CRLF             = <standard end-of-line token as per [RFC5322]>






Kitterman                    Standards Track                   [Page 37]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   The header field SHOULD include a "(...)" style comment after the
   result, conveying supporting information for the result, such as
   <ip>, <sender>, and <domain>.

   The following key-value pairs are designed for later machine parsing.
   SPF verifiers SHOULD give enough information so that the SPF results
   can be verified -- that is, at least "client-ip", "helo", and, if the
   "MAIL FROM" identity was checked, "envelope-from".

   client-ip      the IP address of the SMTP client

   envelope-from  the envelope sender mailbox

   helo           the host name given in the HELO or EHLO command

   mechanism      the mechanism that matched (if no mechanisms matched,
                  substitute the word "default")

   problem        if an error was returned, details about the error

   receiver       the host name of the SPF verifier

   identity       the identity that was checked; see the <identity>
                  ABNF rule

   Other keys MAY be defined by SPF verifiers.

   SPF verifiers MUST make sure that the Received-SPF header field does
   not contain invalid characters, is not excessively long (see
   [RFC5322], Section 2.1.1), and does not contain malicious data that
   has been provided by the sender.

   Examples of various header field styles that could be generated are
   the following:

   Received-SPF: pass (mybox.example.org: domain of
    myname@example.com designates 192.0.2.1 as permitted sender)
       receiver=mybox.example.org; client-ip=192.0.2.1;
       envelope-from="myname@example.com"; helo=foo.example.com;

   Received-SPF: fail (mybox.example.org: domain of
                     myname@example.com does not designate
                     192.0.2.1 as permitted sender)
                     identity=mailfrom; client-ip=192.0.2.1;
                     envelope-from="myname@example.com";






Kitterman                    Standards Track                   [Page 38]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   Received-SPF: pass (mybox.example.org: domain of
    myname@example.com designates 192.0.2.1 as permitted sender)
       receiver=mybox.example.org; client-ip=192.0.2.1;
       mechanism=ip4:192.0.2.1; envelope-from="myname@example.com";
       helo=foo.example.com;

9.2.  SPF Results in the Authentication-Results Header Field

   As mentioned in Section 9, the Authentication-Results header field is
   designed to communicate lists of tests a border MTA did and their
   results.  The specified elements of the field provide less
   information than the Received-SPF field:

   Authentication-Results: myhost.example.org; spf=pass
     smtp.mailfrom=example.net

   Received-SPF: pass (myhost.example.org: domain of
    myname@example.com designates 192.0.2.1 as permitted sender)
       receiver=mybox.example.org; client-ip=192.0.2.1;
       envelope-from="myname@example.com"; helo=foo.example.com;

   It is, however, possible to add CFWS in the "reason" part of an
   Authentication-Results header field and provide the equivalent
   information, if desired.

   As an example, an expanded Authentication-Results header field might
   look like (for a "MAIL FROM" check in this example):

   Authentication-Results: myhost.example.org; spf=pass
     reason="client-ip=192.0.2.1; smtp.helo=foo.example.com"
     smtp.mailfrom=user@example.net

10.  Effects on Infrastructure

   This section outlines the major implications that adoption of this
   protocol will have on various entities involved in Internet email.
   It is intended to make clear to the reader where this protocol
   knowingly affects the operation of such entities.  This section is
   not a "how-to" manual, or a "best practices" document, and it is not
   a comprehensive list of what such entities ought to do in light of
   this specification.

   This section provides operational advice and instruction only.  It is
   non-normative.

   [RFC5598] describes the Internet email architecture.  This section is
   organized based on the different segments of the architecture.




Kitterman                    Standards Track                   [Page 39]

RFC 7208              Sender Policy Framework (SPF)           April 2014


10.1.  Sending Domains

   Originating ADMDs (ADministrative Management Domains --
   Sections 2.2.1 and 2.3 of [RFC5598]) that wish to be compliant with
   this specification will need to determine the list of relays
   ([RFC5598], Section 2.2.2) that they allow to use their domain name
   in the "HELO" and "MAIL FROM" identities when relaying to other
   ADMDs.  It is recognized that forming such a list is not just a
   simple technical exercise, but involves policy decisions with both
   technical and administrative considerations.

10.1.1.  DNS Resource Considerations

   Minimizing the DNS resources needed for SPF lookups can be done by
   choosing directives that require less DNS information and by placing
   lower-cost mechanisms earlier in the SPF record.

   Section 4.6.4 specifies the limits receivers have to use.  It is
   essential to publish records that do not exceed these requirements.
   It is also required to carefully weigh the cost and the
   maintainability of licit solutions.

   For example, consider a domain set up as follows:

      example.com.     IN MX   10 mx.example.com.
                       IN MX   20 mx2.example.com.
      mx.example.com.  IN A    192.0.2.1
      mx2.example.com. IN A    192.0.2.129

   Assume the administrative point is to authorize (pass) mx and mx2
   while failing every other host.  Compare the following solutions:

   Best record:
      example.com.   IN TXT  "v=spf1 ip4:192.0.2.1 ip4:192.0.2.129 -all"

   Good record:
      $ORIGIN example.com.
      @              IN TXT  "v=spf1 a:authorized-spf.example.com -all"
      authorized-spf IN A    192.0.2.1
                     IN A    192.0.2.129

   Expensive record:
      example.com.   IN TXT  "v=spf1 mx:example.com -all"

   Wasteful, bad record:
      example.com.   IN TXT  "v=spf1 ip4:192.0.2.0/24 mx -all"





Kitterman                    Standards Track                   [Page 40]

RFC 7208              Sender Policy Framework (SPF)           April 2014


10.1.2.  Administrator's Considerations

   There might be administrative considerations: using "a" over "ip4" or
   "ip6" allows hosts to be renumbered easily at the cost of a DNS query
   per receiver.  Using "mx" over "a" allows the set of mail hosts to be
   changed easily.  Unless such changes are common, it is better to use
   the less resource-intensive mechanisms like "ip4" and "ip6" over "a"
   or "a" over "mx".

   In some specific cases, standard advice on record content is
   appropriate.  Publishing SPF records for domains that send no mail is
   a well-established best practice.  The record for a domain that sends
   no mail is:

      www.example.com.   IN TXT  "v=spf1 -all"

   Publishing SPF records for individual hosts is also best practice.
   The host name is generally the identity used in the 5321.HELO/.EHLO
   command.  In the case of messages with a null 5321.MailFrom, this is
   used as the domain for 5321.MailFrom SPF checks, in addition to being
   used in 5321.HELO/.EHLO-based SPF checks.  The standard SPF record
   for an individual host that is involved in mail processing is:

      relay.example.com.   IN TXT  "v=spf1 a -all"

   Validating correct deployment is difficult.  [RFC6652] describes one
   mechanism for soliciting feedback on SPF failures.  Another
   suggestion can be found in Appendix C.

   Regardless of the method used, understanding the ADMD's outbound mail
   architecture is essential to effective deployment.

10.1.3.  Bounces

   As explained in Section 2.4, [RFC5321] allows the MAIL FROM to be
   null, which is typical of some Delivery Status Notifications
   [RFC3464], commonly called email bounces.  In this case, the only
   entity available for performing an SPF check is the "HELO" identity
   defined in Section 1.1.4.  SPF functionality is enhanced by
   administrators ensuring this identity is set correctly and has an
   appropriate SPF record.  It is normal to have the "HELO" identity set
   to the host name instead of the domain.  Zone file generation for
   significant numbers of hosts can be consolidated using the "redirect"
   modifier and scripted for initial deployment.  Specific deployment
   advice is given above in Section 10.1.2.






Kitterman                    Standards Track                   [Page 41]

RFC 7208              Sender Policy Framework (SPF)           April 2014


10.2.  Receivers

   SPF results can be used in combination with other methods to
   determine the final local disposition (either positive or negative)
   of a message.  It can also be considered dispositive on its own.

   An attempt to have one organization (sender) direct the email-
   handling policies of another (receiver) is inherently challenging and
   often controversial.  As stated elsewhere in this document, there is
   no comprehensive normative requirement for specific handling of a
   message based on SPF results.  The information presented in Section 8
   and in Appendix G is offered for receiver consideration when forming
   local handling policies.

   The primary considerations are that SPF might return "pass" for mail
   that is ultimately harmful (e.g., spammers that arrange for SPF to
   pass using disposable domain names, or virus or spam outbreaks from
   within trusted sources), and might also return "fail" for mail that
   is ultimately legitimate (e.g., legitimate mail that has traversed a
   mail alias).  It is important to take both of these cases under
   consideration when establishing local handling policy.

10.3.  Mediators

   Mediators are a type of User Actor [RFC5598].  That is, a mediator
   takes 'delivery' of a message and posts a 'submission' of a new
   message.  The mediator can make the newly posted message be as
   similar to or as different from the original message as they wish.
   Examples include mailing lists (see Section 5.3 of [RFC5598]) and
   ReSenders (Section 5.2 of [RFC5598]).  This is discussed in
   [RFC5321], Section 3.9.  For the operation of SPF, the essential
   concern is the email address in the 5321.MailFrom command for the new
   message.

   Because SPF evaluation is based on the IP address of the "last"
   sending SMTP server, the address of the mediator will be used, rather
   than the address of the SMTP server that sent the message to the
   mediator.  Some mediators retain the email address from the original
   message, while some use a new address.

   If the address is the same as for the original message, and the
   original message had an associated SPF record, then the SPF
   evaluation will fail unless mitigations such as those described in
   Appendix D are used.







Kitterman                    Standards Track                   [Page 42]

RFC 7208              Sender Policy Framework (SPF)           April 2014


11.  Security Considerations

11.1.  Processing Limits

   As with most aspects of email, there are a number of ways that
   malicious parties could use the protocol as an avenue for a DoS
   attack.  The processing limits outlined in Section 4.6.4 are designed
   to prevent attacks such as the following:

   o  A malicious party could create an SPF record with many references
      to a victim's domain and send many emails to different SPF
      verifiers; those SPF verifiers would then create a DoS attack.  In
      effect, the SPF verifiers are being used to amplify the attacker's
      bandwidth by using fewer octets in the SMTP session than are used
      by the DNS queries.  Using SPF verifiers also allows the attacker
      to hide the true source of the attack.  This potential attack is
      based on large volumes of mail being transmitted.

   o  Whereas implementations of check_host() are supposed to limit the
      number of DNS lookups, malicious domains could publish records
      that exceed these limits in an attempt to waste computation effort
      at their targets when they send them mail.  Malicious domains
      could also design SPF records that cause particular
      implementations to use excessive memory or CPU or to trigger bugs.
      If a receiver is configured to accept mail with an SPF result of
      "temperror", such an attack might result in mail that would
      otherwise have been rejected due to an SPF "fail" result being
      accepted.  This potential attack is based on specially crafted SPF
      records being used to exhaust DNS resources of the victim.

   o  Malicious parties could send a large volume of mail purporting to
      come from the intended target to a wide variety of legitimate mail
      hosts.  These legitimate machines would then present a DNS load on
      the target as they fetched the relevant records.

   o  Malicious parties could, in theory, use SPF records as a vehicle
      for DNS lookup amplification for a DoS attack.  In this scenario,
      the attacker publishes an SPF record in its own DNS that uses "a"
      and "mx" mechanisms directed toward the intended victim, e.g.,
      "a:example.com a:foo.example.com a:bar.example.com ..." and then
      distributes mail with a MAIL FROM value including its own domain
      in large volume to a wide variety of destinations.  Any such
      destination operating an SPF verifier will begin querying all of
      the names associated with the "a" mechanisms in that record.  The
      names used in the record needn't exist for the attack to be
      effective.  Operational experience since the publication of
      [RFC4408] suggests that mitigation of this class of attack can be
      accomplished with minimal impact on the deployed base by having



Kitterman                    Standards Track                   [Page 43]

RFC 7208              Sender Policy Framework (SPF)           April 2014


      the verifier abort processing and return "permerror"
      (Section 2.6.7) as soon as more than two "void lookups" have been
      encountered (defined in Section 4.6.4).

   Of these, the case of a third party referenced in the SPF record is
   the easiest for a DoS attack to effectively exploit.  As a result,
   limits that might seem reasonable for an individual mail server can
   still allow an unreasonable amount of bandwidth amplification.
   Therefore, the processing limits need to be quite low.

11.2.  SPF-Authorized Email May Contain Other False Identities

   The "MAIL FROM" and "HELO" identity authorizations do not provide
   assurance about the authorization/authenticity of other identities
   used in the message.  It is entirely possible for a malicious sender
   to inject a message using his own domain in the identities used by
   SPF and have that domain's SPF record authorize the sending host, and
   yet the message can easily list other identities in its header.
   Unless the user or the MUA takes care to note that the authorized
   identity does not match the other more commonly presented identities
   (such as the From: header field), the user might be lulled into a
   false sense of security.

11.3.  Spoofed DNS and IP Data

   There are two aspects of this protocol that malicious parties could
   exploit to undermine the validity of the check_host() function:

   o  The evaluation of check_host() relies heavily on DNS.  A malicious
      attacker could attack the DNS infrastructure and cause
      check_host() to see spoofed DNS data, and then return incorrect
      results.  This could include returning "pass" for an <ip> value
      where the actual domain's record would evaluate to "fail".  See
      [RFC3833] for a description of DNS weaknesses, and see [RFC4033]
      for a countermeasure.

   o  The client IP address, <ip>, is assumed to be correct.  In a
      modern, correctly configured system, the risk of this not being
      true is nil.

11.4.  Cross-User Forgery

   By definition, SPF policies just map domain names to sets of
   authorized MTAs, not whole email addresses to sets of authorized
   users.  Although the "l" macro (Section 7) provides a limited way to
   define individual sets of authorized MTAs for specific email
   addresses, it is generally impossible to verify, through SPF, the use
   of specific email addresses by individual users of the same MTA.



Kitterman                    Standards Track                   [Page 44]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   It is up to mail services and their MTAs to directly prevent
   cross-user forgery: based on SMTP AUTH ([RFC4954]), users have to be
   restricted to using only those email addresses that are actually
   under their control (see Section 6.1 of [RFC6409]).  Another means to
   verify the identity of individual users is message cryptography, such
   as Pretty Good Privacy (PGP) ([RFC4880]) or S/MIME ([RFC5751]).

11.5.  Untrusted Information Sources

   An SPF-compliant receiver gathers information from the SMTP commands
   it receives and from the published DNS records of the sending domain
   holder (e.g., "HELO" domain name, the "MAIL FROM" address from the
   envelope, and SPF DNS records published by the domain holder).  These
   parameters are not validated in the SMTP process.

   All of these pieces of information are generated by actors outside of
   the authority of the receiver, and thus are not guaranteed to be
   accurate or legitimate.

11.5.1.  Recorded Results

   This information, passed to the receiver in the Received-SPF: or
   Authentication-Results: trace fields, can be returned to the client
   MTA as an SMTP rejection message.  If such an SMTP rejection message
   is generated, the information from the trace fields has to be checked
   for such problems as invalid characters and excessively long lines.

11.5.2.  External Explanations

   When the authorization check fails, an explanation string could be
   included in the reject response.  Both the sender and the rejecting
   receiver need to be aware that the explanation was determined by the
   publisher of the SPF record checked and, in general, not the
   receiver.  The explanation can contain malicious URLs, or it might be
   offensive or misleading.

   Explanations returned to sender domains due to "exp" modifiers
   (Section 6.2) were generated by the sender policy published by the
   domain holders themselves.  As long as messages are only returned
   with non-delivery notifications ([RFC3464]) to domains publishing the
   explanation strings from their own DNS SPF records, the only affected
   parties are the original publishers of the domain's SPF records.

   In practice, such non-delivery notifications can be misdirected, such
   as when an MTA accepts an email and only later generates the
   notification to a forged address, or when an email forwarder does not
   direct the bounce back to the original sender.




Kitterman                    Standards Track                   [Page 45]

RFC 7208              Sender Policy Framework (SPF)           April 2014


11.5.3.  Macro Expansion

   Macros (Section 7) allow senders to inject arbitrary text (any
   non-null [US-ASCII] character) into receiver DNS queries.  It is
   necessary to be prepared for hostile or unexpected content.

11.6.  Privacy Exposure

   Checking SPF records causes DNS queries to be sent to the domain
   owner.  These DNS queries, especially if they are caused by the
   "exists" mechanism, can contain information about who is sending
   email and likely to which MTA the email is being sent.  This can
   introduce some privacy concerns, which are more or less of an issue
   depending on local laws and the relationship between the ADMD and the
   person sending the email.

11.7.  Delivering Mail Producing a "Fail" Result

   Operators that choose to deliver mail for which SPF produces a "fail"
   result need to understand that they are admitting content that is
   explicitly not authorized by the purported sender.  While there are
   known failure modes that can be considered "false negatives", the
   distinct choice to admit those messages increases end-user exposure
   to likely harm.  This is especially true for domains belonging to
   known good actors that are typically well-behaved; unauthorized mail
   from those sources might well be subjected to much higher skepticism
   and content analysis.

   SPF does not, however, include the capacity to distinguish good
   actors from bad ones, nor does it handle the concept of known actors
   versus unknown ones.  Those notions are out of scope for this
   specification.

12.  Collected ABNF

   This section is normative, and any discrepancies with the ABNF
   fragments in the preceding text are to be resolved in favor of this
   grammar.

   See [RFC5234] for ABNF notation.  Please note that as per this ABNF
   definition, literal text strings (those in quotes) are case-
   insensitive.  Hence, "mx" matches "mx", "MX", "mX", and "Mx".

   record           = version terms *SP
   version          = "v=spf1"

   terms            = *( 1*SP ( directive / modifier ) )




Kitterman                    Standards Track                   [Page 46]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   directive        = [ qualifier ] mechanism
   qualifier        = "+" / "-" / "?" / "~"
   mechanism        = ( all / include
                      / a / mx / ptr / ip4 / ip6 / exists )

   all              = "all"
   include          = "include"  ":" domain-spec
   a                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
   mx               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
   ptr              = "ptr"    [ ":" domain-spec ]
   ip4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
   ip6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]
   exists           = "exists"   ":" domain-spec

   modifier         = redirect / explanation / unknown-modifier
   redirect         = "redirect" "=" domain-spec
   explanation      = "exp" "=" domain-spec
   unknown-modifier = name "=" macro-string
                      ; where name is not any known modifier

   ip4-cidr-length  = "/" ("0" / %x31-39 0*1DIGIT) ; value range 0-32
   ip6-cidr-length  = "/" ("0" / %x31-39 0*2DIGIT) ; value range 0-128
   dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]

   ip4-network      = qnum "." qnum "." qnum "." qnum
   qnum             = DIGIT                 ; 0-9
                      / %x31-39 DIGIT       ; 10-99
                      / "1" 2DIGIT          ; 100-199
                      / "2" %x30-34 DIGIT   ; 200-249
                      / "25" %x30-35        ; 250-255
            ; conventional dotted-quad notation, e.g., 192.0.2.0
   ip6-network      = <as per Section 2.2 of [RFC4291]>
            ; e.g., 2001:db8::cd30

   domain-spec      = macro-string domain-end
   domain-end       = ( "." toplabel [ "." ] ) / macro-expand

   toplabel         = ( *alphanum ALPHA *alphanum ) /
                      ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
                      ; LDH rule plus additional TLD restrictions
                      ; (see Section 2 of [RFC3696] for background)
   alphanum         = ALPHA / DIGIT

   explain-string   = *( macro-string / SP )

   macro-string     = *( macro-expand / macro-literal )
   macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
                      / "%%" / "%_" / "%-"



Kitterman                    Standards Track                   [Page 47]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   macro-literal    = %x21-24 / %x26-7E
                      ; visible characters except "%"
   macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
                      "c" / "r" / "t" / "v"
   transformers     = *DIGIT [ "r" ]
   delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="

   name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )

   header-field     = "Received-SPF:" [CFWS] result FWS [comment FWS]
                      [ key-value-list ] CRLF

   result           = "pass" / "fail" / "softfail" / "neutral" /
                      "none" / "temperror" / "permerror"

   key-value-list   = key-value-pair *( ";" [CFWS] key-value-pair )
                      [";"]

   key-value-pair   = key [CFWS] "=" ( dot-atom / quoted-string )

   key              = "client-ip" / "envelope-from" / "helo" /
                      "problem" / "receiver" / "identity" /
                       "mechanism" / name

   identity         = "mailfrom"   ; for the "MAIL FROM" identity
                      / "helo"     ; for the "HELO" identity
                      / name       ; other identities

   sender           = Mailbox
   ip               = ip4-network / ip6-network
   ALPHA            = <A-Z / a-z as per [RFC5234]>
   DIGIT            = <0-9 as per [RFC5234]>
   SP               = <space character as per [RFC5234]>
   dot-atom         = <unquoted word as per [RFC5322]>
   quoted-string    = <quoted string as per [RFC5322]>
   comment          = <comment string as per [RFC5322]>
   CFWS             = <comment or folding white space as per [RFC5322]>
   FWS              = <folding white space as per [RFC5322]>
   CRLF             = <standard end-of-line token as per [RFC5322]>

13.  Contributors and Acknowledgements

   This document is largely based on the work of Meng Weng Wong, Mark
   Lentczner, and Wayne Schlitt.  Although, as this section
   acknowledges, many people have contributed to this document, a very
   large portion of the writing and editing is due to Meng, Mark, and
   Wayne.




Kitterman                    Standards Track                   [Page 48]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   This design owes a debt of parentage to [RMX] by Hadmut Danisch and
   to [DMP] by Gordon Fecyk.  The idea of using a DNS record to check
   the legitimacy of an email address traces its ancestry further back
   through messages on the namedroppers mailing list by Paul Vixie
   [Vixie] (based on suggestion by Jim Miller) and by David Green
   [Green].

   Philip Gladstone contributed the concept of macros to the
   specification, multiplying the expressiveness of the language and
   making per-user and per-IP lookups possible.

   The authors of both this document and [RFC4408] would also like to
   thank the literally hundreds of individuals who have participated in
   the development of this design.  They are far too numerous to name,
   but they include the following:

      The participants in the SPFbis working group.  The folks on the
      spf-discuss mailing list.  The folks on the SPAM-L mailing list.
      The folks on the IRTF ASRG mailing list.  The folks on the IETF
      MARID mailing list.  The folks on #perl.

14.  IANA Considerations

14.1.  The SPF DNS Record Type

   Per [RFC4408], the IANA assigned the Resource Record Type and Qtype
   from the "Domain Name System (DNS) Parameters" registry for the SPF
   RR type with code 99.  The format of this type is identical to the
   TXT RR [RFC1035].  The character content of the record is encoded as
   [US-ASCII].

   Studies have shown that RRTYPE 99 has not seen any substantial use,
   and in fact its existence and mechanism defined in [RFC4408] have led
   to some interoperability issues.  Accordingly, its use is no longer
   appropriate for SPF version 1; implementations are not to use it.

   IANA has updated the "Resource Record (RR) TYPEs" registry to
   indicate that this document is the reference document for that
   RRTYPE.












Kitterman                    Standards Track                   [Page 49]

RFC 7208              Sender Policy Framework (SPF)           April 2014


14.2.  The Received-SPF Mail Header Field

   Per [RFC3864], the "Received-SPF:" header field is added to the IANA
   "Permanent Message Header Field Names" registry.  The following is
   the registration template:

      Header field name: Received-SPF Applicable protocol: mail
      ([RFC5322]) Status: standard Author/Change controller: IETF
      Specification document(s): RFC 7208

14.3.  SPF Modifier Registry

   IANA has changed the reference for the "exp" and "redirect" modifiers
   in the "Modifier Names" registry, under Sender Policy Framework
   Parameters, from [RFC4408] to this document.  Their status is
   unchanged.

15.  References

15.1.  Normative References

   [RFC1035]  Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, November 1987.

   [RFC1123]  Braden, R., "Requirements for Internet Hosts - Application
              and Support", STD 3, RFC 1123, October 1989.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC3463]  Vaudreuil, G., "Enhanced Mail System Status Codes",
              RFC 3463, January 2003.

   [RFC3864]  Klyne, G., Nottingham, M., and J. Mogul, "Registration
              Procedures for Message Header Fields", BCP 90, RFC 3864,
              September 2004.

   [RFC3986]  Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
              Resource Identifier (URI): Generic Syntax", STD 66,
              RFC 3986, January 2005.

   [RFC4291]  Hinden, R. and S. Deering, "IP Version 6 Addressing
              Architecture", RFC 4291, February 2006.

   [RFC5234]  Crocker, D. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234, January 2008.





Kitterman                    Standards Track                   [Page 50]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   [RFC5321]  Klensin, J., "Simple Mail Transfer Protocol", RFC 5321,
              October 2008.

   [RFC5322]  Resnick, P., Ed., "Internet Message Format", RFC 5322,
              October 2008.

   [RFC5598]  Crocker, D., "Internet Mail Architecture", RFC 5598,
              July 2009.

   [RFC5890]  Klensin, J., "Internationalized Domain Names for
              Applications (IDNA): Definitions and Document Framework",
              RFC 5890, August 2010.

   [RFC7001]  Kucherawy, M., "Message Header Field for Indicating
              Message Authentication Status", RFC 7001, September 2013.

   [US-ASCII]
              American National Standards Institute (formerly United
              States of America Standards Institute), "USA Code for
              Information Interchange, X3.4", 1968.

              ANSI X3.4-1968 has been replaced by newer versions with
              slight modifications, but the 1968 version remains
              definitive for the Internet.

15.2.  Informative References

   [BATV]     Levine, J., Crocker, D., Silberman, S., and T. Finch,
              "Bounce Address Tag Validation (BATV)", Work in Progress,
              May 2008.

   [DMP]      Fecyk, G., "Designated Mailers Protocol", Work in
              Progress, May 2004.

   [Green]    Green, D., "Domain-Authorized SMTP Mail", June 2002,
              <http://www.mhonarc.org/archive/html/ietf-asrg/2003-03/
              msg01525.html>.

   [RFC1034]  Mockapetris, P., "Domain names - concepts and facilities",
              STD 13, RFC 1034, November 1987.

   [RFC1983]  Malkin, G., "Internet Users' Glossary", RFC 1983,
              August 1996.

   [RFC2308]  Andrews, M., "Negative Caching of DNS Queries (DNS
              NCACHE)", RFC 2308, March 1998.





Kitterman                    Standards Track                   [Page 51]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   [RFC2671]  Vixie, P., "Extension Mechanisms for DNS (EDNS0)",
              RFC 2671, August 1999.

   [RFC2782]  Gulbrandsen, A., Vixie, P., and L. Esibov, "A DNS RR for
              specifying the location of services (DNS SRV)", RFC 2782,
              February 2000.

   [RFC3464]  Moore, K. and G. Vaudreuil, "An Extensible Message Format
              for Delivery Status Notifications", RFC 3464,
              January 2003.

   [RFC3696]  Klensin, J., "Application Techniques for Checking and
              Transformation of Names", RFC 3696, February 2004.

   [RFC3833]  Atkins, D. and R. Austein, "Threat Analysis of the Domain
              Name System (DNS)", RFC 3833, August 2004.

   [RFC3834]  Moore, K., "Recommendations for Automatic Responses to
              Electronic Mail", RFC 3834, August 2004.

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, March 2005.

   [RFC4408]  Wong, M. and W. Schlitt, "Sender Policy Framework (SPF)
              for Authorizing Use of Domains in E-Mail, Version 1",
              RFC 4408, April 2006.

   [RFC4632]  Fuller, V. and T. Li, "Classless Inter-domain Routing
              (CIDR): The Internet Address Assignment and Aggregation
              Plan", BCP 122, RFC 4632, August 2006.

   [RFC4880]  Callas, J., Donnerhacke, L., Finney, H., Shaw, D., and R.
              Thayer, "OpenPGP Message Format", RFC 4880, November 2007.

   [RFC4954]  Siemborski, R. and A. Melnikov, "SMTP Service Extension
              for Authentication", RFC 4954, July 2007.

   [RFC5507]  IAB, Faltstrom, P., Austein, R., and P. Koch, "Design
              Choices When Expanding the DNS", RFC 5507, April 2009.

   [RFC5751]  Ramsdell, B. and S. Turner, "Secure/Multipurpose Internet
              Mail Extensions (S/MIME) Version 3.2 Message
              Specification", RFC 5751, January 2010.

   [RFC5782]  Levine, J., "DNS Blacklists and Whitelists", RFC 5782,
              February 2010.




Kitterman                    Standards Track                   [Page 52]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   [RFC6409]  Gellens, R. and J. Klensin, "Message Submission for Mail",
              STD 72, RFC 6409, November 2011.

   [RFC6647]  Kucherawy, M. and D. Crocker, "Email Greylisting: An
              Applicability Statement for SMTP", RFC 6647, June 2012.

   [RFC6648]  Saint-Andre, P., Crocker, D., and M. Nottingham,
              "Deprecating the "X-" Prefix and Similar Constructs in
              Application Protocols", BCP 178, RFC 6648, June 2012.

   [RFC6652]  Kitterman, S., "Sender Policy Framework (SPF)
              Authentication Failure Reporting Using the Abuse Reporting
              Format", RFC 6652, June 2012.

   [RFC6686]  Kucherawy, M., "Resolution of the Sender Policy Framework
              (SPF) and Sender ID Experiments", RFC 6686, July 2012.

   [RFC6891]  Damas, J., Graff, M., and P. Vixie, "Extension Mechanisms
              for DNS (EDNS(0))", STD 75, RFC 6891, April 2013.

   [RMX]      Danisch, H., "The RMX DNS RR and method for lightweight
              SMTP sender authorization", Work in Progress, May 2004.

   [Vixie]    Vixie, P., "Repudiating MAIL FROM", 2002,
              <http://marc.info/?l=namedroppers&m=102298170127004&w=4>.


























Kitterman                    Standards Track                   [Page 53]

RFC 7208              Sender Policy Framework (SPF)           April 2014


Appendix A.  Extended Examples

   These examples are based on the following DNS setup:

   ; A domain with two mail servers, two hosts, and two servers
   ; at the domain name
   $ORIGIN example.com.
   @           MX  10 mail-a
               MX  20 mail-b
               A   192.0.2.10
               A   192.0.2.11
   amy         A   192.0.2.65
   bob         A   192.0.2.66
   mail-a      A   192.0.2.129
   mail-b      A   192.0.2.130
   www         CNAME example.com.

   ; A related domain
   $ORIGIN example.org.
   @           MX  10 mail-c
   mail-c      A   192.0.2.140

   ; The reverse IP for those addresses
   $ORIGIN 2.0.192.in-addr.arpa.
   10          PTR example.com.
   11          PTR example.com.
   65          PTR amy.example.com.
   66          PTR bob.example.com.
   129         PTR mail-a.example.com.
   130         PTR mail-b.example.com.
   140         PTR mail-c.example.org.

   ; A rogue reverse IP domain that claims to be
   ; something it's not
   $ORIGIN 0.0.10.in-addr.arpa.
   4           PTR bob.example.com.















Kitterman                    Standards Track                   [Page 54]

RFC 7208              Sender Policy Framework (SPF)           April 2014


A.1.  Simple Examples

   These examples show various possible published records for
   example.com and which values of <ip> would cause check_host() to
   return "pass".  Note that <domain> is "example.com".

   v=spf1 +all

      -- any <ip> passes

   v=spf1 a -all

      -- hosts 192.0.2.10 and 192.0.2.11 pass

   v=spf1 a:example.org -all

      -- no sending hosts pass since example.org has no A records

   v=spf1 mx -all

      -- sending hosts 192.0.2.129 and 192.0.2.130 pass

   v=spf1 mx:example.org -all

      -- sending host 192.0.2.140 passes

   v=spf1 mx mx:example.org -all

      -- sending hosts 192.0.2.129, 192.0.2.130, and 192.0.2.140 pass

   v=spf1 mx/30 mx:example.org/30 -all

      -- any sending host in 192.0.2.128/30 or 192.0.2.140/30 passes

   v=spf1 ptr -all

      -- sending host 192.0.2.65 passes (reverse DNS is valid and is
         in example.com)

      -- sending host 192.0.2.140 fails (reverse DNS is valid, but not
         in example.com)

      -- sending host 10.0.0.4 fails (reverse IP is not valid)








Kitterman                    Standards Track                   [Page 55]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   v=spf1 ip4:192.0.2.128/28 -all

      -- sending host 192.0.2.65 fails

      -- sending host 192.0.2.129 passes

A.2.  Multiple Domain Example

   These examples show the effect of related records:

      example.org: "v=spf1 include:example.com include:example.net -all"

   This record would be used if mail from example.org actually came
   through servers at example.com and example.net.  Example.org's
   designated servers are the union of example.com's and example.net's
   designated servers.

      la.example.org: "v=spf1 redirect=example.org"

      ny.example.org: "v=spf1 redirect=example.org"

      sf.example.org: "v=spf1 redirect=example.org"

   These records allow a set of domains that all use the same mail
   system to make use of that mail system's record.  In this way, only
   the mail system's record needs to be updated when the mail setup
   changes.  These domains' records never have to change.

A.3.  DNS Blacklist (DNSBL) Style Example

   Imagine that, in addition to the domain records listed above, there
   are these (see [RFC5782]):

   $ORIGIN _spf.example.com.
   mary.mobile-users                   A 127.0.0.2
   fred.mobile-users                   A 127.0.0.2
   15.15.168.192.joel.remote-users     A 127.0.0.2
   16.15.168.192.joel.remote-users     A 127.0.0.2













Kitterman                    Standards Track                   [Page 56]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   The following records describe users at example.com who mail from
   arbitrary servers, or who mail from personal servers.

   example.com:

   v=spf1 mx
          include:mobile-users._spf.%{d}
          include:remote-users._spf.%{d}
          -all

   mobile-users._spf.example.com:

   v=spf1 exists:%{l1r+}.%{d}

   remote-users._spf.example.com:

   v=spf1 exists:%{ir}.%{l1r+}.%{d}

A.4.  Multiple Requirements Example

   Say that your sender policy requires both that the IP address is
   within a certain range and that the reverse DNS for the IP matches.
   This can be done several ways, including the following:

   example.com.           SPF  ( "v=spf1 "
                                 "-include:ip4._spf.%{d} "
                                 "-include:ptr._spf.%{d} "
                                 "+all" )
   ip4._spf.example.com.  SPF  "v=spf1 -ip4:192.0.2.0/24 +all"
   ptr._spf.example.com.  SPF  "v=spf1 -ptr +all"

   This example shows how the "-include" mechanism can be useful, how an
   SPF record that ends in "+all" can be very restrictive, and the use
   of De Morgan's Law.

Appendix B.  Changes in Implementation Requirements from RFC 4408

   The modifications to implementation requirements from [RFC4408] are
   all either (a) corrections to errors in [RFC4408] or (b) additional
   documentation based on consensus of operational experience acquired
   since the publication of [RFC4408].

   o  Use of DNS RR type SPF (99) has been removed from the protocol;
      see [RFC6686] for background.

   o  A new DNS-related processing limit based on "void lookups" has
      been added (Section 4.6.4).




Kitterman                    Standards Track                   [Page 57]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   o  Use of the ptr mechanism and the %p macro has been strongly
      discouraged (Sections 5.5 and 7.2).  The ptr mechanism and the %p
      macro remain part of the protocol because they were found to be in
      use, but records ought to be updated to avoid them.

   o  Use of the "Authentication-Results" header field [RFC7001] as a
      possible alternative to use of the "Received-SPF" header field is
      discussed (Section 9.2).

   o  There have been a number of minor corrections to the ABNF to make
      it more clear and correct (Section 12).  SPF library implementers
      should give the revised ABNF a careful review to determine if
      implementation changes are needed.

   o  Use of X- fields in the ABNF has been removed; see [RFC6648] for
      background.

   o  Ambiguity about how to deal with invalid <domain-spec> after macro
      expansion has been documented.  Depending on one specific behavior
      has to be avoided (Section 4.8).

   o  General operational information has been updated and expanded
      based on eight years of post-[RFC4408] operations experience.  See
      Section 10 and Appendices D through G below.

   o  Security considerations have been reviewed and updated
      (Section 11).

Appendix C.  Further Testing Advice

   Another approach that can be helpful is to publish records that
   include a "tracking exists:" mechanism.  By looking at the name
   server logs, a rough list can then be generated.  For example:

      v=spf1 exists:_h.%{h}._l.%{l}._o.%{o}._i.%{i}._spf.%{d} ?all

   This associated macro expansion would cause the sending HELO domain,
   local-part of the sending email address, domain part of the sending
   email address, and the IP address from which the connection was
   received to be embedded in an SPF query and logged in the sender's
   DNS logs.

   This approach, which has been used since very early in the SPF
   project, allows senders to unilaterally collect data to evaluate the
   correctness of their SPF records.  Unlike newer feedback mechanisms,
   it does not require any special cooperation from SPF verifiers.  A
   similar example, one of the earliest SPF records published, can still
   be found as of this writing at altavista.net.



Kitterman                    Standards Track                   [Page 58]

RFC 7208              Sender Policy Framework (SPF)           April 2014


Appendix D.  SPF/Mediator Interactions

   There are three places that techniques can be used to ameliorate
   unintended SPF failures with mediators.

D.1.  Originating ADMDs

   The beginning, when email is first sent:

   o  "Neutral" results could be given for IP addresses that might be
      forwarders, instead of "fail" results based on a list of known
      reliable forwarders.  For example:

         "v=spf1 mx ?exists:%{ir}.whitelist.example.org -all"

      This would cause a lookup on a DNS White List (DNSWL) and cause a
      result of "fail" only for email not coming from either the
      domain's mx host(s) (SPF pass) or whitelisted sources (SPF
      neutral).  This, in effect, outsources an element of sender policy
      to the maintainer of the whitelist.

   o  The "MAIL FROM" identity could have additional information in the
      local-part that cryptographically identifies the mail as coming
      from an authorized source.  In this case, an SPF record such as
      the following could be used:

         "v=spf1 mx exists:%{l}._spf_verify.%{d} -all"

      Then, a specialized DNS server can be set up to serve the
      _spf_verify subdomain that validates the local-part.  Although
      this requires an extra DNS lookup, this happens only when the
      email would otherwise be rejected as not coming from a known good
      source.

      Note that due to the 63-character limit for domain labels, this
      approach only works reliably if the local-part signature scheme is
      guaranteed to either only produce local-parts with a maximum of
      63 characters or gracefully handle truncated local-parts.  The
      method used to secure the local-part is a local implementation
      issue; it need not be standard.  An example of one way to do it
      can be found in [BATV].

   o  Similarly, a specialized DNS server could be set up that will
      rate-limit the email coming from unexpected IP addresses.

         "v=spf1 mx exists:%{ir}._spf_rate.%{d} -all"





Kitterman                    Standards Track                   [Page 59]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   o  SPF allows the creation of per-user policies for special cases.
      For example, the following SPF record and appropriate wildcard DNS
      records can be used:

         "v=spf1 mx redirect=%{l1r+}._at_.%{o}._spf.%{d}"

D.2.  Mediators

   The middle, when email is forwarded:

   o  Mediators can solve the problem by rewriting the "MAIL FROM" to be
      in their own domain.  This means mail rejected from the external
      mailbox will have to be forwarded back to the original sender by
      the forwarding service.  Various schemes to do this exist, though
      they vary widely in complexity and resource requirements on the
      part of the mediator.

   o  Several popular MTAs can be forced from "alias" semantics to
      "mailing list" semantics by configuring an additional alias with
      "owner-" prepended to the original alias name (e.g., an alias of
      "friends: george@example.com, fred@example.org" would need another
      alias of the form "owner-friends: localowner").

   o  Mediators could reject mail that would "fail" SPF if forwarded
      using an SMTP reply code of 551, User not local (see Section 3.4
      of [RFC5321]) to communicate the correct target address to resend
      the mail to.

D.3.  Receiving ADMDs

   The end, when email is received:

   o  If the owner of the external mailbox wishes to trust the mediator,
      he can direct the external mailbox's MTA to skip SPF tests when
      the client host belongs to the mediator.

   o  Tests against other identities, such as the "HELO" identity, can
      be used to override a failed test against the "MAIL FROM"
      identity.

   o  For larger domains, it might not be possible to have a complete or
      accurate list of forwarding services used by the owners of the
      domain's mailboxes.  In such cases, whitelists of generally
      recognized forwarding services could be employed.







Kitterman                    Standards Track                   [Page 60]

RFC 7208              Sender Policy Framework (SPF)           April 2014


Appendix E.  Mail Services

   MSPs (Mail Service Providers -- Section 2.3 of [RFC5598]) that offer
   mail services to third-party domains, such as the sending of bulk
   mail, might want to adjust their configurations in light of the
   authorization check described in this document.  If the domain part
   of the "MAIL FROM" identity used for such email uses one of the MSP's
   domains, then the provider needs only to ensure that its sending host
   is authorized by its own SPF record, if any.

   If the "MAIL FROM" identity does not use the MSP's domain, then extra
   care has to be taken.  The SPF record format has several options for
   the third-party domain to authorize the service provider's MTAs to
   send mail on its behalf.  For MSPs, such as ISPs, that have a wide
   variety of customers using the same MTA, steps are required to
   mitigate the risk of cross-customer forgery (see Section 11.4).

Appendix F.  MTA Relays

   Relays are described in [RFC5598], Section 2.2.2.  The authorization
   check generally precludes the use of arbitrary MTA relays between the
   sender and receiver of an email message.

   Within an organization, MTA relays can be effectively deployed.
   However, for the purposes of this document, such relays are
   effectively transparent.  The SPF authorization check is a check
   between border MTAs of different ADMDs.

   For mail senders, this means published SPF records have to authorize
   any MTAs that actually send across the Internet.  Usually, these are
   just the border MTAs as internal MTAs simply forward mail to these
   MTAs for relaying.

   The receiving ADMD will generally want to perform the authorization
   check at the boundary MTAs, including all secondary MXs.  Internal
   MTAs (including MTAs that might serve as both boundary MTAs and
   internal relays from secondary MXs when they are processing the
   relayed mail stream) then do not perform the authorization test.  To
   perform the authorization test other than at the boundary, the host
   that first transferred the message to the receiving ADMD has to be
   determined, which can be difficult to extract from the message header
   because (a) header fields can be forged or malformed, and (b) there's
   no standard way to encode that information such that it can be
   reliably extracted.  Testing other than at the boundary is likely to
   produce unreliable results.  This is described further in Appendix D
   of [RFC7001].





Kitterman                    Standards Track                   [Page 61]

RFC 7208              Sender Policy Framework (SPF)           April 2014


Appendix G.  Local Policy Considerations

   SPF results can be used in combination with other methods to
   determine the final local disposition (either positive or negative)
   of a message.  It can also be considered dispositive on its own.

G.1.  Policy for SPF Pass

   SPF "pass" results can be used in combination with "whitelists" of
   known "good" domains to bypass some or all additional pre-delivery
   email checks.  Exactly which checks and how to determine appropriate
   whitelist entries have to be based on local conditions and
   requirements.

G.2.  Policy for SPF Fail

   SPF "fail" results can be used to reject messages during the SMTP
   transaction based on either "MAIL FROM" or "HELO" identity results.
   This reduces resource requirements for various content-filtering
   methods and conserves bandwidth since rejection can be done before
   the SMTP content is transferred.  It also gives immediate feedback to
   the sender, who might then be able to resolve the issue.  Due to some
   of the issues described in this section (Appendix G), SPF-based
   rejection does present some risk of rejecting legitimate email when
   rejecting email based on "MAIL FROM" results.

   SPF "fail" results can alternately be used as one input into a larger
   set of evaluations that might, based on a combination of SPF "fail"
   results with other evaluation techniques, result in the email being
   marked negatively in some way (this might be via delivery to a
   special spam folder, modifying subject lines, or other locally
   determined means).  Developing the details of such an approach has to
   be based on local conditions and requirements.  Using SPF results in
   this way does not have the advantages of resource conservation and
   immediate feedback to the sender associated with SMTP rejection, but
   could produce fewer undesirable rejections in a well-designed system.
   Such an approach might result in email that was not authorized by the
   sending ADMD being unknowingly delivered to end users.

   Either general approach can be used, as they both leave a clear
   disposition of emails; either they are delivered in some manner or
   the sender is notified of the failure.  Other dispositions such as
   "dropping" or deleting email after acceptance are inappropriate
   because they leave uncertainty and reduce the overall reliability and
   utility of email across the Internet.






Kitterman                    Standards Track                   [Page 62]

RFC 7208              Sender Policy Framework (SPF)           April 2014


G.3.  Policy for SPF Permerror

   The "permerror" result (see Section 2.6.7) indicates that the SPF
   processing module at the receiver determined that the retrieved SPF
   policy record could not be interpreted.  This gives no true
   indication about the authorized use of the data found in the
   envelope.

   As with all results, implementers have a choice to make regarding
   what to do with a message that yields this result.  SMTP allows only
   a few basic options.

   Rejection of the message is an option, in that it is the one thing a
   receiver can do to draw attention to the difficulty encountered while
   protecting itself from messages that do not have a definite SPF
   result of some kind.  However, if the SPF implementation is defective
   and returns spurious "permerror" results, only the sender is actively
   notified of the defect (in the form of rejected mail), and not the
   receiver making use of SPF.

   The less intrusive handling choice is to deliver the message, perhaps
   with some kind of annotation of the difficulty encountered and/or
   logging of a similar nature.  However, this will not be desirable to
   SPF verifier operators that wish to implement SPF checking as
   strictly as possible, nor is this sort of passive reporting of
   problems typically effective.

   There is of course the option of placing this choice in the hands of
   the SPF verifier operator rather than the implementer since this kind
   of choice is often a matter of local policy rather than a condition
   with a universal solution, but this adds one more piece of complexity
   to an already non-trivial environment.

   Both implementers and SPF verifier operators need to be cautious of
   all choices and outcomes when handling SPF results.

G.4.  Policy for SPF Temperror

   The "temperror" result (see Section 2.6.6) indicates that the SPF
   processing module at the receiver could not retrieve an SPF policy
   record due to a (probably) transient condition.  This gives no true
   indication about the authorized use of the data found in the
   envelope.

   As with all results, implementers have a choice to make regarding
   what to do with a message that yields this result.  SMTP allows only
   a few basic options.




Kitterman                    Standards Track                   [Page 63]

RFC 7208              Sender Policy Framework (SPF)           April 2014


   Deferring the message is an option, in that it is the one thing a
   receiver can do to draw attention to the difficulty encountered while
   protecting itself from messages that do not have a definite SPF
   result of some kind.  However, if the SPF implementation is defective
   and returns spurious "temperror" results, only the sender is actively
   notified of the defect (in the form of mail rejected after it times
   out of the sending queue), and not the receiver making use of SPF.

   Because of long queue lifetimes, it is possible that mail will be
   repeatedly deferred for several days, and so any awareness that the
   sender may have regarding a problem could be quite delayed.  If
   "temperrors" persist for multiple delivery attempts, it might be
   preferable to treat the error as permanent and reduce the amount of
   time the message is in transit.

   The less intrusive handling choice is to deliver the message, perhaps
   with some kind of annotation of the difficulty encountered and/or
   logging of a similar nature.  However, this will not be desirable to
   SPF verifier operators that wish to implement SPF checking as
   strictly as possible, nor is this sort of passive reporting of
   problems typically effective.

   There is of course the option of placing this choice in the hands of
   the SPF verifier operator rather than the implementer since this kind
   of choice is often a matter of local policy rather than a condition
   with a universal solution, but this adds one more piece of complexity
   to an already non-trivial environment.

   Both implementers and SPF verifier operators need to be cautious of
   all choices and outcomes when handling SPF results.

Author's Address

   Scott Kitterman
   Kitterman Technical Services
   3611 Scheel Dr.
   Ellicott City, MD  21042
   United States of America

   EMail: scott@kitterman.com











Kitterman                    Standards Track                   [Page 64]


```

---

# RFC 6376 — DKIM — DomainKeys Identified Mail Signatures

```






Internet Engineering Task Force (IETF)                   D. Crocker, Ed.
Request for Comments: 6376                   Brandenburg InternetWorking
Obsoletes: 4871, 5672                                     T. Hansen, Ed.
Category: Standards Track                              AT&T Laboratories
ISSN: 2070-1721                                        M. Kucherawy, Ed.
                                                               Cloudmark
                                                          September 2011


              DomainKeys Identified Mail (DKIM) Signatures

Abstract

   DomainKeys Identified Mail (DKIM) permits a person, role, or
   organization that owns the signing domain to claim some
   responsibility for a message by associating the domain with the
   message.  This can be an author's organization, an operational relay,
   or one of their agents.  DKIM separates the question of the identity
   of the Signer of the message from the purported author of the
   message.  Assertion of responsibility is validated through a
   cryptographic signature and by querying the Signer's domain directly
   to retrieve the appropriate public key.  Message transit from author
   to recipient is through relays that typically make no substantive
   change to the message content and thus preserve the DKIM signature.

   This memo obsoletes RFC 4871 and RFC 5672.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 5741.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc6376.

Copyright Notice

   Copyright (c) 2011 IETF Trust and the persons identified as the
   document authors.  All rights reserved.






Crocker, et al.              Standards Track                    [Page 1]

RFC 6376                     DKIM Signatures              September 2011


   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.

   This document may contain material from IETF Documents or IETF
   Contributions published or made publicly available before November
   10, 2008.  The person(s) controlling the copyright in some of this
   material may not have granted the IETF Trust the right to allow
   modifications of such material outside the IETF Standards Process.
   Without obtaining an adequate license from the person(s) controlling
   the copyright in such materials, this document may not be modified
   outside the IETF Standards Process, and derivative works of it may
   not be created outside the IETF Standards Process, except to format
   it for publication as an RFC or to translate it into languages other
   than English.

Table of Contents

   1.  Introduction . . . . . . . . . . . . . . . . . . . . . . . . .  4
     1.1.  DKIM Architecture Documents  . . . . . . . . . . . . . . .  5
     1.2.  Signing Identity . . . . . . . . . . . . . . . . . . . . .  5
     1.3.  Scalability  . . . . . . . . . . . . . . . . . . . . . . .  5
     1.4.  Simple Key Management  . . . . . . . . . . . . . . . . . .  6
     1.5.  Data Integrity . . . . . . . . . . . . . . . . . . . . . .  6
   2.  Terminology and Definitions  . . . . . . . . . . . . . . . . .  6
     2.1.  Signers  . . . . . . . . . . . . . . . . . . . . . . . . .  6
     2.2.  Verifiers  . . . . . . . . . . . . . . . . . . . . . . . .  7
     2.3.  Identity . . . . . . . . . . . . . . . . . . . . . . . . .  7
     2.4.  Identifier . . . . . . . . . . . . . . . . . . . . . . . .  7
     2.5.  Signing Domain Identifier (SDID) . . . . . . . . . . . . .  7
     2.6.  Agent or User Identifier (AUID)  . . . . . . . . . . . . .  7
     2.7.  Identity Assessor  . . . . . . . . . . . . . . . . . . . .  7
     2.8.  Whitespace . . . . . . . . . . . . . . . . . . . . . . . .  8
     2.9.  Imported ABNF Tokens . . . . . . . . . . . . . . . . . . .  8
     2.10. Common ABNF Tokens . . . . . . . . . . . . . . . . . . . .  9
     2.11. DKIM-Quoted-Printable  . . . . . . . . . . . . . . . . . .  9
   3.  Protocol Elements  . . . . . . . . . . . . . . . . . . . . . . 10
     3.1.  Selectors  . . . . . . . . . . . . . . . . . . . . . . . . 10
     3.2.  Tag=Value Lists  . . . . . . . . . . . . . . . . . . . . . 12
     3.3.  Signing and Verification Algorithms  . . . . . . . . . . . 13
     3.4.  Canonicalization . . . . . . . . . . . . . . . . . . . . . 14
     3.5.  The DKIM-Signature Header Field  . . . . . . . . . . . . . 18



Crocker, et al.              Standards Track                    [Page 2]

RFC 6376                     DKIM Signatures              September 2011


     3.6.  Key Management and Representation  . . . . . . . . . . . . 26
     3.7.  Computing the Message Hashes . . . . . . . . . . . . . . . 29
     3.8.  Input Requirements . . . . . . . . . . . . . . . . . . . . 32
     3.9.  Output Requirements  . . . . . . . . . . . . . . . . . . . 32
     3.10. Signing by Parent Domains  . . . . . . . . . . . . . . . . 33
     3.11. Relationship between SDID and AUID . . . . . . . . . . . . 33
   4.  Semantics of Multiple Signatures . . . . . . . . . . . . . . . 34
     4.1.  Example Scenarios  . . . . . . . . . . . . . . . . . . . . 34
     4.2.  Interpretation . . . . . . . . . . . . . . . . . . . . . . 35
   5.  Signer Actions . . . . . . . . . . . . . . . . . . . . . . . . 36
     5.1.  Determine Whether the Email Should Be Signed and by
           Whom . . . . . . . . . . . . . . . . . . . . . . . . . . . 36
     5.2.  Select a Private Key and Corresponding Selector
           Information  . . . . . . . . . . . . . . . . . . . . . . . 37
     5.3.  Normalize the Message to Prevent Transport Conversions . . 37
     5.4.  Determine the Header Fields to Sign  . . . . . . . . . . . 38
     5.5.  Compute the Message Hash and Signature . . . . . . . . . . 43
     5.6.  Insert the DKIM-Signature Header Field . . . . . . . . . . 43
   6.  Verifier Actions . . . . . . . . . . . . . . . . . . . . . . . 43
     6.1.  Extract Signatures from the Message  . . . . . . . . . . . 44
     6.2.  Communicate Verification Results . . . . . . . . . . . . . 49
     6.3.  Interpret Results/Apply Local Policy . . . . . . . . . . . 50
   7.  IANA Considerations  . . . . . . . . . . . . . . . . . . . . . 51
     7.1.  Email Authentication Methods Registry  . . . . . . . . . . 51
     7.2.  DKIM-Signature Tag Specifications  . . . . . . . . . . . . 51
     7.3.  DKIM-Signature Query Method Registry . . . . . . . . . . . 52
     7.4.  DKIM-Signature Canonicalization Registry . . . . . . . . . 52
     7.5.  _domainkey DNS TXT Resource Record Tag Specifications  . . 53
     7.6.  DKIM Key Type Registry . . . . . . . . . . . . . . . . . . 53
     7.7.  DKIM Hash Algorithms Registry  . . . . . . . . . . . . . . 54
     7.8.  DKIM Service Types Registry  . . . . . . . . . . . . . . . 54
     7.9.  DKIM Selector Flags Registry . . . . . . . . . . . . . . . 55
     7.10. DKIM-Signature Header Field  . . . . . . . . . . . . . . . 55
   8.  Security Considerations  . . . . . . . . . . . . . . . . . . . 55
     8.1.  ASCII Art Attacks  . . . . . . . . . . . . . . . . . . . . 55
     8.2.  Misuse of Body Length Limits ("l=" Tag)  . . . . . . . . . 55
     8.3.  Misappropriated Private Key  . . . . . . . . . . . . . . . 56
     8.4.  Key Server Denial-of-Service Attacks . . . . . . . . . . . 56
     8.5.  Attacks against the DNS  . . . . . . . . . . . . . . . . . 57
     8.6.  Replay/Spam Attacks  . . . . . . . . . . . . . . . . . . . 57
     8.7.  Limits on Revoking Keys  . . . . . . . . . . . . . . . . . 58
     8.8.  Intentionally Malformed Key Records  . . . . . . . . . . . 58
     8.9.  Intentionally Malformed DKIM-Signature Header Fields . . . 58
     8.10. Information Leakage  . . . . . . . . . . . . . . . . . . . 58
     8.11. Remote Timing Attacks  . . . . . . . . . . . . . . . . . . 59
     8.12. Reordered Header Fields  . . . . . . . . . . . . . . . . . 59
     8.13. RSA Attacks  . . . . . . . . . . . . . . . . . . . . . . . 59
     8.14. Inappropriate Signing by Parent Domains  . . . . . . . . . 59



Crocker, et al.              Standards Track                    [Page 3]

RFC 6376                     DKIM Signatures              September 2011


     8.15. Attacks Involving Extra Header Fields  . . . . . . . . . . 60
   9.  References . . . . . . . . . . . . . . . . . . . . . . . . . . 61
     9.1.  Normative References . . . . . . . . . . . . . . . . . . . 61
     9.2.  Informative References . . . . . . . . . . . . . . . . . . 62
   Appendix A.  Example of Use (INFORMATIVE)  . . . . . . . . . . . . 64
     A.1.  The User Composes an Email . . . . . . . . . . . . . . . . 64
     A.2.  The Email is Signed  . . . . . . . . . . . . . . . . . . . 65
     A.3.  The Email Signature is Verified  . . . . . . . . . . . . . 66
   Appendix B.  Usage Examples (INFORMATIVE)  . . . . . . . . . . . . 67
     B.1.  Alternate Submission Scenarios . . . . . . . . . . . . . . 67
     B.2.  Alternate Delivery Scenarios . . . . . . . . . . . . . . . 69
   Appendix C.  Creating a Public Key (INFORMATIVE) . . . . . . . . . 71
     C.1.  Compatibility with DomainKeys Key Records  . . . . . . . . 72
     C.2.  RFC 4871 Compatibility . . . . . . . . . . . . . . . . . . 73
   Appendix D.  MUA Considerations (INFORMATIVE)  . . . . . . . . . . 73
   Appendix E.  Changes since RFC 4871  . . . . . . . . . . . . . . . 73
   Appendix F.  Acknowledgments . . . . . . . . . . . . . . . . . . . 75

1.  Introduction

   DomainKeys Identified Mail (DKIM) permits a person, role, or
   organization to claim some responsibility for a message by
   associating a domain name [RFC1034] with the message [RFC5322], which
   they are authorized to use.  This can be an author's organization, an
   operational relay, or one of their agents.  Assertion of
   responsibility is validated through a cryptographic signature and by
   querying the Signer's domain directly to retrieve the appropriate
   public key.  Message transit from author to recipient is through
   relays that typically make no substantive change to the message
   content and thus preserve the DKIM signature.  A message can contain
   multiple signatures, from the same or different organizations
   involved with the message.

   The approach taken by DKIM differs from previous approaches to
   message signing (e.g., Secure/Multipurpose Internet Mail Extensions
   (S/MIME) [RFC5751], OpenPGP [RFC4880]) in that:

   o  the message signature is written as a message header field so that
      neither human recipients nor existing MUA (Mail User Agent)
      software is confused by signature-related content appearing in the
      message body;

   o  there is no dependency on public- and private-key pairs being
      issued by well-known, trusted certificate authorities;

   o  there is no dependency on the deployment of any new Internet
      protocols or services for public-key distribution or revocation;




Crocker, et al.              Standards Track                    [Page 4]

RFC 6376                     DKIM Signatures              September 2011


   o  signature verification failure does not force rejection of the
      message;

   o  no attempt is made to include encryption as part of the mechanism;
      and

   o  message archiving is not a design goal.

   DKIM:

   o  is compatible with the existing email infrastructure and
      transparent to the fullest extent possible;

   o  requires minimal new infrastructure;

   o  can be implemented independently of clients in order to reduce
      deployment time;

   o  can be deployed incrementally; and

   o  allows delegation of signing to third parties.

1.1.  DKIM Architecture Documents

   Readers are advised to be familiar with the material in [RFC4686],
   [RFC5585], and [RFC5863], which provide the background for the
   development of DKIM, an overview of the service, and deployment and
   operations guidance and advice, respectively.

1.2.  Signing Identity

   DKIM separates the question of the identity of the Signer of the
   message from the purported author of the message.  In particular, a
   signature includes the identity of the Signer.  Verifiers can use the
   signing information to decide how they want to process the message.
   The signing identity is included as part of the signature header
   field.

      INFORMATIVE RATIONALE: The signing identity specified by a DKIM
      signature is not required to match an address in any particular
      header field because of the broad methods of interpretation by
      recipient mail systems, including MUAs.

1.3.  Scalability

   DKIM is designed to support the extreme scalability requirements that
   characterize the email identification problem.  There are many
   millions of domains and a much larger number of individual addresses.



Crocker, et al.              Standards Track                    [Page 5]

RFC 6376                     DKIM Signatures              September 2011


   DKIM seeks to preserve the positive aspects of the current email
   infrastructure, such as the ability for anyone to communicate with
   anyone else without introduction.

1.4.  Simple Key Management

   DKIM differs from traditional hierarchical public-key systems in that
   no certificate authority infrastructure is required; the Verifier
   requests the public key from a repository in the domain of the
   claimed Signer directly rather than from a third party.

   The DNS is proposed as the initial mechanism for the public keys.
   Thus, DKIM currently depends on DNS administration and the security
   of the DNS system.  DKIM is designed to be extensible to other key
   fetching services as they become available.

1.5.  Data Integrity

   A DKIM signature associates the "d=" name with the computed hash of
   some or all of the message (see Section 3.7) in order to prevent the
   reuse of the signature with different messages.  Verifying the
   signature asserts that the hashed content has not changed since it
   was signed and asserts nothing else about "protecting" the end-to-end
   integrity of the message.

2.  Terminology and Definitions

   This section defines terms used in the rest of the document.

   DKIM is designed to operate within the Internet Mail service, as
   defined in [RFC5598].  Basic email terminology is taken from that
   specification.

   Syntax descriptions use Augmented BNF (ABNF) [RFC5234].

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   [RFC2119].  These words take their normative meanings only when they
   are presented in ALL UPPERCASE.

2.1.  Signers

   Elements in the mail system that sign messages on behalf of a domain
   are referred to as Signers.  These may be MUAs (Mail User Agents),
   MSAs (Mail Submission Agents), MTAs (Mail Transfer Agents), or other
   agents such as mailing list exploders.  In general, any Signer will




Crocker, et al.              Standards Track                    [Page 6]

RFC 6376                     DKIM Signatures              September 2011


   be involved in the injection of a message into the message system in
   some way.  The key issue is that a message must be signed before it
   leaves the administrative domain of the Signer.

2.2.  Verifiers

   Elements in the mail system that verify signatures are referred to as
   Verifiers.  These may be MTAs, Mail Delivery Agents (MDAs), or MUAs.
   In most cases, it is expected that Verifiers will be close to an end
   user (reader) of the message or some consuming agent such as a
   mailing list exploder.

2.3.  Identity

   A person, role, or organization.  In the context of DKIM, examples
   include the author, the author's organization, an ISP along the
   handling path, an independent trust assessment service, and a mailing
   list operator.

2.4.  Identifier

   A label that refers to an identity.

2.5.  Signing Domain Identifier (SDID)

   A single domain name that is the mandatory payload output of DKIM and
   that refers to the identity claiming some responsibility for the
   message by signing it.  It is specified in Section 3.5.

2.6.  Agent or User Identifier (AUID)

   A single identifier that refers to the agent or user on behalf of
   whom the Signing Domain Identifier (SDID) has taken responsibility.
   The AUID comprises a domain name and an optional <local-part>.  The
   domain name is the same as that used for the SDID or is a subdomain
   of it.  For DKIM processing, the domain name portion of the AUID has
   only basic domain name semantics; any possible owner-specific
   semantics are outside the scope of DKIM.  It is specified in
   Section 3.5.

   Note that acceptable values for the AUID may be constrained via a
   flag in the public-key record.  (See Section 3.6.1.)

2.7.  Identity Assessor

   An element in the mail system that consumes DKIM's payload, which is
   the responsible Signing Domain Identifier (SDID).  The Identity
   Assessor is dedicated to the assessment of the delivered identifier.



Crocker, et al.              Standards Track                    [Page 7]

RFC 6376                     DKIM Signatures              September 2011


   Other DKIM (and non-DKIM) values can also be used by the Identity
   Assessor (if they are available) to provide a more general message
   evaluation filtering engine.  However, this additional activity is
   outside the scope of this specification.

2.8.  Whitespace

   There are three forms of whitespace:

   o  WSP represents simple whitespace, i.e., a space or a tab character
      (formal definition in [RFC5234]).

   o  LWSP is linear whitespace, defined as WSP plus CRLF (formal
      definition in [RFC5234]).

   o  FWS is folding whitespace.  It allows multiple lines separated by
      CRLF followed by at least one whitespace, to be joined.

   The formal ABNF for these are (WSP and LWSP are given for information
   only):

   WSP =   SP / HTAB
   LWSP =  *(WSP / CRLF WSP)
   FWS =   [*WSP CRLF] 1*WSP

   The definition of FWS is identical to that in [RFC5322] except for
   the exclusion of obs-FWS.

2.9.  Imported ABNF Tokens

   The following tokens are imported from other RFCs as noted.  Those
   RFCs should be considered definitive.

   The following tokens are imported from [RFC5321]:

   o  "local-part" (implementation warning: this permits quoted strings)

   o  "sub-domain"

   The following tokens are imported from [RFC5322]:

   o  "field-name" (name of a header field)

   o  "dot-atom-text" (in the local-part of an email address)

   The following tokens are imported from [RFC2045]:

   o  "qp-section" (a single line of quoted-printable-encoded text)



Crocker, et al.              Standards Track                    [Page 8]

RFC 6376                     DKIM Signatures              September 2011


   o  "hex-octet" (a quoted-printable encoded octet)

      INFORMATIVE NOTE: Be aware that the ABNF in [RFC2045] does not
      obey the rules of [RFC5234] and must be interpreted accordingly,
      particularly as regards case folding.

   Other tokens not defined herein are imported from [RFC5234].  These
   are intuitive primitives such as SP, HTAB, WSP, ALPHA, DIGIT, CRLF,
   etc.

2.10.  Common ABNF Tokens

   The following ABNF tokens are used elsewhere in this document:

   hyphenated-word =  ALPHA [ *(ALPHA / DIGIT / "-") (ALPHA / DIGIT) ]
   ALPHADIGITPS    =  (ALPHA / DIGIT / "+" / "/")
   base64string    =  ALPHADIGITPS *([FWS] ALPHADIGITPS)
                      [ [FWS] "=" [ [FWS] "=" ] ]
   hdr-name        =  field-name
   qp-hdr-value    =  dkim-quoted-printable    ; with "|" encoded

2.11.  DKIM-Quoted-Printable

   The DKIM-Quoted-Printable encoding syntax resembles that described in
   Quoted-Printable [RFC2045], Section 6.7: any character MAY be encoded
   as an "=" followed by two hexadecimal digits from the alphabet
   "0123456789ABCDEF" (no lowercase characters permitted) representing
   the hexadecimal-encoded integer value of that character.  All control
   characters (those with values < %x20), 8-bit characters (values >
   %x7F), and the characters DEL (%x7F), SPACE (%x20), and semicolon
   (";", %x3B) MUST be encoded.  Note that all whitespace, including
   SPACE, CR, and LF characters, MUST be encoded.  After encoding, FWS
   MAY be added at arbitrary locations in order to avoid excessively
   long lines; such whitespace is NOT part of the value, and MUST be
   removed before decoding.  Use of characters not listed as "mail-safe"
   in [RFC2049] is NOT RECOMMENDED.

   ABNF:

   dkim-quoted-printable =  *(FWS / hex-octet / dkim-safe-char)
                               ; hex-octet is from RFC2045
   dkim-safe-char        =  %x21-3A / %x3C / %x3E-7E
                               ; '!' - ':', '<', '>' - '~'








Crocker, et al.              Standards Track                    [Page 9]

RFC 6376                     DKIM Signatures              September 2011


      INFORMATIVE NOTE: DKIM-Quoted-Printable differs from Quoted-
      Printable as defined in [RFC2045] in several important ways:

      1.  Whitespace in the input text, including CR and LF, must be
          encoded.  [RFC2045] does not require such encoding, and does
          not permit encoding of CR or LF characters that are part of a
          CRLF line break.

      2.  Whitespace in the encoded text is ignored.  This is to allow
          tags encoded using DKIM-Quoted-Printable to be wrapped as
          needed.  In particular, [RFC2045] requires that line breaks in
          the input be represented as physical line breaks; that is not
          the case here.

      3.  The "soft line break" syntax ("=" as the last non-whitespace
          character on the line) does not apply.

      4.  DKIM-Quoted-Printable does not require that encoded lines be
          no more than 76 characters long (although there may be other
          requirements depending on the context in which the encoded
          text is being used).

3.  Protocol Elements

   Protocol Elements are conceptual parts of the protocol that are not
   specific to either Signers or Verifiers.  The protocol descriptions
   for Signers and Verifiers are described in later sections ("Signer
   Actions" (Section 5) and "Verifier Actions" (Section 6)).  NOTE: This
   section must be read in the context of those sections.

3.1.  Selectors

   To support multiple concurrent public keys per signing domain, the
   key namespace is subdivided using "selectors".  For example,
   selectors might indicate the names of office locations (e.g.,
   "sanfrancisco", "coolumbeach", and "reykjavik"), the signing date
   (e.g., "january2005", "february2005", etc.), or even an individual
   user.

   Selectors are needed to support some important use cases.  For
   example:

   o  Domains that want to delegate signing capability for a specific
      address for a given duration to a partner, such as an advertising
      provider or other outsourced function.

   o  Domains that want to allow frequent travelers to send messages
      locally without the need to connect with a particular MSA.



Crocker, et al.              Standards Track                   [Page 10]

RFC 6376                     DKIM Signatures              September 2011


   o  "Affinity" domains (e.g., college alumni associations) that
      provide forwarding of incoming mail, but that do not operate a
      mail submission agent for outgoing mail.

   Periods are allowed in selectors and are component separators.  When
   keys are retrieved from the DNS, periods in selectors define DNS
   label boundaries in a manner similar to the conventional use in
   domain names.  Selector components might be used to combine dates
   with locations, for example, "march2005.reykjavik".  In a DNS
   implementation, this can be used to allow delegation of a portion of
   the selector namespace.

   ABNF:

   selector =   sub-domain *( "." sub-domain )

   The number of public keys and corresponding selectors for each domain
   is determined by the domain owner.  Many domain owners will be
   satisfied with just one selector, whereas administratively
   distributed organizations can choose to manage disparate selectors
   and key pairs in different regions or on different email servers.

   Beyond administrative convenience, selectors make it possible to
   seamlessly replace public keys on a routine basis.  If a domain
   wishes to change from using a public key associated with selector
   "january2005" to a public key associated with selector
   "february2005", it merely makes sure that both public keys are
   advertised in the public-key repository concurrently for the
   transition period during which email may be in transit prior to
   verification.  At the start of the transition period, the outbound
   email servers are configured to sign with the "february2005" private
   key.  At the end of the transition period, the "january2005" public
   key is removed from the public-key repository.

      INFORMATIVE NOTE: A key may also be revoked as described below.
      The distinction between revoking and removing a key selector
      record is subtle.  When phasing out keys as described above, a
      signing domain would probably simply remove the key record after
      the transition period.  However, a signing domain could elect to
      revoke the key (but maintain the key record) for a further period.
      There is no defined semantic difference between a revoked key and
      a removed key.

   While some domains may wish to make selector values well-known,
   others will want to take care not to allocate selector names in a way
   that allows harvesting of data by outside parties.  For example, if
   per-user keys are issued, the domain owner will need to decide




Crocker, et al.              Standards Track                   [Page 11]

RFC 6376                     DKIM Signatures              September 2011


   whether to associate this selector directly with the name of a
   registered end user or make it some unassociated random value, such
   as a fingerprint of the public key.

      INFORMATIVE OPERATIONS NOTE: Reusing a selector with a new key
      (for example, changing the key associated with a user's name)
      makes it impossible to tell the difference between a message that
      didn't verify because the key is no longer valid and a message
      that is actually forged.  For this reason, Signers are ill-advised
      to reuse selectors for new keys.  A better strategy is to assign
      new keys to new selectors.

3.2.  Tag=Value Lists

   DKIM uses a simple "tag=value" syntax in several contexts, including
   in messages and domain signature records.

   Values are a series of strings containing either plain text, "base64"
   text (as defined in [RFC2045], Section 6.8), "qp-section" (ibid,
   Section 6.7), or "dkim-quoted-printable" (as defined in
   Section 2.11).  The name of the tag will determine the encoding of
   each value.  Unencoded semicolon (";") characters MUST NOT occur in
   the tag value, since that separates tag-specs.

      INFORMATIVE IMPLEMENTATION NOTE: Although the "plain text" defined
      below (as "tag-value") only includes 7-bit characters, an
      implementation that wished to anticipate future standards would be
      advised not to preclude the use of UTF-8-encoded ([RFC3629]) text
      in tag=value lists.

   Formally, the ABNF syntax rules are as follows:

   tag-list  =  tag-spec *( ";" tag-spec ) [ ";" ]
   tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
   tag-name  =  ALPHA *ALNUMPUNC
   tag-value =  [ tval *( 1*(WSP / FWS) tval ) ]
                     ; Prohibits WSP and FWS at beginning and end
   tval      =  1*VALCHAR
   VALCHAR   =  %x21-3A / %x3C-7E
                     ; EXCLAMATION to TILDE except SEMICOLON
   ALNUMPUNC =  ALPHA / DIGIT / "_"

   Note that WSP is allowed anywhere around tags.  In particular, any
   WSP after the "=" and any WSP before the terminating ";" is not part
   of the value; however, WSP inside the value is significant.






Crocker, et al.              Standards Track                   [Page 12]

RFC 6376                     DKIM Signatures              September 2011


   Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
   processed as case sensitive unless the specific tag description of
   semantics specifies case insensitivity.

   Tags with duplicate names MUST NOT occur within a single tag-list; if
   a tag name does occur more than once, the entire tag-list is invalid.

   Whitespace within a value MUST be retained unless explicitly excluded
   by the specific tag description.

   Tag=value pairs that represent the default value MAY be included to
   aid legibility.

   Unrecognized tags MUST be ignored.

   Tags that have an empty value are not the same as omitted tags.  An
   omitted tag is treated as having the default value; a tag with an
   empty value explicitly designates the empty string as the value.

3.3.  Signing and Verification Algorithms

   DKIM supports multiple digital signature algorithms.  Two algorithms
   are defined by this specification at this time: rsa-sha1 and rsa-
   sha256.  Signers MUST implement and SHOULD sign using rsa-sha256.
   Verifiers MUST implement both rsa-sha1 and rsa-sha256.

      INFORMATIVE NOTE: Although rsa-sha256 is strongly encouraged, some
      senders might prefer to use rsa-sha1 when balancing security
      strength against performance, complexity, or other needs.  In
      general, however, rsa-sha256 should always be used whenever
      possible.

3.3.1.  The rsa-sha1 Signing Algorithm

   The rsa-sha1 Signing Algorithm computes a message hash as described
   in Section 3.7 using SHA-1 [FIPS-180-3-2008] as the hash-alg.  That
   hash is then signed by the Signer using the RSA algorithm (defined in
   Public-Key Cryptography Standards (PKCS) #1 version 1.5 [RFC3447]) as
   the crypt-alg and the Signer's private key.  The hash MUST NOT be
   truncated or converted into any form other than the native binary
   form before being signed.  The signing algorithm SHOULD use a public
   exponent of 65537.

3.3.2.  The rsa-sha256 Signing Algorithm

   The rsa-sha256 Signing Algorithm computes a message hash as described
   in Section 3.7 using SHA-256 [FIPS-180-3-2008] as the hash-alg.  That
   hash is then signed by the Signer using the RSA algorithm (defined in



Crocker, et al.              Standards Track                   [Page 13]

RFC 6376                     DKIM Signatures              September 2011


   PKCS#1 version 1.5 [RFC3447]) as the crypt-alg and the Signer's
   private key.  The hash MUST NOT be truncated or converted into any
   form other than the native binary form before being signed.  The
   signing algorithm SHOULD use a public exponent of 65537.

3.3.3.  Key Sizes

   Selecting appropriate key sizes is a trade-off between cost,
   performance, and risk.  Since short RSA keys more easily succumb to
   off-line attacks, Signers MUST use RSA keys of at least 1024 bits for
   long-lived keys.  Verifiers MUST be able to validate signatures with
   keys ranging from 512 bits to 2048 bits, and they MAY be able to
   validate signatures with larger keys.  Verifier policies may use the
   length of the signing key as one metric for determining whether a
   signature is acceptable.

   Factors that should influence the key size choice include the
   following:

   o  The practical constraint that large (e.g., 4096-bit) keys might
      not fit within a 512-byte DNS UDP response packet

   o  The security constraint that keys smaller than 1024 bits are
      subject to off-line attacks

   o  Larger keys impose higher CPU costs to verify and sign email

   o  Keys can be replaced on a regular basis; thus, their lifetime can
      be relatively short

   o  The security goals of this specification are modest compared to
      typical goals of other systems that employ digital signatures

   See [RFC3766] for further discussion on selecting key sizes.

3.3.4.  Other Algorithms

   Other algorithms MAY be defined in the future.  Verifiers MUST ignore
   any signatures using algorithms that they do not implement.

3.4.  Canonicalization

   Some mail systems modify email in transit, potentially invalidating a
   signature.  For most Signers, mild modification of email is
   immaterial to validation of the DKIM domain name's use.  For such
   Signers, a canonicalization algorithm that survives modest in-transit
   modification is preferred.




Crocker, et al.              Standards Track                   [Page 14]

RFC 6376                     DKIM Signatures              September 2011


   Other Signers demand that any modification of the email, however
   minor, result in a signature verification failure.  These Signers
   prefer a canonicalization algorithm that does not tolerate in-transit
   modification of the signed email.

   Some Signers may be willing to accept modifications to header fields
   that are within the bounds of email standards such as [RFC5322], but
   are unwilling to accept any modification to the body of messages.

   To satisfy all requirements, two canonicalization algorithms are
   defined for each of the header and the body: a "simple" algorithm
   that tolerates almost no modification and a "relaxed" algorithm that
   tolerates common modifications such as whitespace replacement and
   header field line rewrapping.  A Signer MAY specify either algorithm
   for header or body when signing an email.  If no canonicalization
   algorithm is specified by the Signer, the "simple" algorithm defaults
   for both header and body.  Verifiers MUST implement both
   canonicalization algorithms.  Note that the header and body may use
   different canonicalization algorithms.  Further canonicalization
   algorithms MAY be defined in the future; Verifiers MUST ignore any
   signatures that use unrecognized canonicalization algorithms.

   Canonicalization simply prepares the email for presentation to the
   signing or verification algorithm.  It MUST NOT change the
   transmitted data in any way.  Canonicalization of header fields and
   body are described below.

   NOTE: This section assumes that the message is already in "network
   normal" format (text is ASCII encoded, lines are separated with CRLF
   characters, etc.).  See also Section 5.3 for information about
   normalizing the message.

3.4.1.  The "simple" Header Canonicalization Algorithm

   The "simple" header canonicalization algorithm does not change header
   fields in any way.  Header fields MUST be presented to the signing or
   verification algorithm exactly as they are in the message being
   signed or verified.  In particular, header field names MUST NOT be
   case folded and whitespace MUST NOT be changed.

3.4.2.  The "relaxed" Header Canonicalization Algorithm

   The "relaxed" header canonicalization algorithm MUST apply the
   following steps in order:

   o  Convert all header field names (not the header field values) to
      lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".




Crocker, et al.              Standards Track                   [Page 15]

RFC 6376                     DKIM Signatures              September 2011


   o  Unfold all header field continuation lines as described in
      [RFC5322]; in particular, lines with terminators embedded in
      continued header field values (that is, CRLF sequences followed by
      WSP) MUST be interpreted without the CRLF.  Implementations MUST
      NOT remove the CRLF at the end of the header field value.

   o  Convert all sequences of one or more WSP characters to a single SP
      character.  WSP characters here include those before and after a
      line folding boundary.

   o  Delete all WSP characters at the end of each unfolded header field
      value.

   o  Delete any WSP characters remaining before and after the colon
      separating the header field name from the header field value.  The
      colon separator MUST be retained.

3.4.3.  The "simple" Body Canonicalization Algorithm

   The "simple" body canonicalization algorithm ignores all empty lines
   at the end of the message body.  An empty line is a line of zero
   length after removal of the line terminator.  If there is no body or
   no trailing CRLF on the message body, a CRLF is added.  It makes no
   other changes to the message body.  In more formal terms, the
   "simple" body canonicalization algorithm converts "*CRLF" at the end
   of the body to a single "CRLF".

   Note that a completely empty or missing body is canonicalized as a
   single "CRLF"; that is, the canonicalized length will be 2 octets.

   The SHA-1 value (in base64) for an empty body (canonicalized to a
   "CRLF") is:

   uoq1oCgLlTqpdDX/iUbLy7J1Wic=

   The SHA-256 value is:

   frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=

3.4.4.  The "relaxed" Body Canonicalization Algorithm

   The "relaxed" body canonicalization algorithm MUST apply the
   following steps (a) and (b) in order:

   a.  Reduce whitespace:

       *  Ignore all whitespace at the end of lines.  Implementations
          MUST NOT remove the CRLF at the end of the line.



Crocker, et al.              Standards Track                   [Page 16]

RFC 6376                     DKIM Signatures              September 2011


       *  Reduce all sequences of WSP within a line to a single SP
          character.

   b.  Ignore all empty lines at the end of the message body.  "Empty
       line" is defined in Section 3.4.3.  If the body is non-empty but
       does not end with a CRLF, a CRLF is added.  (For email, this is
       only possible when using extensions to SMTP or non-SMTP transport
       mechanisms.)

   The SHA-1 value (in base64) for an empty body (canonicalized to a
   null input) is:

   2jmj7l5rSw0yVb/vlWAYkK/YBwk=

   The SHA-256 value is:

   47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=

3.4.5.  Canonicalization Examples (INFORMATIVE)

   In the following examples, actual whitespace is used only for
   clarity.  The actual input and output text is designated using
   bracketed descriptors: "<SP>" for a space character, "<HTAB>" for a
   tab character, and "<CRLF>" for a carriage-return/line-feed sequence.
   For example, "X <SP> Y" and "X<SP>Y" represent the same three
   characters.

   Example 1: A message reading:

   A: <SP> X <CRLF>
   B <SP> : <SP> Y <HTAB><CRLF>
                   <HTAB> Z <SP><SP><CRLF>
   <CRLF>
   <SP> C <SP><CRLF>
   D <SP><HTAB><SP> E <CRLF>
   <CRLF>
   <CRLF>

   when canonicalized using relaxed canonicalization for both header and
   body results in a header reading:

   a:X <CRLF>
   b:Y <SP> Z <CRLF>

   and a body reading:

   <SP> C <CRLF>
   D <SP> E <CRLF>



Crocker, et al.              Standards Track                   [Page 17]

RFC 6376                     DKIM Signatures              September 2011


   Example 2: The same message canonicalized using simple
   canonicalization for both header and body results in a header
   reading:

   A: <SP> X <CRLF>
   B <SP> : <SP> Y <HTAB><CRLF>
          <HTAB> Z <SP><SP><CRLF>

   and a body reading:

   <SP> C <SP><CRLF>
   D <SP><HTAB><SP> E <CRLF>

   Example 3: When processed using relaxed header canonicalization and
   simple body canonicalization, the canonicalized version has a header
   of:

   a:X <CRLF>
   b:Y <SP> Z <CRLF>

   and a body reading:

   <SP> C <SP><CRLF>
   D <SP><HTAB><SP> E <CRLF>

3.5.  The DKIM-Signature Header Field

   The signature of the email is stored in the DKIM-Signature header
   field.  This header field contains all of the signature and key-
   fetching data.  The DKIM-Signature value is a tag-list as described
   in Section 3.2.

   The DKIM-Signature header field SHOULD be treated as though it were a
   trace header field as defined in Section 3.6 of [RFC5322] and hence
   SHOULD NOT be reordered and SHOULD be prepended to the message.

   The DKIM-Signature header field being created or verified is always
   included in the signature calculation, after the rest of the header
   fields being signed; however, when calculating or verifying the
   signature, the value of the "b=" tag (signature value) of that DKIM-
   Signature header field MUST be treated as though it were an empty
   string.  Unknown tags in the DKIM-Signature header field MUST be
   included in the signature calculation but MUST be otherwise ignored
   by Verifiers.  Other DKIM-Signature header fields that are included
   in the signature should be treated as normal header fields; in
   particular, the "b=" tag is not treated specially.





Crocker, et al.              Standards Track                   [Page 18]

RFC 6376                     DKIM Signatures              September 2011


   The encodings for each field type are listed below.  Tags described
   as qp-section are encoded as described in Section 6.7 of MIME Part
   One [RFC2045], with the additional conversion of semicolon characters
   to "=3B"; intuitively, this is one line of quoted-printable encoded
   text.  The dkim-quoted-printable syntax is defined in Section 2.11.

   Tags on the DKIM-Signature header field along with their type and
   requirement status are shown below.  Unrecognized tags MUST be
   ignored.

   v= Version (plain-text; REQUIRED).  This tag defines the version of
      this specification that applies to the signature record.  It MUST
      have the value "1" for implementations compliant with this version
      of DKIM.

      ABNF:

      sig-v-tag       = %x76 [FWS] "=" [FWS] 1*DIGIT

         INFORMATIVE NOTE: DKIM-Signature version numbers may increase
         arithmetically as new versions of this specification are
         released.

   a= The algorithm used to generate the signature (plain-text;
      REQUIRED).  Verifiers MUST support "rsa-sha1" and "rsa-sha256";
      Signers SHOULD sign using "rsa-sha256".  See Section 3.3 for a
      description of the algorithms.

      ABNF:

      sig-a-tag       = %x61 [FWS] "=" [FWS] sig-a-tag-alg
      sig-a-tag-alg   = sig-a-tag-k "-" sig-a-tag-h
      sig-a-tag-k     = "rsa" / x-sig-a-tag-k
      sig-a-tag-h     = "sha1" / "sha256" / x-sig-a-tag-h
      x-sig-a-tag-k   = ALPHA *(ALPHA / DIGIT)
                           ; for later extension
      x-sig-a-tag-h   = ALPHA *(ALPHA / DIGIT)
                           ; for later extension

   b= The signature data (base64; REQUIRED).  Whitespace is ignored in
      this value and MUST be ignored when reassembling the original
      signature.  In particular, the signing process can safely insert
      FWS in this value in arbitrary places to conform to line-length
      limits.  See "Signer Actions" (Section 5) for how the signature is
      computed.






Crocker, et al.              Standards Track                   [Page 19]

RFC 6376                     DKIM Signatures              September 2011


      ABNF:

      sig-b-tag       = %x62 [FWS] "=" [FWS] sig-b-tag-data
      sig-b-tag-data  = base64string

   bh=  The hash of the canonicalized body part of the message as
      limited by the "l=" tag (base64; REQUIRED).  Whitespace is ignored
      in this value and MUST be ignored when reassembling the original
      signature.  In particular, the signing process can safely insert
      FWS in this value in arbitrary places to conform to line-length
      limits.  See Section 3.7 for how the body hash is computed.

      ABNF:

      sig-bh-tag      = %x62 %x68 [FWS] "=" [FWS] sig-bh-tag-data
      sig-bh-tag-data = base64string

   c= Message canonicalization (plain-text; OPTIONAL, default is
      "simple/simple").  This tag informs the Verifier of the type of
      canonicalization used to prepare the message for signing.  It
      consists of two names separated by a "slash" (%d47) character,
      corresponding to the header and body canonicalization algorithms,
      respectively.  These algorithms are described in Section 3.4.  If
      only one algorithm is named, that algorithm is used for the header
      and "simple" is used for the body.  For example, "c=relaxed" is
      treated the same as "c=relaxed/simple".

      ABNF:

      sig-c-tag       = %x63 [FWS] "=" [FWS] sig-c-tag-alg
                        ["/" sig-c-tag-alg]
      sig-c-tag-alg   = "simple" / "relaxed" / x-sig-c-tag-alg
      x-sig-c-tag-alg = hyphenated-word    ; for later extension

   d= The SDID claiming responsibility for an introduction of a message
      into the mail stream (plain-text; REQUIRED).  Hence, the SDID
      value is used to form the query for the public key.  The SDID MUST
      correspond to a valid DNS name under which the DKIM key record is
      published.  The conventions and semantics used by a Signer to
      create and use a specific SDID are outside the scope of this
      specification, as is any use of those conventions and semantics.
      When presented with a signature that does not meet these
      requirements, Verifiers MUST consider the signature invalid.

      Internationalized domain names MUST be encoded as A-labels, as
      described in Section 2.3 of [RFC5890].





Crocker, et al.              Standards Track                   [Page 20]

RFC 6376                     DKIM Signatures              September 2011


      ABNF:

      sig-d-tag       = %x64 [FWS] "=" [FWS] domain-name
      domain-name     = sub-domain 1*("." sub-domain)
                        ; from [RFC5321] Domain,
                        ; excluding address-literal

   h= Signed header fields (plain-text, but see description; REQUIRED).
      A colon-separated list of header field names that identify the
      header fields presented to the signing algorithm.  The field MUST
      contain the complete list of header fields in the order presented
      to the signing algorithm.  The field MAY contain names of header
      fields that do not exist when signed; nonexistent header fields do
      not contribute to the signature computation (that is, they are
      treated as the null input, including the header field name, the
      separating colon, the header field value, and any CRLF
      terminator).  The field MAY contain multiple instances of a header
      field name, meaning multiple occurrences of the corresponding
      header field are included in the header hash.  The field MUST NOT
      include the DKIM-Signature header field that is being created or
      verified but may include others.  Folding whitespace (FWS) MAY be
      included on either side of the colon separator.  Header field
      names MUST be compared against actual header field names in a
      case-insensitive manner.  This list MUST NOT be empty.  See
      Section 5.4 for a discussion of choosing header fields to sign and
      Section 5.4.2 for requirements when signing multiple instances of
      a single field.

      ABNF:

      sig-h-tag       = %x68 [FWS] "=" [FWS] hdr-name
                         *( [FWS] ":" [FWS] hdr-name )

         INFORMATIVE EXPLANATION: By "signing" header fields that do not
         actually exist, a Signer can allow a Verifier to detect
         insertion of those header fields after signing.  However, since
         a Signer cannot possibly know what header fields might be
         defined in the future, this mechanism cannot be used to prevent
         the addition of any possible unknown header fields.

         INFORMATIVE NOTE: "Signing" fields that are not present at the
         time of signing not only prevents fields and values from being
         added but also prevents adding fields with no values.

   i= The Agent or User Identifier (AUID) on behalf of which the SDID is
      taking responsibility (dkim-quoted-printable; OPTIONAL, default is
      an empty local-part followed by an "@" followed by the domain from
      the "d=" tag).



Crocker, et al.              Standards Track                   [Page 21]

RFC 6376                     DKIM Signatures              September 2011


      The syntax is a standard email address where the local-part MAY be
      omitted.  The domain part of the address MUST be the same as, or a
      subdomain of, the value of the "d=" tag.

      Internationalized domain names MUST be encoded as A-labels, as
      described in Section 2.3 of [RFC5890].

      ABNF:

      sig-i-tag       = %x69 [FWS] "=" [FWS] [ Local-part ]
                                 "@" domain-name

      The AUID is specified as having the same syntax as an email
      address but it need not have the same semantics.  Notably, the
      domain name need not be registered in the DNS -- so it might not
      resolve in a query -- and the local-part MAY be drawn from a
      namespace unrelated to any mailbox.  The details of the structure
      and semantics for the namespace are determined by the Signer.  Any
      knowledge or use of those details by Verifiers or Assessors is
      outside the scope of this specification.  The Signer MAY choose to
      use the same namespace for its AUIDs as its users' email addresses
      or MAY choose other means of representing its users.  However, the
      Signer SHOULD use the same AUID for each message intended to be
      evaluated as being within the same sphere of responsibility, if it
      wishes to offer receivers the option of using the AUID as a stable
      identifier that is finer grained than the SDID.

         INFORMATIVE NOTE: The local-part of the "i=" tag is optional
         because in some cases a Signer may not be able to establish a
         verified individual identity.  In such cases, the Signer might
         wish to assert that although it is willing to go as far as
         signing for the domain, it is unable or unwilling to commit to
         an individual user name within the domain.  It can do so by
         including the domain part but not the local-part of the
         identity.

         INFORMATIVE DISCUSSION: This specification does not require the
         value of the "i=" tag to match the identity in any message
         header fields.  This is considered to be a Verifier policy
         issue.  Constraints between the value of the "i=" tag and other
         identities in other header fields seek to apply basic
         authentication into the semantics of trust associated with a
         role such as content author.  Trust is a broad and complex
         topic, and trust mechanisms are subject to highly creative
         attacks.  The real-world efficacy of any but the most basic
         bindings between the "i=" value and other identities is not
         well established, nor is its vulnerability to subversion by an
         attacker.  Hence, reliance on the use of these options should



Crocker, et al.              Standards Track                   [Page 22]

RFC 6376                     DKIM Signatures              September 2011


         be strictly limited.  In particular, it is not at all clear to
         what extent a typical end-user recipient can rely on any
         assurances that might be made by successful use of the "i="
         options.

   l= Body length count (plain-text unsigned decimal integer; OPTIONAL,
      default is entire body).  This tag informs the Verifier of the
      number of octets in the body of the email after canonicalization
      included in the cryptographic hash, starting from 0 immediately
      following the CRLF preceding the body.  This value MUST NOT be
      larger than the actual number of octets in the canonicalized
      message body.  See further discussion in Section 8.2.

         INFORMATIVE NOTE: The value of the "l=" tag is constrained to
         76 decimal digits.  This constraint is not intended to predict
         the size of future messages or to require implementations to
         use an integer representation large enough to represent the
         maximum possible value but is intended to remind the
         implementer to check the length of this and all other tags
         during verification and to test for integer overflow when
         decoding the value.  Implementers may need to limit the actual
         value expressed to a value smaller than 10^76, e.g., to allow a
         message to fit within the available storage space.

      ABNF:

      sig-l-tag    = %x6c [FWS] "=" [FWS]
                     1*76DIGIT

   q= A colon-separated list of query methods used to retrieve the
      public key (plain-text; OPTIONAL, default is "dns/txt").  Each
      query method is of the form "type[/options]", where the syntax and
      semantics of the options depend on the type and specified options.
      If there are multiple query mechanisms listed, the choice of query
      mechanism MUST NOT change the interpretation of the signature.
      Implementations MUST use the recognized query mechanisms in the
      order presented.  Unrecognized query mechanisms MUST be ignored.

      Currently, the only valid value is "dns/txt", which defines the
      DNS TXT resource record (RR) lookup algorithm described elsewhere
      in this document.  The only option defined for the "dns" query
      type is "txt", which MUST be included.  Verifiers and Signers MUST
      support "dns/txt".

      ABNF:

      sig-q-tag        = %x71 [FWS] "=" [FWS] sig-q-tag-method
                            *([FWS] ":" [FWS] sig-q-tag-method)



Crocker, et al.              Standards Track                   [Page 23]

RFC 6376                     DKIM Signatures              September 2011


      sig-q-tag-method = "dns/txt" / x-sig-q-tag-type
                         ["/" x-sig-q-tag-args]
      x-sig-q-tag-type = hyphenated-word  ; for future extension
      x-sig-q-tag-args = qp-hdr-value

   s= The selector subdividing the namespace for the "d=" (domain) tag
      (plain-text; REQUIRED).

      Internationalized selector names MUST be encoded as A-labels, as
      described in Section 2.3 of [RFC5890].

      ABNF:

      sig-s-tag    = %x73 [FWS] "=" [FWS] selector

   t= Signature Timestamp (plain-text unsigned decimal integer;
      RECOMMENDED, default is an unknown creation time).  The time that
      this signature was created.  The format is the number of seconds
      since 00:00:00 on January 1, 1970 in the UTC time zone.  The value
      is expressed as an unsigned integer in decimal ASCII.  This value
      is not constrained to fit into a 31- or 32-bit integer.
      Implementations SHOULD be prepared to handle values up to at least
      10^12 (until approximately AD 200,000; this fits into 40 bits).
      To avoid denial-of-service attacks, implementations MAY consider
      any value longer than 12 digits to be infinite.  Leap seconds are
      not counted.  Implementations MAY ignore signatures that have a
      timestamp in the future.

      ABNF:

      sig-t-tag    = %x74 [FWS] "=" [FWS] 1*12DIGIT

   x= Signature Expiration (plain-text unsigned decimal integer;
      RECOMMENDED, default is no expiration).  The format is the same as
      in the "t=" tag, represented as an absolute date, not as a time
      delta from the signing timestamp.  The value is expressed as an
      unsigned integer in decimal ASCII, with the same constraints on
      the value in the "t=" tag.  Signatures MAY be considered invalid
      if the verification time at the Verifier is past the expiration
      date.  The verification time should be the time that the message
      was first received at the administrative domain of the Verifier if
      that time is reliably available; otherwise, the current time
      should be used.  The value of the "x=" tag MUST be greater than
      the value of the "t=" tag if both are present.

         INFORMATIVE NOTE: The "x=" tag is not intended as an anti-
         replay defense.




Crocker, et al.              Standards Track                   [Page 24]

RFC 6376                     DKIM Signatures              September 2011


         INFORMATIVE NOTE: Due to clock drift, the receiver's notion of
         when to consider the signature expired may not exactly match
         what the sender is expecting.  Receivers MAY add a 'fudge
         factor' to allow for such possible drift.

      ABNF:

      sig-x-tag    = %x78 [FWS] "=" [FWS]
                                    1*12DIGIT

   z= Copied header fields (dkim-quoted-printable, but see description;
      OPTIONAL, default is null).  A vertical-bar-separated list of
      selected header fields present when the message was signed,
      including both the field name and value.  It is not required to
      include all header fields present at the time of signing.  This
      field need not contain the same header fields listed in the "h="
      tag.  The header field text itself must encode the vertical bar
      ("|", %x7C) character (i.e., vertical bars in the "z=" text are
      meta-characters, and any actual vertical bar characters in a
      copied header field must be encoded).  Note that all whitespace
      must be encoded, including whitespace between the colon and the
      header field value.  After encoding, FWS MAY be added at arbitrary
      locations in order to avoid excessively long lines; such
      whitespace is NOT part of the value of the header field and MUST
      be removed before decoding.

      The header fields referenced by the "h=" tag refer to the fields
      in the [RFC5322] header of the message, not to any copied fields
      in the "z=" tag.  Copied header field values are for diagnostic
      use.

      ABNF:

      sig-z-tag      = %x7A [FWS] "=" [FWS] sig-z-tag-copy
                       *( "|" [FWS] sig-z-tag-copy )
      sig-z-tag-copy = hdr-name [FWS] ":" qp-hdr-value

         INFORMATIVE EXAMPLE of a signature header field spread across
         multiple continuation lines:

   DKIM-Signature: v=1; a=rsa-sha256; d=example.net; s=brisbane;
      c=simple; q=dns/txt; i=@eng.example.net;
      t=1117574938; x=1118006938;
      h=from:to:subject:date;
      z=From:foo@eng.example.net|To:joe@example.com|
       Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700;
      bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
      b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR



Crocker, et al.              Standards Track                   [Page 25]

RFC 6376                     DKIM Signatures              September 2011


3.6.  Key Management and Representation

   Signature applications require some level of assurance that the
   verification public key is associated with the claimed Signer.  Many
   applications achieve this by using public-key certificates issued by
   a trusted third party.  However, DKIM can achieve a sufficient level
   of security, with significantly enhanced scalability, by simply
   having the Verifier query the purported Signer's DNS entry (or some
   security-equivalent) in order to retrieve the public key.

   DKIM keys can potentially be stored in multiple types of key servers
   and in multiple formats.  The storage and format of keys are
   irrelevant to the remainder of the DKIM algorithm.

   Parameters to the key lookup algorithm are the type of the lookup
   (the "q=" tag), the domain of the Signer (the "d=" tag of the DKIM-
   Signature header field), and the selector (the "s=" tag).

   public_key = dkim_find_key(q_val, d_val, s_val)

   This document defines a single binding, using DNS TXT RRs to
   distribute the keys.  Other bindings may be defined in the future.

3.6.1.  Textual Representation

   It is expected that many key servers will choose to present the keys
   in an otherwise unstructured text format (for example, an XML form
   would not be considered to be unstructured text for this purpose).
   The following definition MUST be used for any DKIM key represented in
   an otherwise unstructured textual form.

   The overall syntax is a tag-list as described in Section 3.2.  The
   current valid tags are described below.  Other tags MAY be present
   and MUST be ignored by any implementation that does not understand
   them.

   v= Version of the DKIM key record (plain-text; RECOMMENDED, default
      is "DKIM1").  If specified, this tag MUST be set to "DKIM1"
      (without the quotes).  This tag MUST be the first tag in the
      record.  Records beginning with a "v=" tag with any other value
      MUST be discarded.  Note that Verifiers must do a string
      comparison on this value; for example, "DKIM1" is not the same as
      "DKIM1.0".

      ABNF:

      key-v-tag    = %x76 [FWS] "=" [FWS] %x44.4B.49.4D.31




Crocker, et al.              Standards Track                   [Page 26]

RFC 6376                     DKIM Signatures              September 2011


   h= Acceptable hash algorithms (plain-text; OPTIONAL, defaults to
      allowing all algorithms).  A colon-separated list of hash
      algorithms that might be used.  Unrecognized algorithms MUST be
      ignored.  Refer to Section 3.3 for a discussion of the hash
      algorithms implemented by Signers and Verifiers.  The set of
      algorithms listed in this tag in each record is an operational
      choice made by the Signer.

      ABNF:

      key-h-tag       = %x68 [FWS] "=" [FWS] key-h-tag-alg
                        *( [FWS] ":" [FWS] key-h-tag-alg )
      key-h-tag-alg   = "sha1" / "sha256" / x-key-h-tag-alg
      x-key-h-tag-alg = hyphenated-word   ; for future extension

   k= Key type (plain-text; OPTIONAL, default is "rsa").  Signers and
      Verifiers MUST support the "rsa" key type.  The "rsa" key type
      indicates that an ASN.1 DER-encoded [ITU-X660-1997] RSAPublicKey
      (see [RFC3447], Sections 3.1 and A.1.1) is being used in the "p="
      tag.  (Note: the "p=" tag further encodes the value using the
      base64 algorithm.)  Unrecognized key types MUST be ignored.

      ABNF:

      key-k-tag        = %x76 [FWS] "=" [FWS] key-k-tag-type
      key-k-tag-type   = "rsa" / x-key-k-tag-type
      x-key-k-tag-type = hyphenated-word   ; for future extension

   n= Notes that might be of interest to a human (qp-section; OPTIONAL,
      default is empty).  No interpretation is made by any program.
      This tag should be used sparingly in any key server mechanism that
      has space limitations (notably DNS).  This is intended for use by
      administrators, not end users.

      ABNF:

      key-n-tag    = %x6e [FWS] "=" [FWS] qp-section

   p= Public-key data (base64; REQUIRED).  An empty value means that
      this public key has been revoked.  The syntax and semantics of
      this tag value before being encoded in base64 are defined by the
      "k=" tag.

         INFORMATIVE RATIONALE: If a private key has been compromised or
         otherwise disabled (e.g., an outsourcing contract has been
         terminated), a Signer might want to explicitly state that it
         knows about the selector, but all messages using that selector




Crocker, et al.              Standards Track                   [Page 27]

RFC 6376                     DKIM Signatures              September 2011


         should fail verification.  Verifiers SHOULD return an error
         code for any DKIM-Signature header field with a selector
         referencing a revoked key.  (See Section 6.1.2 for details.)

      ABNF:

      key-p-tag    = %x70 [FWS] "=" [ [FWS] base64string]

         INFORMATIVE NOTE: A base64string is permitted to include
         whitespace (FWS) at arbitrary places; however, any CRLFs must
         be followed by at least one WSP character.  Implementers and
         administrators are cautioned to ensure that selector TXT RRs
         conform to this specification.

   s= Service Type (plain-text; OPTIONAL; default is "*").  A colon-
      separated list of service types to which this record applies.
      Verifiers for a given service type MUST ignore this record if the
      appropriate type is not listed.  Unrecognized service types MUST
      be ignored.  Currently defined service types are as follows:

      *  matches all service types

      email   electronic mail (not necessarily limited to SMTP)

      This tag is intended to constrain the use of keys for other
      purposes, should use of DKIM be defined by other services in the
      future.

      ABNF:

      key-s-tag        = %x73 [FWS] "=" [FWS] key-s-tag-type
                         *( [FWS] ":" [FWS] key-s-tag-type )
      key-s-tag-type   = "email" / "*" / x-key-s-tag-type
      x-key-s-tag-type = hyphenated-word   ; for future extension

   t= Flags, represented as a colon-separated list of names (plain-
      text; OPTIONAL, default is no flags set).  Unrecognized flags MUST
      be ignored.  The defined flags are as follows:

      y  This domain is testing DKIM.  Verifiers MUST NOT treat messages
         from Signers in testing mode differently from unsigned email,
         even should the signature fail to verify.  Verifiers MAY wish
         to track testing mode results to assist the Signer.








Crocker, et al.              Standards Track                   [Page 28]

RFC 6376                     DKIM Signatures              September 2011


      s  Any DKIM-Signature header fields using the "i=" tag MUST have
         the same domain value on the right-hand side of the "@" in the
         "i=" tag and the value of the "d=" tag.  That is, the "i="
         domain MUST NOT be a subdomain of "d=".  Use of this flag is
         RECOMMENDED unless subdomaining is required.

      ABNF:

      key-t-tag        = %x74 [FWS] "=" [FWS] key-t-tag-flag
                         *( [FWS] ":" [FWS] key-t-tag-flag )
      key-t-tag-flag   = "y" / "s" / x-key-t-tag-flag
      x-key-t-tag-flag = hyphenated-word   ; for future extension

3.6.2.  DNS Binding

   A binding using DNS TXT RRs as a key service is hereby defined.  All
   implementations MUST support this binding.

3.6.2.1.  Namespace

   All DKIM keys are stored in a subdomain named "_domainkey".  Given a
   DKIM-Signature field with a "d=" tag of "example.com" and an "s=" tag
   of "foo.bar", the DNS query will be for
   "foo.bar._domainkey.example.com".

3.6.2.2.  Resource Record Types for Key Storage

   The DNS Resource Record type used is specified by an option to the
   query-type ("q=") tag.  The only option defined in this base
   specification is "txt", indicating the use of a TXT RR.  A later
   extension of this standard may define another RR type.

   Strings in a TXT RR MUST be concatenated together before use with no
   intervening whitespace.  TXT RRs MUST be unique for a particular
   selector name; that is, if there are multiple records in an RRset,
   the results are undefined.

   TXT RRs are encoded as described in Section 3.6.1.

3.7.  Computing the Message Hashes

   Both signing and verifying message signatures start with a step of
   computing two cryptographic hashes over the message.  Signers will
   choose the parameters of the signature as described in "Signer
   Actions" (Section 5); Verifiers will use the parameters specified in
   the DKIM-Signature header field being verified.  In the following
   discussion, the names of the tags in the DKIM-Signature header field
   that either exists (when verifying) or will be created (when signing)



Crocker, et al.              Standards Track                   [Page 29]

RFC 6376                     DKIM Signatures              September 2011


   are used.  Note that canonicalization (Section 3.4) is only used to
   prepare the email for signing or verifying; it does not affect the
   transmitted email in any way.

   The Signer/Verifier MUST compute two hashes: one over the body of the
   message and one over the selected header fields of the message.

   Signers MUST compute them in the order shown.  Verifiers MAY compute
   them in any order convenient to the Verifier, provided that the
   result is semantically identical to the semantics that would be the
   case had they been computed in this order.

   In hash step 1, the Signer/Verifier MUST hash the message body,
   canonicalized using the body canonicalization algorithm specified in
   the "c=" tag and then truncated to the length specified in the "l="
   tag.  That hash value is then converted to base64 form and inserted
   into (Signers) or compared to (Verifiers) the "bh=" tag of the DKIM-
   Signature header field.

   In hash step 2, the Signer/Verifier MUST pass the following to the
   hash algorithm in the indicated order.

   1.  The header fields specified by the "h=" tag, in the order
       specified in that tag, and canonicalized using the header
       canonicalization algorithm specified in the "c=" tag.  Each
       header field MUST be terminated with a single CRLF.

   2.  The DKIM-Signature header field that exists (verifying) or will
       be inserted (signing) in the message, with the value of the "b="
       tag (including all surrounding whitespace) deleted (i.e., treated
       as the empty string), canonicalized using the header
       canonicalization algorithm specified in the "c=" tag, and without
       a trailing CRLF.

   All tags and their values in the DKIM-Signature header field are
   included in the cryptographic hash with the sole exception of the
   value portion of the "b=" (signature) tag, which MUST be treated as
   the null string.  All tags MUST be included even if they might not be
   understood by the Verifier.  The header field MUST be presented to
   the hash algorithm after the body of the message rather than with the
   rest of the header fields and MUST be canonicalized as specified in
   the "c=" (canonicalization) tag.  The DKIM-Signature header field
   MUST NOT be included in its own "h=" tag, although other DKIM-
   Signature header fields MAY be signed (see Section 4).

   When calculating the hash on messages that will be transmitted using
   base64 or quoted-printable encoding, Signers MUST compute the hash
   after the encoding.  Likewise, the Verifier MUST incorporate the



Crocker, et al.              Standards Track                   [Page 30]

RFC 6376                     DKIM Signatures              September 2011


   values into the hash before decoding the base64 or quoted-printable
   text.  However, the hash MUST be computed before transport-level
   encodings such as SMTP "dot-stuffing" (the modification of lines
   beginning with a "." to avoid confusion with the SMTP end-of-message
   marker, as specified in [RFC5321]).

   With the exception of the canonicalization procedure described in
   Section 3.4, the DKIM signing process treats the body of messages as
   simply a string of octets.  DKIM messages MAY be either in plain-text
   or in MIME format; no special treatment is afforded to MIME content.
   Message attachments in MIME format MUST be included in the content
   that is signed.

   More formally, pseudo-code for the signature algorithm is:

   body-hash    =  hash-alg (canon-body, l-param)
   data-hash    =  hash-alg (h-headers, D-SIG, body-hash)
   signature    =  sig-alg (d-domain, selector, data-hash)

   where:

   body-hash:  is the output from hashing the body, using hash-alg.

   hash-alg:   is the hashing algorithm specified in the "a" parameter.

   canon-body: is a canonicalized representation of the body, produced
               using the body algorithm specified in the "c" parameter,
               as defined in Section 3.4 and excluding the
               DKIM-Signature field.

   l-param:    is the length-of-body value of the "l" parameter.

   data-hash:  is the output from using the hash-alg algorithm, to hash
               the header including the DKIM-Signature header, and the
               body hash.

   h-headers:  is the list of headers to be signed, as specified in the
               "h" parameter.

   D-SIG:      is the canonicalized DKIM-Signature field itself without
               the signature value portion of the parameter, that is, an
               empty parameter value.

   signature:  is the signature value produced by the signing algorithm.

   sig-alg:    is the signature algorithm specified by the "a"
               parameter.




Crocker, et al.              Standards Track                   [Page 31]

RFC 6376                     DKIM Signatures              September 2011


   d-domain:   is the domain name specified in the "d" parameter.

   selector:   is the selector value specified in the "s" parameter.

      NOTE: Many digital signature APIs provide both hashing and
      application of the RSA private key using a single "sign()"
      primitive.  When using such an API, the last two steps in the
      algorithm would probably be combined into a single call that would
      perform both the "a-hash-alg" and the "sig-alg".

3.8.  Input Requirements

   A message that is not compliant with [RFC5322], [RFC2045], and
   [RFC2047] can be subject to attempts by intermediaries to correct or
   interpret such content.  See Section 8 of [RFC4409] for examples of
   changes that are commonly made.  Such "corrections" may invalidate
   DKIM signatures or have other undesirable effects, including some
   that involve changes to the way a message is presented to an end
   user.

   Accordingly, DKIM's design is predicated on valid input.  Therefore,
   Signers and Verifiers SHOULD take reasonable steps to ensure that the
   messages they are processing are valid according to [RFC5322],
   [RFC2045], and any other relevant message format standards.

   See Section 8.15 for additional discussion.

3.9.  Output Requirements

   The evaluation of each signature ends in one of three states, which
   this document refers to as follows:

   SUCCESS:  a successful verification

   PERMFAIL:  a permanent, non-recoverable error such as a signature
      verification failure

   TEMPFAIL:  a temporary, recoverable error such as a DNS query timeout

   For each signature that verifies successfully or produces a TEMPFAIL
   result, output of the DKIM algorithm MUST include the set of:

   o  The domain name, taken from the "d=" signature tag; and

   o  The result of the verification attempt for that signature.






Crocker, et al.              Standards Track                   [Page 32]

RFC 6376                     DKIM Signatures              September 2011


   The output MAY include other signature properties or result meta-
   data, including PERMFAILed or otherwise ignored signatures, for use
   by modules that consume those results.

   See Section 6.1 for discussion of signature validation result codes.

3.10.  Signing by Parent Domains

   In some circumstances, it is desirable for a domain to apply a
   signature on behalf of any of its subdomains without the need to
   maintain separate selectors (key records) in each subdomain.  By
   default, private keys corresponding to key records can be used to
   sign messages for any subdomain of the domain in which they reside;
   for example, a key record for the domain example.com can be used to
   verify messages where the AUID ("i=" tag of the signature) is
   sub.example.com, or even sub1.sub2.example.com.  In order to limit
   the capability of such keys when this is not intended, the "s" flag
   MAY be set in the "t=" tag of the key record, to constrain the
   validity of the domain of the AUID.  If the referenced key record
   contains the "s" flag as part of the "t=" tag, the domain of the AUID
   ("i=" flag) MUST be the same as that of the SDID (d=) domain.  If
   this flag is absent, the domain of the AUID MUST be the same as, or a
   subdomain of, the SDID.

3.11.  Relationship between SDID and AUID

   DKIM's primary task is to communicate from the Signer to a recipient-
   side Identity Assessor a single Signing Domain Identifier (SDID) that
   refers to a responsible identity.  DKIM MAY optionally provide a
   single responsible Agent or User Identifier (AUID).

   Hence, DKIM's mandatory output to a receive-side Identity Assessor is
   a single domain name.  Within the scope of its use as DKIM output,
   the name has only basic domain name semantics; any possible owner-
   specific semantics are outside the scope of DKIM.  That is, within
   its role as a DKIM identifier, additional semantics cannot be assumed
   by an Identity Assessor.

   Upon successfully verifying the signature, a receive-side DKIM
   Verifier MUST communicate the Signing Domain Identifier (d=) to a
   consuming Identity Assessor module and MAY communicate the Agent or
   User Identifier (i=) if present.

   To the extent that a receiver attempts to intuit any structured
   semantics for either of the identifiers, this is a heuristic function
   that is outside the scope of DKIM's specification and semantics.





Crocker, et al.              Standards Track                   [Page 33]

RFC 6376                     DKIM Signatures              September 2011


   Hence, it is relegated to a higher-level service, such as a delivery-
   handling filter that integrates a variety of inputs and performs
   heuristic analysis of them.

      INFORMATIVE DISCUSSION: This document does not require the value
      of the SDID or AUID to match an identifier in any other message
      header field.  This requirement is, instead, an Assessor policy
      issue.  The purpose of such a linkage would be to authenticate the
      value in that other header field.  This, in turn, is the basis for
      applying a trust assessment based on the identifier value.  Trust
      is a broad and complex topic, and trust mechanisms are subject to
      highly creative attacks.  The real-world efficacy of any but the
      most basic bindings between the SDID or AUID and other identities
      is not well established, nor is its vulnerability to subversion by
      an attacker.  Hence, reliance on the use of such bindings should
      be strictly limited.  In particular, it is not at all clear to
      what extent a typical end-user recipient can rely on any
      assurances that might be made by successful use of the SDID or
      AUID.

4.  Semantics of Multiple Signatures

4.1.  Example Scenarios

   There are many reasons why a message might have multiple signatures.
   For example, suppose SHA-256 is in the future found to be
   insufficiently strong, and DKIM usage transitions to SHA-1024.  A
   Signer might immediately sign using the newer algorithm but also
   continue to sign using the older algorithm for interoperability with
   Verifiers that had not yet upgraded.  The Signer would do this by
   adding two DKIM-Signature header fields, one using each algorithm.
   Older Verifiers that did not recognize SHA-1024 as an acceptable
   algorithm would skip that signature and use the older algorithm;
   newer Verifiers could use either signature at their option and, all
   other things being equal, might not even attempt to verify the other
   signature.

   Similarly, a Signer might sign a message including all header fields
   and no "l=" tag (to satisfy strict Verifiers) and a second time with
   a limited set of header fields and an "l=" tag (in anticipation of
   possible message modifications en route to other Verifiers).
   Verifiers could then choose which signature they prefer.

   Of course, a message might also have multiple signatures because it
   passed through multiple Signers.  A common case is expected to be
   that of a signed message that passes through a mailing list that also





Crocker, et al.              Standards Track                   [Page 34]

RFC 6376                     DKIM Signatures              September 2011


   signs all messages.  Assuming both of those signatures verify, a
   recipient might choose to accept the message if either of those
   signatures were known to come from trusted sources.

   In particular, recipients might choose to whitelist mailing lists to
   which they have subscribed and that have acceptable anti-abuse
   policies so as to accept messages sent to that list even from unknown
   authors.  They might also subscribe to less trusted mailing lists
   (e.g., those without anti-abuse protection) and be willing to accept
   all messages from specific authors but insist on doing additional
   abuse scanning for other messages.

   Another related example of multiple Signers might be forwarding
   services, such as those commonly associated with academic alumni
   sites.  For example, a recipient might have an address at
   members.example.org, a site that has anti-abuse protection that is
   somewhat less effective than the recipient would prefer.  Such a
   recipient might have specific authors whose messages would be trusted
   absolutely, but messages from unknown authors that had passed the
   forwarder's scrutiny would have only medium trust.

4.2.  Interpretation

   A Signer that is adding a signature to a message merely creates a new
   DKIM-Signature header, using the usual semantics of the "h=" option.
   A Signer MAY sign previously existing DKIM-Signature header fields
   using the method described in Section 5.4 to sign trace header
   fields.

   Note that Signers should be cognizant that signing DKIM-Signature
   header fields may result in signature failures with intermediaries
   that do not recognize that DKIM-Signature header fields are trace
   header fields and unwittingly reorder them, thus breaking such
   signatures.  For this reason, signing existing DKIM-Signature header
   fields is unadvised, albeit legal.

      INFORMATIVE NOTE: If a header field with multiple instances is
      signed, those header fields are always signed from the bottom up.
      Thus, it is not possible to sign only specific DKIM-Signature
      header fields.  For example, if the message being signed already
      contains three DKIM-Signature header fields A, B, and C, it is
      possible to sign all of them, B and C only, or C only, but not A
      only, B only, A and B only, or A and C only.

   A Signer MAY add more than one DKIM-Signature header field using
   different parameters.  For example, during a transition period, a
   Signer might want to produce signatures using two different hash
   algorithms.



Crocker, et al.              Standards Track                   [Page 35]

RFC 6376                     DKIM Signatures              September 2011


   Signers SHOULD NOT remove any DKIM-Signature header fields from
   messages they are signing, even if they know that the signatures
   cannot be verified.

   When evaluating a message with multiple signatures, a Verifier SHOULD
   evaluate signatures independently and on their own merits.  For
   example, a Verifier that by policy chooses not to accept signatures
   with deprecated cryptographic algorithms would consider such
   signatures invalid.  Verifiers MAY process signatures in any order of
   their choice; for example, some Verifiers might choose to process
   signatures corresponding to the From field in the message header
   before other signatures.  See Section 6.1 for more information about
   signature choices.

      INFORMATIVE IMPLEMENTATION NOTE: Verifier attempts to correlate
      valid signatures with invalid signatures in an attempt to guess
      why a signature failed are ill-advised.  In particular, there is
      no general way that a Verifier can determine that an invalid
      signature was ever valid.

   Verifiers SHOULD continue to check signatures until a signature
   successfully verifies to the satisfaction of the Verifier.  To limit
   potential denial-of-service attacks, Verifiers MAY limit the total
   number of signatures they will attempt to verify.

   If a Verifier module reports signatures whose evaluations produced
   PERMFAIL results, Identity Assessors SHOULD ignore those signatures
   (see Section 6.1), acting as though they were not present in the
   message.

5.  Signer Actions

   The following steps are performed in order by Signers.

5.1.  Determine Whether the Email Should Be Signed and by Whom

   A Signer can obviously only sign email for domains for which it has a
   private key and the necessary knowledge of the corresponding public
   key and selector information.  However, there are a number of other
   reasons beyond the lack of a private key why a Signer could choose
   not to sign an email.

      INFORMATIVE NOTE: A Signer can be implemented as part of any
      portion of the mail system as deemed appropriate, including an
      MUA, a SUBMISSION server, or an MTA.  Wherever implemented,
      Signers should beware of signing (and thereby asserting
      responsibility for) messages that may be problematic.  In
      particular, within a trusted enclave, the signing domain might be



Crocker, et al.              Standards Track                   [Page 36]

RFC 6376                     DKIM Signatures              September 2011


      derived from the header according to local policy; SUBMISSION
      servers might only sign messages from users that are properly
      authenticated and authorized.

      INFORMATIVE IMPLEMENTER ADVICE: SUBMISSION servers should not sign
      Received header fields if the outgoing gateway MTA obfuscates
      Received header fields, for example, to hide the details of
      internal topology.

   If an email cannot be signed for some reason, it is a local policy
   decision as to what to do with that email.

5.2.  Select a Private Key and Corresponding Selector Information

   This specification does not define the basis by which a Signer should
   choose which private key and selector information to use.  Currently,
   all selectors are equal as far as this specification is concerned, so
   the decision should largely be a matter of administrative
   convenience.  Distribution and management of private keys is also
   outside the scope of this document.

      INFORMATIVE OPERATIONS ADVICE: A Signer should not sign with a
      private key when the selector containing the corresponding public
      key is expected to be revoked or removed before the Verifier has
      an opportunity to validate the signature.  The Signer should
      anticipate that Verifiers can choose to defer validation, perhaps
      until the message is actually read by the final recipient.  In
      particular, when rotating to a new key pair, signing should
      immediately commence with the new private key, and the old public
      key should be retained for a reasonable validation interval before
      being removed from the key server.

5.3.  Normalize the Message to Prevent Transport Conversions

   Some messages, particularly those using 8-bit characters, are subject
   to modification during transit, notably conversion to 7-bit form.
   Such conversions will break DKIM signatures.  In order to minimize
   the chances of such breakage, Signers SHOULD convert the message to a
   suitable MIME content-transfer encoding such as quoted-printable or
   base64 as described in [RFC2045] before signing.  Such conversion is
   outside the scope of DKIM; the actual message SHOULD be converted to
   7-bit MIME by an MUA or MSA prior to presentation to the DKIM
   algorithm.

   If the message is submitted to the Signer with any local encoding
   that will be modified before transmission, that modification to
   canonical [RFC5322] form MUST be done before signing.  In particular,
   bare CR or LF characters (used by some systems as a local line



Crocker, et al.              Standards Track                   [Page 37]

RFC 6376                     DKIM Signatures              September 2011


   separator convention) MUST be converted to the SMTP-standard CRLF
   sequence before the message is signed.  Any conversion of this sort
   SHOULD be applied to the message actually sent to the recipient(s),
   not just to the version presented to the signing algorithm.

   More generally, the Signer MUST sign the message as it is expected to
   be received by the Verifier rather than in some local or internal
   form.

5.3.1.  Body Length Limits

   A body length count MAY be specified to limit the signature
   calculation to an initial prefix of the body text, measured in
   octets.  If the body length count is not specified, the entire
   message body is signed.

      INFORMATIVE RATIONALE: This capability is provided because it is
      very common for mailing lists to add trailers to messages (e.g.,
      instructions on how to get off the list).  Until those messages
      are also signed, the body length count is a useful tool for the
      Verifier since it can, as a matter of policy, accept messages
      having valid signatures with extraneous data.

   The length actually hashed should be inserted in the "l=" tag of the
   DKIM-Signature header field.  (See Section 3.5.)

   The body length count allows the Signer of a message to permit data
   to be appended to the end of the body of a signed message.  The body
   length count MUST be calculated following the canonicalization
   algorithm; for example, any whitespace ignored by a canonicalization
   algorithm is not included as part of the body length count.

   A body length count of zero means that the body is completely
   unsigned.

   Signers wishing to ensure that no modification of any sort can occur
   should specify the "simple" canonicalization algorithm for both
   header and body and omit the body length count.

   See Section 8.2 for further discussion.

5.4.  Determine the Header Fields to Sign

   The From header field MUST be signed (that is, included in the "h="
   tag of the resulting DKIM-Signature header field).  Signers SHOULD
   NOT sign an existing header field likely to be legitimately modified
   or removed in transit.  In particular, [RFC5321] explicitly permits




Crocker, et al.              Standards Track                   [Page 38]

RFC 6376                     DKIM Signatures              September 2011


   modification or removal of the Return-Path header field in transit.
   Signers MAY include any other header fields present at the time of
   signing at the discretion of the Signer.

      INFORMATIVE OPERATIONS NOTE: The choice of which header fields to
      sign is non-obvious.  One strategy is to sign all existing, non-
      repeatable header fields.  An alternative strategy is to sign only
      header fields that are likely to be displayed to or otherwise be
      likely to affect the processing of the message at the receiver.  A
      third strategy is to sign only "well-known" headers.  Note that
      Verifiers may treat unsigned header fields with extreme
      skepticism, including refusing to display them to the end user or
      even ignoring the signature if it does not cover certain header
      fields.  For this reason, signing fields present in the message
      such as Date, Subject, Reply-To, Sender, and all MIME header
      fields are highly advised.

   The DKIM-Signature header field is always implicitly signed and MUST
   NOT be included in the "h=" tag except to indicate that other
   preexisting signatures are also signed.

   Signers MAY claim to have signed header fields that do not exist
   (that is, Signers MAY include the header field name in the "h=" tag
   even if that header field does not exist in the message).  When
   computing the signature, the nonexisting header field MUST be treated
   as the null string (including the header field name, header field
   value, all punctuation, and the trailing CRLF).

      INFORMATIVE RATIONALE: This allows Signers to explicitly assert
      the absence of a header field; if that header field is added
      later, the signature will fail.

      INFORMATIVE NOTE: A header field name need only be listed once
      more than the actual number of that header field in a message at
      the time of signing in order to prevent any further additions.
      For example, if there is a single Comments header field at the
      time of signing, listing Comments twice in the "h=" tag is
      sufficient to prevent any number of Comments header fields from
      being appended; it is not necessary (but is legal) to list
      Comments three or more times in the "h=" tag.

   Refer to Section 5.4.2 for a discussion of the procedure to be
   followed when canonicalizing a header with more than one instance of
   a particular header field name.

   Signers need to be careful of signing header fields that might have
   additional instances added later in the delivery process, since such
   header fields might be inserted after the signed instance or



Crocker, et al.              Standards Track                   [Page 39]

RFC 6376                     DKIM Signatures              September 2011


   otherwise reordered.  Trace header fields (such as Received) and
   Resent-* blocks are the only fields prohibited by [RFC5322] from
   being reordered.  In particular, since DKIM-Signature header fields
   may be reordered by some intermediate MTAs, signing existing DKIM-
   Signature header fields is error-prone.

      INFORMATIVE ADMONITION: Despite the fact that [RFC5322] does not
      prohibit the reordering of header fields, reordering of signed
      header fields with multiple instances by intermediate MTAs will
      cause DKIM signatures to be broken; such antisocial behavior
      should be avoided.

      INFORMATIVE IMPLEMENTER'S NOTE: Although not required by this
      specification, all end-user visible header fields should be signed
      to avoid possible "indirect spamming".  For example, if the
      Subject header field is not signed, a spammer can resend a
      previously signed mail, replacing the legitimate subject with a
      one-line spam.

5.4.1.  Recommended Signature Content

   The purpose of the DKIM cryptographic algorithm is to affix an
   identifier to the message in a way that is both robust against normal
   transit-related changes and resistant to kinds of replay attacks.  An
   essential aspect of satisfying these requirements is choosing what
   header fields to include in the hash and what fields to exclude.

   The basic rule for choosing fields to include is to select those
   fields that constitute the "core" of the message content.  Hence, any
   replay attack will have to include these in order to have the
   signature succeed; however, with these included, the core of the
   message is valid, even if sent on to new recipients.

   Common examples of fields with addresses and fields with textual
   content related to the body are:

   o  From (REQUIRED; see Section 5.4)

   o  Reply-To

   o  Subject

   o  Date

   o  To, Cc

   o  Resent-Date, Resent-From, Resent-To, Resent-Cc




Crocker, et al.              Standards Track                   [Page 40]

RFC 6376                     DKIM Signatures              September 2011


   o  In-Reply-To, References

   o  List-Id, List-Help, List-Unsubscribe, List-Subscribe, List-Post,
      List-Owner, List-Archive

   If the "l=" signature tag is in use (see Section 3.5), the Content-
   Type field is also a candidate for being included as it could be
   replaced in a way that causes completely different content to be
   rendered to the receiving user.

   There are trade-offs in the decision of what constitutes the "core"
   of the message, which for some fields is a subjective concept.
   Including fields such as "Message-ID", for example, is useful if one
   considers a mechanism for being able to distinguish separate
   instances of the same message to be core content.  Similarly, "In-
   Reply-To" and "References" might be desirable to include if one
   considers message threading to be a core part of the message.

   Another class of fields that may be of interest are those that convey
   security-related information about the message, such as
   Authentication-Results [RFC5451].

   The basic rule for choosing fields to exclude is to select those
   fields for which there are multiple fields with the same name and
   fields that are modified in transit.  Examples of these are:

   o  Return-Path

   o  Received

   o  Comments, Keywords

   Note that the DKIM-Signature field is also excluded from the header
   hash because its handling is specified separately.

   Typically, it is better to exclude other optional fields because of
   the potential that additional fields of the same name will be
   legitimately added or reordered prior to verification.  There are
   likely to be legitimate exceptions to this rule because of the wide
   variety of application-specific header fields that might be applied
   to a message, some of which are unlikely to be duplicated, modified,
   or reordered.

   Signers SHOULD choose canonicalization algorithms based on the types
   of messages they process and their aversion to risk.  For example,
   e-commerce sites sending primarily purchase receipts, which are not
   expected to be processed by mailing lists or other software likely to
   modify messages, will generally prefer "simple" canonicalization.



Crocker, et al.              Standards Track                   [Page 41]

RFC 6376                     DKIM Signatures              September 2011


   Sites sending primarily person-to-person email will likely prefer to
   be more resilient to modification during transport by using "relaxed"
   canonicalization.

   Unless mail is processed through intermediaries, such as mailing
   lists that might add "unsubscribe" instructions to the bottom of the
   message body, the "l=" tag is likely to convey no additional benefit
   while providing an avenue for unauthorized addition of text to a
   message.  The use of "l=0" takes this to the extreme, allowing
   complete alteration of the text of the message without invalidating
   the signature.  Moreover, a Verifier would be within its rights to
   consider a partly signed message body as unacceptable.  Judicious use
   is advised.

5.4.2.  Signatures Involving Multiple Instances of a Field

   Signers choosing to sign an existing header field that occurs more
   than once in the message (such as Received) MUST sign the physically
   last instance of that header field in the header block.  Signers
   wishing to sign multiple instances of such a header field MUST
   include the header field name multiple times in the "h=" tag of the
   DKIM-Signature header field and MUST sign such header fields in order
   from the bottom of the header field block to the top.  The Signer MAY
   include more instances of a header field name in "h=" than there are
   actual corresponding header fields so that the signature will not
   verify if additional header fields of that name are added.

      INFORMATIVE EXAMPLE:

      If the Signer wishes to sign two existing Received header fields,
      and the existing header contains:

      Received: <A>
      Received: <B>
      Received: <C>

      then the resulting DKIM-Signature header field should read:

      DKIM-Signature: ... h=Received : Received :...

      and Received header fields <C> and <B> will be signed in that
      order.









Crocker, et al.              Standards Track                   [Page 42]

RFC 6376                     DKIM Signatures              September 2011


5.5.  Compute the Message Hash and Signature

   The Signer MUST compute the message hash as described in Section 3.7
   and then sign it using the selected public-key algorithm.  This will
   result in a DKIM-Signature header field that will include the body
   hash and a signature of the header hash, where that header includes
   the DKIM-Signature header field itself.

   Entities such as mailing list managers that implement DKIM and that
   modify the message or a header field (for example, inserting
   unsubscribe information) before retransmitting the message SHOULD
   check any existing signature on input and MUST make such
   modifications before re-signing the message.

5.6.  Insert the DKIM-Signature Header Field

   Finally, the Signer MUST insert the DKIM-Signature header field
   created in the previous step prior to transmitting the email.  The
   DKIM-Signature header field MUST be the same as used to compute the
   hash as described above, except that the value of the "b=" tag MUST
   be the appropriately signed hash computed in the previous step,
   signed using the algorithm specified in the "a=" tag of the DKIM-
   Signature header field and using the private key corresponding to the
   selector given in the "s=" tag of the DKIM-Signature header field, as
   chosen above in Section 5.2.

   The DKIM-Signature header field MUST be inserted before any other
   DKIM-Signature fields in the header block.

      INFORMATIVE IMPLEMENTATION NOTE: The easiest way to achieve this
      is to insert the DKIM-Signature header field at the beginning of
      the header block.  In particular, it may be placed before any
      existing Received header fields.  This is consistent with treating
      DKIM-Signature as a trace header field.

6.  Verifier Actions

   Since a Signer MAY remove or revoke a public key at any time, it is
   advised that verification occur in a timely manner.  In many
   configurations, the most timely place is during acceptance by the
   border MTA or shortly thereafter.  In particular, deferring
   verification until the message is accessed by the end user is
   discouraged.

   A border or intermediate MTA MAY verify the message signature(s).  An
   MTA who has performed verification MAY communicate the result of that
   verification by adding a verification header field to incoming
   messages.  This simplifies things considerably for the user, who can



Crocker, et al.              Standards Track                   [Page 43]

RFC 6376                     DKIM Signatures              September 2011


   now use an existing mail user agent.  Most MUAs have the ability to
   filter messages based on message header fields or content; these
   filters would be used to implement whatever policy the user wishes
   with respect to unsigned mail.

   A verifying MTA MAY implement a policy with respect to unverifiable
   mail, regardless of whether or not it applies the verification header
   field to signed messages.

   Verifiers MUST produce a result that is semantically equivalent to
   applying the steps listed in Sections 6.1, 6.1.1, and 6.1.2 in order.
   In practice, several of these steps can be performed in parallel in
   order to improve performance.

6.1.  Extract Signatures from the Message

   The order in which Verifiers try DKIM-Signature header fields is not
   defined; Verifiers MAY try signatures in any order they like.  For
   example, one implementation might try the signatures in textual
   order, whereas another might try signatures by identities that match
   the contents of the From header field before trying other signatures.
   Verifiers MUST NOT attribute ultimate meaning to the order of
   multiple DKIM-Signature header fields.  In particular, there is
   reason to believe that some relays will reorder the header fields in
   potentially arbitrary ways.

      INFORMATIVE IMPLEMENTATION NOTE: Verifiers might use the order as
      a clue to signing order in the absence of any other information.
      However, other clues as to the semantics of multiple signatures
      (such as correlating the signing host with Received header fields)
      might also be considered.

   Survivability of signatures after transit is not guaranteed, and
   signatures can fail to verify through no fault of the Signer.
   Therefore, a Verifier SHOULD NOT treat a message that has one or more
   bad signatures and no good signatures differently from a message with
   no signature at all.

   When a signature successfully verifies, a Verifier will either stop
   processing or attempt to verify any other signatures, at the
   discretion of the implementation.  A Verifier MAY limit the number of
   signatures it tries, in order to avoid denial-of-service attacks (see
   Section 8.4 for further discussion).

   In the following description, text reading "return status
   (explanation)" (where "status" is one of "PERMFAIL" or "TEMPFAIL")
   means that the Verifier MUST immediately cease processing that
   signature.  The Verifier SHOULD proceed to the next signature, if one



Crocker, et al.              Standards Track                   [Page 44]

RFC 6376                     DKIM Signatures              September 2011


   is present, and completely ignore the bad signature.  If the status
   is "PERMFAIL", the signature failed and should not be reconsidered.
   If the status is "TEMPFAIL", the signature could not be verified at
   this time but may be tried again later.  A Verifier MAY either
   arrange to defer the message for later processing or try another
   signature; if no good signature is found and any of the signatures
   resulted in a TEMPFAIL status, the Verifier MAY arrange to defer the
   message for later processing.  The "(explanation)" is not normative
   text; it is provided solely for clarification.

   Verifiers that are prepared to validate multiple signature header
   fields SHOULD proceed to the next signature header field, if one
   exists.  However, Verifiers MAY make note of the fact that an invalid
   signature was present for consideration at a later step.

      INFORMATIVE NOTE: The rationale of this requirement is to permit
      messages that have invalid signatures but also a valid signature
      to work.  For example, a mailing list exploder might opt to leave
      the original submitter signature in place even though the exploder
      knows that it is modifying the message in some way that will break
      that signature, and the exploder inserts its own signature.  In
      this case, the message should succeed even in the presence of the
      known-broken signature.

   For each signature to be validated, the following steps should be
   performed in such a manner as to produce a result that is
   semantically equivalent to performing them in the indicated order.

6.1.1.  Validate the Signature Header Field

   Implementers MUST meticulously validate the format and values in the
   DKIM-Signature header field; any inconsistency or unexpected values
   MUST cause the header field to be completely ignored and the Verifier
   to return PERMFAIL (signature syntax error).  Being "liberal in what
   you accept" is definitely a bad strategy in this security context.
   Note, however, that this does not include the existence of unknown
   tags in a DKIM-Signature header field, which are explicitly
   permitted.  Verifiers MUST return PERMFAIL (incompatible version)
   when presented a DKIM-Signature header field with a "v=" tag that is
   inconsistent with this specification.

      INFORMATIVE IMPLEMENTATION NOTE: An implementation may, of course,
      choose to also verify signatures generated by older versions of
      this specification.







Crocker, et al.              Standards Track                   [Page 45]

RFC 6376                     DKIM Signatures              September 2011


   If any tag listed as "required" in Section 3.5 is omitted from the
   DKIM-Signature header field, the Verifier MUST ignore the DKIM-
   Signature header field and return PERMFAIL (signature missing
   required tag).

      INFORMATIVE NOTE: The tags listed as required in Section 3.5 are
      "v=", "a=", "b=", "bh=", "d=", "h=", and "s=".  Should there be a
      conflict between this note and Section 3.5, Section 3.5 is
      normative.

   If the DKIM-Signature header field does not contain the "i=" tag, the
   Verifier MUST behave as though the value of that tag were "@d", where
   "d" is the value from the "d=" tag.

   Verifiers MUST confirm that the domain specified in the "d=" tag is
   the same as or a parent domain of the domain part of the "i=" tag.
   If not, the DKIM-Signature header field MUST be ignored, and the
   Verifier should return PERMFAIL (domain mismatch).

   If the "h=" tag does not include the From header field, the Verifier
   MUST ignore the DKIM-Signature header field and return PERMFAIL (From
   field not signed).

   Verifiers MAY ignore the DKIM-Signature header field and return
   PERMFAIL (signature expired) if it contains an "x=" tag and the
   signature has expired.

   Verifiers MAY ignore the DKIM-Signature header field if the domain
   used by the Signer in the "d=" tag is not associated with a valid
   signing entity.  For example, signatures with "d=" values such as
   "com" and "co.uk" could be ignored.  The list of unacceptable domains
   SHOULD be configurable.

   Verifiers MAY ignore the DKIM-Signature header field and return
   PERMFAIL (unacceptable signature header) for any other reason, for
   example, if the signature does not sign header fields that the
   Verifier views to be essential.  As a case in point, if MIME header
   fields are not signed, certain attacks may be possible that the
   Verifier would prefer to avoid.

6.1.2.  Get the Public Key

   The public key for a signature is needed to complete the verification
   process.  The process of retrieving the public key depends on the
   query type as defined by the "q=" tag in the DKIM-Signature header
   field.  Obviously, a public key need only be retrieved if the process
   of extracting the signature information is completely successful.




Crocker, et al.              Standards Track                   [Page 46]

RFC 6376                     DKIM Signatures              September 2011


   Details of key management and representation are described in
   Section 3.6.  The Verifier MUST validate the key record and MUST
   ignore any public-key records that are malformed.

      NOTE: The use of a wildcard TXT RR that covers a queried DKIM
      domain name will produce a response to a DKIM query that is
      unlikely to be a valid DKIM key record.  This problem is not
      specific to DKIM and applies to many other types of queries.
      Client software that processes DNS responses needs to take this
      problem into account.

   When validating a message, a Verifier MUST perform the following
   steps in a manner that is semantically the same as performing them in
   the order indicated; in some cases, the implementation may
   parallelize or reorder these steps, as long as the semantics remain
   unchanged:

   1.  The Verifier retrieves the public key as described in Section 3.6
       using the algorithm in the "q=" tag, the domain from the "d="
       tag, and the selector from the "s=" tag.

   2.  If the query for the public key fails to respond, the Verifier
       MAY seek a later verification attempt by returning TEMPFAIL (key
       unavailable).

   3.  If the query for the public key fails because the corresponding
       key record does not exist, the Verifier MUST immediately return
       PERMFAIL (no key for signature).

   4.  If the query for the public key returns multiple key records, the
       Verifier can choose one of the key records or may cycle through
       the key records, performing the remainder of these steps on each
       record at the discretion of the implementer.  The order of the
       key records is unspecified.  If the Verifier chooses to cycle
       through the key records, then the "return ..." wording in the
       remainder of this section means "try the next key record, if any;
       if none, return to try another signature in the usual way".

   5.  If the result returned from the query does not adhere to the
       format defined in this specification, the Verifier MUST ignore
       the key record and return PERMFAIL (key syntax error).  Verifiers
       are urged to validate the syntax of key records carefully to
       avoid attempted attacks.  In particular, the Verifier MUST ignore
       keys with a version code ("v=" tag) that they do not implement.







Crocker, et al.              Standards Track                   [Page 47]

RFC 6376                     DKIM Signatures              September 2011


   6.  If the "h=" tag exists in the public-key record and the hash
       algorithm implied by the "a=" tag in the DKIM-Signature header
       field is not included in the contents of the "h=" tag, the
       Verifier MUST ignore the key record and return PERMFAIL
       (inappropriate hash algorithm).

   7.  If the public-key data (the "p=" tag) is empty, then this key has
       been revoked and the Verifier MUST treat this as a failed
       signature check and return PERMFAIL (key revoked).  There is no
       defined semantic difference between a key that has been revoked
       and a key record that has been removed.

   8.  If the public-key data is not suitable for use with the algorithm
       and key types defined by the "a=" and "k=" tags in the DKIM-
       Signature header field, the Verifier MUST immediately return
       PERMFAIL (inappropriate key algorithm).

6.1.3.  Compute the Verification

   Given a Signer and a public key, verifying a signature consists of
   actions semantically equivalent to the following steps.

   1.  Based on the algorithm defined in the "c=" tag, the body length
       specified in the "l=" tag, and the header field names in the "h="
       tag, prepare a canonicalized version of the message as is
       described in Section 3.7 (note that this canonicalized version
       does not actually replace the original content).  When matching
       header field names in the "h=" tag against the actual message
       header field, comparisons MUST be case-insensitive.

   2.  Based on the algorithm indicated in the "a=" tag, compute the
       message hashes from the canonical copy as described in
       Section 3.7.

   3.  Verify that the hash of the canonicalized message body computed
       in the previous step matches the hash value conveyed in the "bh="
       tag.  If the hash does not match, the Verifier SHOULD ignore the
       signature and return PERMFAIL (body hash did not verify).

   4.  Using the signature conveyed in the "b=" tag, verify the
       signature against the header hash using the mechanism appropriate
       for the public-key algorithm described in the "a=" tag.  If the
       signature does not validate, the Verifier SHOULD ignore the
       signature and return PERMFAIL (signature did not verify).







Crocker, et al.              Standards Track                   [Page 48]

RFC 6376                     DKIM Signatures              September 2011


   5.  Otherwise, the signature has correctly verified.

      INFORMATIVE IMPLEMENTER'S NOTE: Implementations might wish to
      initiate the public-key query in parallel with calculating the
      hash as the public key is not needed until the final decryption is
      calculated.  Implementations may also verify the signature on the
      message header before validating that the message hash listed in
      the "bh=" tag in the DKIM-Signature header field matches that of
      the actual message body; however, if the body hash does not match,
      the entire signature must be considered to have failed.

   A body length specified in the "l=" tag of the signature limits the
   number of bytes of the body passed to the verification algorithm.
   All data beyond that limit is not validated by DKIM.  Hence,
   Verifiers might treat a message that contains bytes beyond the
   indicated body length with suspicion and can choose to treat the
   signature as if it were invalid (e.g., by returning PERMFAIL
   (unsigned content)).

   Should the algorithm reach this point, the verification has
   succeeded, and DKIM reports SUCCESS for this signature.

6.2.  Communicate Verification Results

   Verifiers wishing to communicate the results of verification to other
   parts of the mail system may do so in whatever manner they see fit.
   For example, implementations might choose to add an email header
   field to the message before passing it on.  Any such header field
   SHOULD be inserted before any existing DKIM-Signature or preexisting
   authentication status header fields in the header field block.  The
   Authentication-Results: header field ([RFC5451]) MAY be used for this
   purpose.

      INFORMATIVE ADVICE to MUA filter writers: Patterns intended to
      search for results header fields to visibly mark authenticated
      mail for end users should verify that such a header field was
      added by the appropriate verifying domain and that the verified
      identity matches the author identity that will be displayed by the
      MUA.  In particular, MUA filters should not be influenced by bogus
      results header fields added by attackers.  To circumvent this
      attack, Verifiers MAY wish to request deletion of existing results
      header fields after verification and before arranging to add a new
      header field.








Crocker, et al.              Standards Track                   [Page 49]

RFC 6376                     DKIM Signatures              September 2011


6.3.  Interpret Results/Apply Local Policy

   It is beyond the scope of this specification to describe what actions
   an Identity Assessor can make, but mail carrying a validated SDID
   presents an opportunity to an Identity Assessor that unauthenticated
   email does not.  Specifically, an authenticated email creates a
   predictable identifier by which other decisions can reliably be
   managed, such as trust and reputation.  Conversely, unauthenticated
   email lacks a reliable identifier that can be used to assign trust
   and reputation.  It is reasonable to treat unauthenticated email as
   lacking any trust and having no positive reputation.

   In general, modules that consume DKIM verification output SHOULD NOT
   determine message acceptability based solely on a lack of any
   signature or on an unverifiable signature; such rejection would cause
   severe interoperability problems.  If an MTA does wish to reject such
   messages during an SMTP session (for example, when communicating with
   a peer who, by prior agreement, agrees to only send signed messages),
   and a signature is missing or does not verify, the handling MTA
   SHOULD use a 550/5.7.x reply code.

   Where the Verifier is integrated within the MTA and it is not
   possible to fetch the public key, perhaps because the key server is
   not available, a temporary failure message MAY be generated using a
   451/4.7.5 reply code, such as:

   451 4.7.5 Unable to verify signature - key server unavailable

   Temporary failures such as inability to access the key server or
   other external service are the only conditions that SHOULD use a 4xx
   SMTP reply code.  In particular, cryptographic signature verification
   failures MUST NOT provoke 4xx SMTP replies.

   Once the signature has been verified, that information MUST be
   conveyed to the Identity Assessor (such as an explicit allow/
   whitelist and reputation system) and/or to the end user.  If the SDID
   is not the same as the address in the From: header field, the mail
   system SHOULD take pains to ensure that the actual SDID is clear to
   the reader.

   While the symptoms of a failed verification are obvious -- the
   signature doesn't verify -- establishing the exact cause can be more
   difficult.  If a selector cannot be found, is that because the
   selector has been removed, or was the value changed somehow in
   transit?  If the signature line is missing, is that because it was
   never there, or was it removed by an overzealous filter?  For
   diagnostic purposes, the exact reason why the verification fails
   SHOULD be made available and possibly recorded in the system logs.



Crocker, et al.              Standards Track                   [Page 50]

RFC 6376                     DKIM Signatures              September 2011


   If the email cannot be verified, then it SHOULD be treated the same
   as all unverified email, regardless of whether or not it looks like
   it was signed.

   See Section 8.15 for additional discussion.

7.  IANA Considerations

   DKIM has registered namespaces with IANA.  In all cases, new values
   are assigned only for values that have been documented in a published
   RFC that has IETF Consensus [RFC5226].

   This memo updates these registries as described below.  Of note is
   the addition of a new "status" column.  All registrations into these
   namespaces MUST include the name being registered, the document in
   which it was registered or updated, and an indication of its current
   status, which MUST be one of "active" (in current use) or "historic"
   (no longer in current use).

   No new tags are defined in this specification compared to [RFC4871],
   but one has been designated as "historic".

   Also, the "Email Authentication Methods" registry is revised to refer
   to this update.

7.1.  Email Authentication Methods Registry

   The "Email Authentication Methods" registry is updated to indicate
   that "dkim" is defined in this memo.

7.2.  DKIM-Signature Tag Specifications

   A DKIM-Signature provides for a list of tag specifications.  IANA has
   established the "DKIM-Signature Tag Specifications" registry for tag
   specifications that can be used in DKIM-Signature fields.
















Crocker, et al.              Standards Track                   [Page 51]

RFC 6376                     DKIM Signatures              September 2011


                    +------+-----------------+--------+
                    | TYPE | REFERENCE       | STATUS |
                    +------+-----------------+--------+
                    |   v  | (this document) | active |
                    |   a  | (this document) | active |
                    |   b  | (this document) | active |
                    |  bh  | (this document) | active |
                    |   c  | (this document) | active |
                    |   d  | (this document) | active |
                    |   h  | (this document) | active |
                    |   i  | (this document) | active |
                    |   l  | (this document) | active |
                    |   q  | (this document) | active |
                    |   s  | (this document) | active |
                    |   t  | (this document) | active |
                    |   x  | (this document) | active |
                    |   z  | (this document) | active |
                    +------+-----------------+--------+

    Table 1: DKIM-Signature Tag Specifications Registry Updated Values

7.3.  DKIM-Signature Query Method Registry

   The "q=" tag-spec (specified in Section 3.5) provides for a list of
   query methods.

   IANA has established the "DKIM-Signature Query Method" registry for
   mechanisms that can be used to retrieve the key that will permit
   validation processing of a message signed using DKIM.

               +------+--------+-----------------+--------+
               | TYPE | OPTION | REFERENCE       | STATUS |
               +------+--------+-----------------+--------+
               |  dns |   txt  | (this document) | active |
               +------+--------+-----------------+--------+

       Table 2: DKIM-Signature Query Method Registry Updated Values

7.4.  DKIM-Signature Canonicalization Registry

   The "c=" tag-spec (specified in Section 3.5) provides for a specifier
   for canonicalization algorithms for the header and body of the
   message.

   IANA has established the "DKIM-Signature Canonicalization Header"
   Registry for algorithms for converting a message into a canonical
   form before signing or verifying using DKIM.




Crocker, et al.              Standards Track                   [Page 52]

RFC 6376                     DKIM Signatures              September 2011


                  +---------+-----------------+--------+
                  |   TYPE  | REFERENCE       | STATUS |
                  +---------+-----------------+--------+
                  |  simple | (this document) | active |
                  | relaxed | (this document) | active |
                  +---------+-----------------+--------+

     Table 3: DKIM-Signature Canonicalization Header Registry Updated
                                  Values

                  +---------+-----------------+--------+
                  |   TYPE  | REFERENCE       | STATUS |
                  +---------+-----------------+--------+
                  |  simple | (this document) | active |
                  | relaxed | (this document) | active |
                  +---------+-----------------+--------+

   Table 4: DKIM-Signature Canonicalization Body Registry Updated Values

7.5.  _domainkey DNS TXT Resource Record Tag Specifications

   A _domainkey DNS TXT RR provides for a list of tag specifications.
   IANA has established the DKIM "_domainkey DNS TXT Record Tag
   Specifications" registry for tag specifications that can be used in
   DNS TXT resource records.

                   +------+-----------------+----------+
                   | TYPE | REFERENCE       | STATUS   |
                   +------+-----------------+----------+
                   |   v  | (this document) | active   |
                   |   g  | [RFC4871]       | historic |
                   |   h  | (this document) | active   |
                   |   k  | (this document) | active   |
                   |   n  | (this document) | active   |
                   |   p  | (this document) | active   |
                   |   s  | (this document) | active   |
                   |   t  | (this document) | active   |
                   +------+-----------------+----------+

      Table 5: _domainkey DNS TXT Record Tag Specifications Registry
                              Updated Values

7.6.  DKIM Key Type Registry

   The "k=" <key-k-tag> (specified in Section 3.6.1) and the "a=" <sig-
   a-tag-k> (specified in Section 3.5) tags provide for a list of
   mechanisms that can be used to decode a DKIM signature.




Crocker, et al.              Standards Track                   [Page 53]

RFC 6376                     DKIM Signatures              September 2011


   IANA has established the "DKIM Key Type" registry for such
   mechanisms.

                       +------+-----------+--------+
                       | TYPE | REFERENCE | STATUS |
                       +------+-----------+--------+
                       |  rsa | [RFC3447] | active |
                       +------+-----------+--------+

              Table 6: DKIM Key Type Registry Updated Values

7.7.  DKIM Hash Algorithms Registry

   The "h=" <key-h-tag> (specified in Section 3.6.1) and the "a=" <sig-
   a-tag-h> (specified in Section 3.5) tags provide for a list of
   mechanisms that can be used to produce a digest of message data.

   IANA has established the "DKIM Hash Algorithms" registry for such
   mechanisms.

                  +--------+-------------------+--------+
                  |  TYPE  | REFERENCE         | STATUS |
                  +--------+-------------------+--------+
                  |  sha1  | [FIPS-180-3-2008] | active |
                  | sha256 | [FIPS-180-3-2008] | active |
                  +--------+-------------------+--------+

           Table 7: DKIM Hash Algorithms Registry Updated Values

7.8.  DKIM Service Types Registry

   The "s=" <key-s-tag> tag (specified in Section 3.6.1) provides for a
   list of service types to which this selector may apply.

   IANA has established the "DKIM Service Types" registry for service
   types.

                   +-------+-----------------+--------+
                   |  TYPE | REFERENCE       | STATUS |
                   +-------+-----------------+--------+
                   | email | (this document) | active |
                   |   *   | (this document) | active |
                   +-------+-----------------+--------+

            Table 8: DKIM Service Types Registry Updated Values






Crocker, et al.              Standards Track                   [Page 54]

RFC 6376                     DKIM Signatures              September 2011


7.9.  DKIM Selector Flags Registry

   The "t=" <key-t-tag> tag (specified in Section 3.6.1) provides for a
   list of flags to modify interpretation of the selector.

   IANA has established the "DKIM Selector Flags" registry for
   additional flags.

                    +------+-----------------+--------+
                    | TYPE | REFERENCE       | STATUS |
                    +------+-----------------+--------+
                    |   y  | (this document) | active |
                    |   s  | (this document) | active |
                    +------+-----------------+--------+

           Table 9: DKIM Selector Flags Registry Updated Values

7.10.  DKIM-Signature Header Field

   IANA has added DKIM-Signature to the "Permanent Message Header Field
   Names" registry (see [RFC3864]) for the "mail" protocol, using this
   document as the reference.

8.  Security Considerations

   It has been observed that any introduced mechanism that attempts to
   stem the flow of spam is subject to intensive attack.  DKIM needs to
   be carefully scrutinized to identify potential attack vectors and the
   vulnerability to each.  See also [RFC4686].

8.1.  ASCII Art Attacks

   The relaxed body canonicalization algorithm may enable certain types
   of extremely crude "ASCII Art" attacks where a message may be
   conveyed by adjusting the spacing between words.  If this is a
   concern, the "simple" body canonicalization algorithm should be used
   instead.

8.2.  Misuse of Body Length Limits ("l=" Tag)

   Use of the "l=" tag might allow display of fraudulent content without
   appropriate warning to end users.  The "l=" tag is intended for
   increasing signature robustness when sending to mailing lists that
   both modify their content and do not sign their modified messages.
   However, using the "l=" tag enables attacks in which an intermediary
   with malicious intent can modify a message to include content that
   solely benefits the attacker.  It is possible for the appended




Crocker, et al.              Standards Track                   [Page 55]

RFC 6376                     DKIM Signatures              September 2011


   content to completely replace the original content in the end
   recipient's eyes and to defeat duplicate message detection
   algorithms.

   An example of such an attack includes altering the MIME structure,
   exploiting lax HTML parsing in the MUA, and defeating duplicate
   message detection algorithms.

   To avoid this attack, Signers should be extremely wary of using this
   tag, and Assessors might wish to ignore signatures that use the tag.

8.3.  Misappropriated Private Key

   As with any other security application that uses private- or public-
   key pairs, DKIM requires caution around the handling and protection
   of keys.  A compromised private key or access to one means an
   intruder or malware can send mail signed by the domain that
   advertises the matching public key.

   Thus, private keys issued to users, rather than one used by an
   ADministrative Management Domain (ADMD) itself, create the usual
   problem of securing data stored on personal resources that can affect
   the ADMD.

   A more secure architecture involves sending messages through an
   outgoing MTA that can authenticate the submitter using existing
   techniques (e.g., SMTP Authentication), possibly validate the message
   itself (e.g., verify that the header is legitimate and that the
   content passes a spam content check), and sign the message using a
   key appropriate for the submitter address.  Such an MTA can also
   apply controls on the volume of outgoing mail each user is permitted
   to originate in order to further limit the ability of malware to
   generate bulk email.

8.4.  Key Server Denial-of-Service Attacks

   Since the key servers are distributed (potentially separate for each
   domain), the number of servers that would need to be attacked to
   defeat this mechanism on an Internet-wide basis is very large.
   Nevertheless, key servers for individual domains could be attacked,
   impeding the verification of messages from that domain.  This is not
   significantly different from the ability of an attacker to deny
   service to the mail exchangers for a given domain, although it
   affects outgoing, not incoming, mail.

   A variation on this attack involves a very large amount of mail being
   sent using spoofed signatures from a given domain: the key servers
   for that domain could be overwhelmed with requests in a denial-of-



Crocker, et al.              Standards Track                   [Page 56]

RFC 6376                     DKIM Signatures              September 2011


   service attack (see [RFC4732]).  However, given the low overhead of
   verification compared with handling of the email message itself, such
   an attack would be difficult to mount.

8.5.  Attacks against the DNS

   Since the DNS is a required binding for key services, specific
   attacks against the DNS must be considered.

   While the DNS is currently insecure [RFC3833], these security
   problems are the motivation behind DNS Security (DNSSEC) [RFC4033],
   and all users of the DNS will reap the benefit of that work.

   DKIM is only intended as a "sufficient" method of proving
   authenticity.  It is not intended to provide strong cryptographic
   proof about authorship or contents.  Other technologies such as
   OpenPGP [RFC4880] and S/MIME [RFC5751] address those requirements.

   A second security issue related to the DNS revolves around the
   increased DNS traffic as a consequence of fetching selector-based
   data as well as fetching signing domain policy.  Widespread
   deployment of DKIM will result in a significant increase in DNS
   queries to the claimed signing domain.  In the case of forgeries on a
   large scale, DNS servers could see a substantial increase in queries.

   A specific DNS security issue that should be considered by DKIM
   Verifiers is the name chaining attack described in Section 2.3 of
   [RFC3833].  A DKIM Verifier, while verifying a DKIM-Signature header
   field, could be prompted to retrieve a key record of an attacker's
   choosing.  This threat can be minimized by ensuring that name
   servers, including recursive name servers, used by the Verifier
   enforce strict checking of "glue" and other additional information in
   DNS responses and are therefore not vulnerable to this attack.

8.6.  Replay/Spam Attacks

   In this attack, a spammer sends a piece of spam through an MTA that
   signs it, banking on the reputation of the signing domain (e.g., a
   large popular mailbox provider) rather than its own, and then re-
   sends that message to a large number of intended recipients.  The
   recipients observe the valid signature from the well-known domain,
   elevating their trust in the message and increasing the likelihood of
   delivery and presentation to the user.

   Partial solutions to this problem involve the use of reputation
   services to convey the fact that the specific email address is being
   used for spam and that messages from that Signer are likely to be
   spam.  This requires a real-time detection mechanism in order to



Crocker, et al.              Standards Track                   [Page 57]

RFC 6376                     DKIM Signatures              September 2011


   react quickly enough.  However, such measures might be prone to
   abuse, if, for example, an attacker re-sent a large number of
   messages received from a victim in order to make the victim appear to
   be a spammer.

   Large Verifiers might be able to detect unusually large volumes of
   mails with the same signature in a short time period.  Smaller
   Verifiers can get substantially the same volume of information via
   existing collaborative systems.

8.7.  Limits on Revoking Keys

   When a large domain detects undesirable behavior on the part of one
   of its users, it might wish to revoke the key used to sign that
   user's messages in order to disavow responsibility for messages that
   have not yet been verified or that are the subject of a replay
   attack.  However, the ability of the domain to do so can be limited
   if the same key, for scalability reasons, is used to sign messages
   for many other users.  Mechanisms for explicitly revoking keys on a
   per-address basis have been proposed but require further study as to
   their utility and the DNS load they represent.

8.8.  Intentionally Malformed Key Records

   It is possible for an attacker to publish key records in DNS that are
   intentionally malformed, with the intent of causing a denial-of-
   service attack on a non-robust Verifier implementation.  The attacker
   could then cause a Verifier to read the malformed key record by
   sending a message to one of its users referencing the malformed
   record in a (not necessarily valid) signature.  Verifiers MUST
   thoroughly verify all key records retrieved from the DNS and be
   robust against intentionally as well as unintentionally malformed key
   records.

8.9.  Intentionally Malformed DKIM-Signature Header Fields

   Verifiers MUST be prepared to receive messages with malformed DKIM-
   Signature header fields and thoroughly verify the header field before
   depending on any of its contents.

8.10.  Information Leakage

   An attacker could determine when a particular signature was verified
   by using a per-message selector and then monitoring their DNS traffic
   for the key lookup.  This would act as the equivalent of a "web bug"
   for verification time rather than the time the message was read.





Crocker, et al.              Standards Track                   [Page 58]

RFC 6376                     DKIM Signatures              September 2011


8.11.  Remote Timing Attacks

   In some cases, it may be possible to extract private keys using a
   remote timing attack [BONEH03].  Implementations should consider
   obfuscating the timing to prevent such attacks.

8.12.  Reordered Header Fields

   Existing standards allow intermediate MTAs to reorder header fields.
   If a Signer signs two or more header fields of the same name, this
   can cause spurious verification errors on otherwise legitimate
   messages.  In particular, Signers that sign any existing DKIM-
   Signature fields run the risk of having messages incorrectly fail to
   verify.

8.13.  RSA Attacks

   An attacker could create a large RSA signing key with a small
   exponent, thus requiring that the verification key have a large
   exponent.  This will force Verifiers to use considerable computing
   resources to verify the signature.  Verifiers might avoid this attack
   by refusing to verify signatures that reference selectors with public
   keys having unreasonable exponents.

   In general, an attacker might try to overwhelm a Verifier by flooding
   it with messages requiring verification.  This is similar to other
   MTA denial-of-service attacks and should be dealt with in a similar
   fashion.

8.14.  Inappropriate Signing by Parent Domains

   The trust relationship described in Section 3.10 could conceivably be
   used by a parent domain to sign messages with identities in a
   subdomain not administratively related to the parent.  For example,
   the ".com" registry could create messages with signatures using an
   "i=" value in the example.com domain.  There is no general solution
   to this problem, since the administrative cut could occur anywhere in
   the domain name.  For example, in the domain "example.podunk.ca.us",
   there are three administrative cuts (podunk.ca.us, ca.us, and us),
   any of which could create messages with an identity in the full
   domain.

      INFORMATIVE NOTE: This is considered an acceptable risk for the
      same reason that it is acceptable for domain delegation.  For
      example, in the case above, any of the domains could potentially
      simply delegate "example.podunk.ca.us" to a server of their choice





Crocker, et al.              Standards Track                   [Page 59]

RFC 6376                     DKIM Signatures              September 2011


      and completely replace all DNS-served information.  Note that a
      Verifier MAY ignore signatures that come from an unlikely domain
      such as ".com", as discussed in Section 6.1.1.

8.15.  Attacks Involving Extra Header Fields

   Many email components, including MTAs, MSAs, MUAs, and filtering
   modules, implement message format checks only loosely.  This is done
   out of years of industry pressure to be liberal in what is accepted
   into the mail stream for the sake of reducing support costs;
   improperly formed messages are often silently fixed in transit,
   delivered unrepaired, or displayed inappropriately (e.g., by showing
   only the first of multiple From: fields).

   Agents that evaluate or apply DKIM output need to be aware that a
   DKIM Signer can sign messages that are malformed (e.g., violate
   [RFC5322], such as by having multiple instances of a field that is
   only permitted once), that become malformed in transit, or that
   contain header or body content that is not true or valid.  Use of
   DKIM on such messages might constitute an attack against a receiver,
   especially where additional credence is given to a signed message
   without adequate evaluation of the Signer.

   These can represent serious attacks, but they have nothing to do with
   DKIM; they are attacks on the recipient or on the wrongly identified
   author.

   Moreover, an agent would be incorrect to infer that all instances of
   a header field are signed just because one is.

   A genuine signature from the domain under attack can be obtained by
   legitimate means, but extra header fields can then be added, either
   by interception or by replay.  In this scenario, DKIM can aid in
   detecting addition of specific fields in transit.  This is done by
   having the Signer list the field name(s) in the "h=" tag an extra
   time (e.g., "h=from:from:..." for a message with one From field), so
   that addition of an instance of that field downstream will render the
   signature unable to be verified.  (See Section 3.5 for details.)
   This, in essence, is an explicit indication that the Signer
   repudiates responsibility for such a malformed message.

   DKIM signs and validates the data it is told to and works correctly.
   So in this case, DKIM has done its job of delivering a validated
   domain (the "d=" value) and, given the semantics of a DKIM signature,
   essentially the Signer has taken some responsibility for a
   problematic message.  It is up to the Identity Assessor or some other





Crocker, et al.              Standards Track                   [Page 60]

RFC 6376                     DKIM Signatures              September 2011


   subsequent agent to act on such messages as needed, such as degrading
   the trust of the message (or, indeed, of the Signer), warning the
   recipient, or even refusing delivery.

   All components of the mail system that perform loose enforcement of
   other mail standards will need to revisit that posture when
   incorporating DKIM, especially when considering matters of potential
   attacks such as those described.

9.  References

9.1.  Normative References

   [FIPS-180-3-2008]
              U.S. Department of Commerce, "Secure Hash Standard", FIPS
              PUB 180-3, October 2008.

   [ITU-X660-1997]
              "Information Technology - ASN.1 encoding rules:
              Specification of Basic Encoding Rules (BER), Canonical
              Encoding Rules (CER) and Distinguished Encoding Rules
              (DER)", 1997.

   [RFC1034]  Mockapetris, P., "Domain names - concepts and facilities",
              STD 13, RFC 1034, November 1987.

   [RFC2045]  Freed, N. and N. Borenstein, "Multipurpose Internet Mail
              Extensions (MIME) Part One: Format of Internet Message
              Bodies", RFC 2045, November 1996.

   [RFC2049]  Freed, N. and N. Borenstein, "Multipurpose Internet Mail
              Extensions (MIME) Part Five: Conformance Criteria and
              Examples", RFC 2049, November 1996.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC3447]  Jonsson, J. and B. Kaliski, "Public-Key Cryptography
              Standards (PKCS) #1: RSA Cryptography Specifications
              Version 2.1", RFC 3447, February 2003.

   [RFC5234]  Crocker, D. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234, January 2008.

   [RFC5321]  Klensin, J., "Simple Mail Transfer Protocol", RFC 5321,
              October 2008.





Crocker, et al.              Standards Track                   [Page 61]

RFC 6376                     DKIM Signatures              September 2011


   [RFC5322]  Resnick, P., Ed., "Internet Message Format", RFC 5322,
              October 2008.

   [RFC5598]  Crocker, D., "Internet Mail Architecture", RFC 5598,
              July 2009.

   [RFC5890]  Klensin, J., "Internationalized Domain Names for
              Applications (IDNA): Definitions and Document Framework",
              RFC 5890, August 2010.

9.2.  Informative References

   [BONEH03]  "Remote Timing Attacks are Practical", Proceedings 12th
              USENIX Security Symposium, 2003.

   [RFC2047]  Moore, K., "MIME (Multipurpose Internet Mail Extensions)
              Part Three: Message Header Extensions for Non-ASCII Text",
              RFC 2047, November 1996.

   [RFC3629]  Yergeau, F., "UTF-8, a transformation format of ISO
              10646", STD 63, RFC 3629, November 2003.

   [RFC3766]  Orman, H. and P. Hoffman, "Determining Strengths For
              Public Keys Used For Exchanging Symmetric Keys", BCP 86,
              RFC 3766, April 2004.

   [RFC3833]  Atkins, D. and R. Austein, "Threat Analysis of the Domain
              Name System (DNS)", RFC 3833, August 2004.

   [RFC3864]  Klyne, G., Nottingham, M., and J. Mogul, "Registration
              Procedures for Message Header Fields", BCP 90, RFC 3864,
              September 2004.

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, March 2005.

   [RFC4409]  Gellens, R. and J. Klensin, "Message Submission for Mail",
              RFC 4409, April 2006.

   [RFC4686]  Fenton, J., "Analysis of Threats Motivating DomainKeys
              Identified Mail (DKIM)", RFC 4686, September 2006.

   [RFC4732]  Handley, M., Rescorla, E., and IAB, "Internet Denial-of-
              Service Considerations", RFC 4732, December 2006.






Crocker, et al.              Standards Track                   [Page 62]

RFC 6376                     DKIM Signatures              September 2011


   [RFC4870]  Delany, M., "Domain-Based Email Authentication Using
              Public Keys Advertised in the DNS (DomainKeys)", RFC 4870,
              May 2007.

   [RFC4871]  Allman, E., Callas, J., Delany, M., Libbey, M., Fenton,
              J., and M. Thomas, "DomainKeys Identified Mail (DKIM)
              Signatures", RFC 4871, May 2007.

   [RFC4880]  Callas, J., Donnerhacke, L., Finney, H., Shaw, D., and R.
              Thayer, "OpenPGP Message Format", RFC 4880, November 2007.

   [RFC5226]  Narten, T. and H. Alvestrand, "Guidelines for Writing an
              IANA Considerations Section in RFCs", BCP 26, RFC 5226,
              May 2008.

   [RFC5451]  Kucherawy, M., "Message Header Field for Indicating
              Message Authentication Status", RFC 5451, April 2009.

   [RFC5585]  Hansen, T., Crocker, D., and P. Hallam-Baker, "DomainKeys
              Identified Mail (DKIM) Service Overview", RFC 5585,
              July 2009.

   [RFC5672]  Crocker, D., "RFC 4871 DomainKeys Identified Mail (DKIM)
              Signatures -- Update", RFC 5672, August 2009.

   [RFC5751]  Ramsdell, B. and S. Turner, "Secure/Multipurpose Internet
              Mail Extensions (S/MIME) Version 3.2 Message
              Specification", RFC 5751, January 2010.

   [RFC5863]  Hansen, T., Siegel, E., Hallam-Baker, P., and D. Crocker,
              "DomainKeys Identified Mail (DKIM) Development,
              Deployment, and Operations", RFC 5863, May 2010.

   [RFC6377]  Kucherawy, M., "DomainKeys Identified Mail (DKIM) and
              Mailing Lists", RFC 6377, September 2011.
















Crocker, et al.              Standards Track                   [Page 63]

RFC 6376                     DKIM Signatures              September 2011


Appendix A.  Example of Use (INFORMATIVE)

   This section shows the complete flow of an email from submission to
   final delivery, demonstrating how the various components fit
   together.  The key used in this example is shown in Appendix C.

A.1.  The User Composes an Email

   From: Joe SixPack <joe@football.example.com>
   To: Suzie Q <suzie@shopping.example.net>
   Subject: Is dinner ready?
   Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
   Message-ID: <20030712040037.46341.5F8J@football.example.com>

   Hi.

   We lost the game.  Are you hungry yet?

   Joe.

                   Figure 1: The User Composes an Email






























Crocker, et al.              Standards Track                   [Page 64]

RFC 6376                     DKIM Signatures              September 2011


A.2.  The Email is Signed

   This email is signed by the example.com outbound email server and now
   looks like this:

   DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
        c=simple/simple; q=dns/txt; i=joe@football.example.com;
        h=Received : From : To : Subject : Date : Message-ID;
        bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
        b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
        4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
        KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
        4bmp/YzhwvcubU4=;
   Received: from client1.football.example.com  [192.0.2.1]
        by submitserver.example.com with SUBMISSION;
        Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
   From: Joe SixPack <joe@football.example.com>
   To: Suzie Q <suzie@shopping.example.net>
   Subject: Is dinner ready?
   Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
   Message-ID: <20030712040037.46341.5F8J@football.example.com>

   Hi.

   We lost the game.  Are you hungry yet?

   Joe.

                       Figure 2: The Email is Signed

   The signing email server requires access to the private key
   associated with the "brisbane" selector to generate this signature.



















Crocker, et al.              Standards Track                   [Page 65]

RFC 6376                     DKIM Signatures              September 2011


A.3.  The Email Signature is Verified

   The signature is normally verified by an inbound SMTP server or
   possibly the final delivery agent.  However, intervening MTAs can
   also perform this verification if they choose to do so.  The
   verification process uses the domain "example.com" extracted from the
   "d=" tag and the selector "brisbane" from the "s=" tag in the DKIM-
   Signature header field to form the DNS DKIM query for:
   brisbane._domainkey.example.com

   Signature verification starts with the physically last Received
   header field, the From header field, and so forth, in the order
   listed in the "h=" tag.  Verification follows with a single CRLF
   followed by the body (starting with "Hi.").  The email is canonically
   prepared for verifying with the "simple" method.  The result of the
   query and subsequent verification of the signature is stored (in this
   example) in the X-Authentication-Results header field line.  After
   successful verification, the email looks like this:

   X-Authentication-Results: shopping.example.net
     header.from=joe@football.example.com; dkim=pass
   Received: from mout23.football.example.com (192.168.1.1)
     by shopping.example.net with SMTP;
     Fri, 11 Jul 2003 21:01:59 -0700 (PDT)
   DKIM-Signature: v=1; a=rsa-sha256; s=brisbane; d=example.com;
     c=simple/simple; q=dns/txt; i=joe@football.example.com;
     h=Received : From : To : Subject : Date : Message-ID;
     bh=2jUSOH9NhtVGCQWNr9BrIAPreKQjO6Sn7XIkfJVOzv8=;
     b=AuUoFEfDxTDkHlLXSZEpZj79LICEps6eda7W3deTVFOk4yAUoqOB
       4nujc7YopdG5dWLSdNg6xNAZpOPr+kHxt1IrE+NahM6L/LbvaHut
       KVdkLLkpVaVVQPzeRDI009SO2Il5Lu7rDNH6mZckBdrIx0orEtZV
       4bmp/YzhwvcubU4=;
   Received: from client1.football.example.com  [192.0.2.1]
     by submitserver.example.com with SUBMISSION;
     Fri, 11 Jul 2003 21:01:54 -0700 (PDT)
   From: Joe SixPack <joe@football.example.com>
   To: Suzie Q <suzie@shopping.example.net>
   Subject: Is dinner ready?
   Date: Fri, 11 Jul 2003 21:00:37 -0700 (PDT)
   Message-ID: <20030712040037.46341.5F8J@football.example.com>

   Hi.

   We lost the game.  Are you hungry yet?

   Joe.

                     Figure 3: Successful Verification



Crocker, et al.              Standards Track                   [Page 66]

RFC 6376                     DKIM Signatures              September 2011


Appendix B.  Usage Examples (INFORMATIVE)

   DKIM signing and validating can be used in different ways, for
   different operational scenarios.  This Appendix discusses some common
   examples.

      NOTE: Descriptions in this Appendix are for informational purposes
      only.  They describe various ways that DKIM can be used, given
      particular constraints and needs.  In no case are these examples
      intended to be taken as providing explanation or guidance
      concerning DKIM specification details when creating an
      implementation.

B.1.  Alternate Submission Scenarios

   In the most simple scenario, a user's MUA, MSA, and Internet
   (boundary) MTA are all within the same administrative environment,
   using the same domain name.  Therefore, all of the components
   involved in submission and initial transfer are related.  However, it
   is common for two or more of the components to be under independent
   administrative control.  This creates challenges for choosing and
   administering the domain name to use for signing and for its
   relationship to common email identity header fields.

B.1.1.  Delegated Business Functions

   Some organizations assign specific business functions to discrete
   groups, inside or outside the organization.  The goal, then, is to
   authorize that group to sign some mail but to constrain what
   signatures they can generate.  DKIM selectors (the "s=" signature
   tag) facilitate this kind of restricted authorization.  Examples of
   these outsourced business functions are legitimate email marketing
   providers and corporate benefits providers.

   Here, the delegated group needs to be able to send messages that are
   signed, using the email domain of the client company.  At the same
   time, the client often is reluctant to register a key for the
   provider that grants the ability to send messages for arbitrary
   addresses in the domain.

   There are multiple ways to administer these usage scenarios.  In one
   case, the client organization provides all of the public query
   service (for example, DNS) administration, and in another, it uses
   DNS delegation to enable all ongoing administration of the DKIM key
   record by the delegated group.






Crocker, et al.              Standards Track                   [Page 67]

RFC 6376                     DKIM Signatures              September 2011


   If the client organization retains responsibility for all of the DNS
   administration, the outsourcing company can generate a key pair,
   supplying the public key to the client company, which then registers
   it in the query service using a unique selector.  The client company
   retains control over the use of the delegated key because it retains
   the ability to revoke the key at any time.

   If the client wants the delegated group to do the DNS administration,
   it can have the domain name that is specified with the selector point
   to the provider's DNS server.  The provider then creates and
   maintains all of the DKIM signature information for that selector.
   Hence, the client cannot provide constraints on the local-part of
   addresses that get signed, but it can revoke the provider's signing
   rights by removing the DNS delegation record.

B.1.2.  PDAs and Similar Devices

   PDAs demonstrate the need for using multiple keys per domain.
   Suppose that John Doe wants to be able to send messages using his
   corporate email address, jdoe@example.com, and his email device does
   not have the ability to make a Virtual Private Network (VPN)
   connection to the corporate network, either because the device is
   limited or because there are restrictions enforced by his Internet
   access provider.  If the device is equipped with a private key
   registered for jdoe@example.com by the administrator of the
   example.com domain and appropriate software to sign messages, John
   could sign the message on the device itself before transmission
   through the outgoing network of the access service provider.

B.1.3.  Roaming Users

   Roaming users often find themselves in circumstances where it is
   convenient or necessary to use an SMTP server other than their home
   server; examples are conferences and many hotels.  In such
   circumstances, a signature that is added by the submission service
   will use an identity that is different from the user's home system.

   Ideally, roaming users would connect back to their home server using
   either a VPN or a SUBMISSION server running with SMTP AUTHentication
   on port 587.  If the signing can be performed on the roaming user's
   laptop, then they can sign before submission, although the risk of
   further modification is high.  If neither of these are possible,
   these roaming users will not be able to send mail signed using their
   own domain key.







Crocker, et al.              Standards Track                   [Page 68]

RFC 6376                     DKIM Signatures              September 2011


B.1.4.  Independent (Kiosk) Message Submission

   Stand-alone services, such as walk-up kiosks and web-based
   information services, have no enduring email service relationship
   with the user, but users occasionally request that mail be sent on
   their behalf.  For example, a website providing news often allows the
   reader to forward a copy of the article to a friend.  This is
   typically done using the reader's own email address, to indicate who
   the author is.  This is sometimes referred to as the "Evite" problem,
   named after the website of the same name that allows a user to send
   invitations to friends.

   A common way this is handled is to continue to put the reader's email
   address in the From header field of the message but put an address
   owned by the email posting site into the Sender header field.  The
   posting site can then sign the message, using the domain that is in
   the Sender field.  This provides useful information to the receiving
   email site, which is able to correlate the signing domain with the
   initial submission email role.

   Receiving sites often wish to provide their end users with
   information about mail that is mediated in this fashion.  Although
   the real efficacy of different approaches is a subject for human
   factors usability research, one technique that is used is for the
   verifying system to rewrite the From header field to indicate the
   address that was verified, for example: From: John Doe via
   news@news-site.example <jdoe@example.com>.  (Note that such rewriting
   will break a signature, unless it is done after the verification pass
   is complete.)

B.2.  Alternate Delivery Scenarios

   Email is often received at a mailbox that has an address different
   from the one used during initial submission.  In these cases, an
   intermediary mechanism operates at the address originally used, and
   it then passes the message on to the final destination.  This
   mediation process presents some challenges for DKIM signatures.

B.2.1.  Affinity Addresses

   "Affinity addresses" allow a user to have an email address that
   remains stable, even as the user moves among different email
   providers.  They are typically associated with college alumni
   associations, professional organizations, and recreational
   organizations with which they expect to have a long-term
   relationship.  These domains usually provide forwarding of incoming
   email, and they often have an associated Web application that
   authenticates the user and allows the forwarding address to be



Crocker, et al.              Standards Track                   [Page 69]

RFC 6376                     DKIM Signatures              September 2011


   changed.  However, these services usually depend on users sending
   outgoing messages through their own service provider's MTAs.  Hence,
   mail that is signed with the domain of the affinity address is not
   signed by an entity that is administered by the organization owning
   that domain.

   With DKIM, affinity domains could use the Web application to allow
   users to register per-user keys to be used to sign messages on behalf
   of their affinity address.  The user would take away the secret half
   of the key pair for signing, and the affinity domain would publish
   the public half in DNS for access by Verifiers.

   This is another application that takes advantage of user-level
   keying, and domains used for affinity addresses would typically have
   a very large number of user-level keys.  Alternatively, the affinity
   domain could handle outgoing mail, operating a mail submission agent
   that authenticates users before accepting and signing messages for
   them.  This is, of course, dependent on the user's service provider
   not blocking the relevant TCP ports used for mail submission.

B.2.2.  Simple Address Aliasing (.forward)

   In some cases, a recipient is allowed to configure an email address
   to cause automatic redirection of email messages from the original
   address to another, such as through the use of a Unix .forward file.
   In this case, messages are typically redirected by the mail handling
   service of the recipient's domain, without modification, except for
   the addition of a Received header field to the message and a change
   in the envelope recipient address.  In this case, the recipient at
   the final address' mailbox is likely to be able to verify the
   original signature since the signed content has not changed, and DKIM
   is able to validate the message signature.

B.2.3.  Mailing Lists and Re-Posters

   There is a wide range of behaviors in services that take delivery of
   a message and then resubmit it.  A primary example is with mailing
   lists (collectively called "forwarders" below), ranging from those
   that make no modification to the message itself, other than to add a
   Received header field and change the envelope information, to those
   that add header fields, change the Subject header field, add content
   to the body (typically at the end), or reformat the body in some
   manner.  The simple ones produce messages that are quite similar to
   the automated alias services.  More elaborate systems essentially
   create a new message.






Crocker, et al.              Standards Track                   [Page 70]

RFC 6376                     DKIM Signatures              September 2011


   A Forwarder that does not modify the body or signed header fields of
   a message is likely to maintain the validity of the existing
   signature.  It also could choose to add its own signature to the
   message.

   Forwarders that modify a message in a way that could make an existing
   signature invalid are particularly good candidates for adding their
   own signatures (e.g., mailing-list-name@example.net).  Since
   (re-)signing is taking responsibility for the content of the message,
   these signing forwarders are likely to be selective and forward or
   re-sign a message only if it is received with a valid signature or if
   they have some other basis for knowing that the message is not
   spoofed.

   A common practice among systems that are primarily redistributors of
   mail is to add a Sender header field to the message to identify the
   address being used to sign the message.  This practice will remove
   any preexisting Sender header field as required by [RFC5322].  The
   forwarder applies a new DKIM-Signature header field with the
   signature, public key, and related information of the forwarder.

   See [RFC6377] for additional related topics and discussion.

Appendix C.  Creating a Public Key (INFORMATIVE)

   The default signature is an RSA-signed SHA-256 digest of the complete
   email.  For ease of explanation, the openssl command is used to
   describe the mechanism by which keys and signatures are managed.  One
   way to generate a 1024-bit, unencrypted private key suitable for DKIM
   is to use openssl like this:

   $ openssl genrsa -out rsa.private 1024

   For increased security, the "-passin" parameter can also be added to
   encrypt the private key.  Use of this parameter will require entering
   a password for several of the following steps.  Servers may prefer to
   use hardware cryptographic support.

   The "genrsa" step results in the file rsa.private containing the key
   information similar to this:











Crocker, et al.              Standards Track                   [Page 71]

RFC 6376                     DKIM Signatures              September 2011


   -----BEGIN RSA PRIVATE KEY-----
   MIICXwIBAAKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYtIxN2SnFC
   jxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/RtdC2UzJ1lWT947qR+Rcac2gb
   to/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB
   AoGBALmn+XwWk7akvkUlqb+dOxyLB9i5VBVfje89Teolwc9YJT36BGN/l4e0l6QX
   /1//6DWUTB3KI6wFcm7TWJcxbS0tcKZX7FsJvUz1SbQnkS54DJck1EZO/BLa5ckJ
   gAYIaqlA9C0ZwM6i58lLlPadX/rtHb7pWzeNcZHjKrjM461ZAkEA+itss2nRlmyO
   n1/5yDyCluST4dQfO8kAB3toSEVc7DeFeDhnC1mZdjASZNvdHS4gbLIA1hUGEF9m
   3hKsGUMMPwJBAPW5v/U+AWTADFCS22t72NUurgzeAbzb1HWMqO4y4+9Hpjk5wvL/
   eVYizyuce3/fGke7aRYw/ADKygMJdW8H/OcCQQDz5OQb4j2QDpPZc0Nc4QlbvMsj
   7p7otWRO5xRa6SzXqqV3+F0VpqvDmshEBkoCydaYwc2o6WQ5EBmExeV8124XAkEA
   qZzGsIxVP+sEVRWZmW6KNFSdVUpk3qzK0Tz/WjQMe5z0UunY9Ax9/4PVhp/j61bf
   eAYXunajbBSOLlx4D+TunwJBANkPI5S9iylsbLs6NkaMHV6k5ioHBBmgCak95JGX
   GMot/L2x0IYyMLAz6oLWh2hm7zwtb0CgOrPo1ke44hFYnfc=
   -----END RSA PRIVATE KEY-----

   To extract the public-key component from the private key, use openssl
   like this:

   $ openssl rsa -in rsa.private -out rsa.public -pubout -outform PEM

   This results in the file rsa.public containing the key information
   similar to this:

   -----BEGIN PUBLIC KEY-----
   MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkM
   oGeLnQg1fWn7/zYtIxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v/R
   tdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhitdY9tf6mcwGjaNBcWToI
   MmPSPDdQPNUYckcQ2QIDAQAB
   -----END PUBLIC KEY-----

   This public-key data (without the BEGIN and END tags) is placed in
   the DNS:

   $ORIGIN _domainkey.example.org.
   brisbane IN  TXT  ("v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ"
                      "KBgQDwIRP/UC3SBsEmGqZ9ZJW3/DkMoGeLnQg1fWn7/zYt"
                      "IxN2SnFCjxOCKG9v3b4jYfcTNh5ijSsq631uBItLa7od+v"
                      "/RtdC2UzJ1lWT947qR+Rcac2gbto/NMqJ0fzfVjH4OuKhi"
                      "tdY9tf6mcwGjaNBcWToIMmPSPDdQPNUYckcQ2QIDAQAB")

C.1.  Compatibility with DomainKeys Key Records

   DKIM key records were designed to be backward compatible in many
   cases with key records used by DomainKeys [RFC4870] (sometimes
   referred to as "selector records" in the DomainKeys context).  One
   area of incompatibility warrants particular attention.  The "g=" tag
   value may be used in DomainKeys and [RFC4871] key records to provide



Crocker, et al.              Standards Track                   [Page 72]

RFC 6376                     DKIM Signatures              September 2011


   finer granularity of the validity of the key record to a specific
   local-part.  A null "g=" value in DomainKeys is valid for all
   addresses in the domain.  This differs from the usage in the original
   DKIM specification ([RFC4871]), where a null "g=" value is not valid
   for any address.  In particular, see the example public-key record in
   Section 3.2.3 of [RFC4870].

C.2.  RFC 4871 Compatibility

   Although the "g=" tag has been deprecated in this version of the DKIM
   specification (and thus MUST now be ignored), Signers are advised not
   to include the "g=" tag in key records because some [RFC4871]-
   compliant Verifiers will be in use for a considerable period to come.

Appendix D.  MUA Considerations (INFORMATIVE)

   When a DKIM signature is verified, the processing system sometimes
   makes the result available to the recipient user's MUA.  How to
   present this information to users in a way that helps them is a
   matter of continuing human factors usability research.  The tendency
   is to have the MUA highlight the SDID, in an attempt to show the user
   the identity that is claiming responsibility for the message.  An MUA
   might do this with visual cues such as graphics, might include the
   address in an alternate view, or might even rewrite the original From
   address using the verified information.  Some MUAs might indicate
   which header fields were protected by the validated DKIM signature.
   This could be done with a positive indication on the signed header
   fields, with a negative indication on the unsigned header fields, by
   visually hiding the unsigned header fields, or some combination of
   these.  If an MUA uses visual indications for signed header fields,
   the MUA probably needs to be careful not to display unsigned header
   fields in a way that might be construed by the end user as having
   been signed.  If the message has an "l=" tag whose value does not
   extend to the end of the message, the MUA might also hide or mark the
   portion of the message body that was not signed.

   The aforementioned information is not intended to be exhaustive.  The
   MUA can choose to highlight, accentuate, hide, or otherwise display
   any other information that may, in the opinion of the MUA author, be
   deemed important to the end user.

Appendix E.  Changes since RFC 4871

   o  Abstract and introduction refined based on accumulated experience.

   o  Various references updated.





Crocker, et al.              Standards Track                   [Page 73]

RFC 6376                     DKIM Signatures              September 2011


   o  Several errata resolved (see http://www.rfc-editor.org/):

      *  1376 applied

      *  1377 applied

      *  1378 applied

      *  1379 applied

      *  1380 applied

      *  1381 applied

      *  1382 applied

      *  1383 discarded (no longer applies)

      *  1384 applied

      *  1386 applied

      *  1461 applied

      *  1487 applied

      *  1532 applied

      *  1596 applied

   o  Introductory section enumerating relevant architectural documents
      added.

   o  Introductory section briefly discussing the matter of data
      integrity added.

   o  Allowed tolerance of some clock drift.

   o  Dropped "g=" tag from key records.  The implementation report
      indicates that it is not in use.

   o  Removed errant note about wildcards in the DNS.

   o  Removed SMTP-specific advice in most places.

   o  Reduced (non-normative) recommended signature content list, and
      reworked the text in that section.




Crocker, et al.              Standards Track                   [Page 74]

RFC 6376                     DKIM Signatures              September 2011


   o  Clarified signature generation algorithm by rewriting its pseudo-
      code.

   o  Numerous terminology subsections added, imported from [RFC5672].
      Also, began using these terms throughout the document (e.g., SDID,
      AUID).

   o  Sections added that specify input and output requirements.  Input
      requirements address a security concern raised by the working
      group (see also new sections in Security Considerations).  Output
      requirements are imported from [RFC5672].

   o  Appendix subsection added discussing compatibility with DomainKeys
      ([RFC4870]) records.

   o  Referred to [RFC5451] as an example method of communicating the
      results of DKIM verification.

   o  Removed advice about possible uses of the "l=" signature tag.

   o  IANA registry updated.

   o  Added two new Security Considerations sections talking about
      malformed message attacks.

   o  Various copy editing.

Appendix F.  Acknowledgments

   The previous IETF version of DKIM [RFC4871] was edited by Eric
   Allman, Jon Callas, Mark Delany, Miles Libbey, Jim Fenton, and
   Michael Thomas.

   That specification was the result of an extended collaborative
   effort, including participation by Russ Allbery, Edwin Aoki, Claus
   Assmann, Steve Atkins, Rob Austein, Fred Baker, Mark Baugher, Steve
   Bellovin, Nathaniel Borenstein, Dave Crocker, Michael Cudahy, Dennis
   Dayman, Jutta Degener, Frank Ellermann, Patrik Faeltstroem, Mark
   Fanto, Stephen Farrell, Duncan Findlay, Elliot Gillum, Olafur
   Gudmundsson, Phillip Hallam-Baker, Tony Hansen, Sam Hartman, Arvel
   Hathcock, Amir Herzberg, Paul Hoffman, Russ Housley, Craig Hughes,
   Cullen Jennings, Don Johnsen, Harry Katz, Murray S. Kucherawy, Barry
   Leiba, John Levine, Charles Lindsey, Simon Longsdale, David Margrave,
   Justin Mason, David Mayne, Thierry Moreau, Steve Murphy, Russell
   Nelson, Dave Oran, Doug Otis, Shamim Pirzada, Juan Altmayer Pizzorno,
   Sanjay Pol, Blake Ramsdell, Christian Renaud, Scott Renfro, Neil





Crocker, et al.              Standards Track                   [Page 75]

RFC 6376                     DKIM Signatures              September 2011


   Rerup, Eric Rescorla, Dave Rossetti, Hector Santos, Jim Schaad, the
   Spamhaus.org team, Malte S. Stretz, Robert Sanders, Rand Wacker, Sam
   Weiler, and Dan Wing.

   The earlier DomainKeys was a primary source from which DKIM was
   derived.  Further information about DomainKeys is at [RFC4870].

   This revision received contributions from Steve Atkins, Mark Delany,
   J.D. Falk, Jim Fenton, Michael Hammer, Barry Leiba, John Levine,
   Charles Lindsey, Jeff Macdonald, Franck Martin, Brett McDowell, Doug
   Otis, Bill Oxley, Hector Santos, Rolf Sonneveld, Michael Thomas, and
   Alessandro Vesely.

Authors' Addresses

   Dave Crocker (editor)
   Brandenburg InternetWorking
   675 Spruce Dr.
   Sunnyvale, CA  94086
   USA

   Phone: +1.408.246.8253
   EMail: dcrocker@bbiw.net
   URI:   http://bbiw.net


   Tony Hansen (editor)
   AT&T Laboratories
   200 Laurel Ave. South
   Middletown, NJ  07748
   USA

   EMail: tony+dkimsig@maillennium.att.com


   Murray S. Kucherawy (editor)
   Cloudmark
   128 King St., 2nd Floor
   San Francisco, CA  94107
   USA

   EMail: msk@cloudmark.com









Crocker, et al.              Standards Track                   [Page 76]


```

---

# RFC 7489 — DMARC — Domain-based Message Authentication, Reporting & Conformance

```






Independent Submission                                 M. Kucherawy, Ed.
Request for Comments: 7489
Category: Informational                                   E. Zwicky, Ed.
ISSN: 2070-1721                                                   Yahoo!
                                                              March 2015


Domain-based Message Authentication, Reporting, and Conformance (DMARC)

Abstract

   Domain-based Message Authentication, Reporting, and Conformance
   (DMARC) is a scalable mechanism by which a mail-originating
   organization can express domain-level policies and preferences for
   message validation, disposition, and reporting, that a mail-receiving
   organization can use to improve mail handling.

   Originators of Internet Mail need to be able to associate reliable
   and authenticated domain identifiers with messages, communicate
   policies about messages that use those identifiers, and report about
   mail using those identifiers.  These abilities have several benefits:
   Receivers can provide feedback to Domain Owners about the use of
   their domains; this feedback can provide valuable insight about the
   management of internal operations and the presence of external domain
   name abuse.

   DMARC does not produce or encourage elevated delivery privilege of
   authenticated email.  DMARC is a mechanism for policy distribution
   that enables increasingly strict handling of messages that fail
   authentication checks, ranging from no action, through altered
   delivery, up to message rejection.

Status of This Memo

   This document is not an Internet Standards Track specification; it is
   published for informational purposes.

   This is a contribution to the RFC Series, independently of any other
   RFC stream.  The RFC Editor has chosen to publish this document at
   its discretion and makes no statement about its value for
   implementation or deployment.  Documents approved for publication by
   the RFC Editor are not a candidate for any level of Internet
   Standard; see Section 2 of RFC 5741.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc7489.




Kucherawy & Zwicky            Informational                     [Page 1]

RFC 7489                          DMARC                       March 2015


Copyright Notice

   Copyright (c) 2015 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.

Table of Contents

   1. Introduction ....................................................3
   2. Requirements ....................................................5
      2.1. High-Level Goals ...........................................5
      2.2. Out of Scope ...............................................6
      2.3. Scalability ................................................6
      2.4. Anti-Phishing ..............................................7
   3. Terminology and Definitions .....................................7
      3.1. Identifier Alignment .......................................8
      3.2. Organizational Domain .....................................11
   4. Overview .......................................................12
      4.1. Authentication Mechanisms .................................12
      4.2. Key Concepts ..............................................12
      4.3. Flow Diagram ..............................................13
   5. Use of RFC5322.From ............................................15
   6. Policy .........................................................15
      6.1. DMARC Policy Record .......................................16
      6.2. DMARC URIs ................................................16
      6.3. General Record Format .....................................17
      6.4. Formal Definition .........................................21
      6.5. Domain Owner Actions ......................................22
      6.6. Mail Receiver Actions .....................................23
      6.7. Policy Enforcement Considerations .........................27
   7. DMARC Feedback .................................................28
      7.1. Verifying External Destinations ...........................28
      7.2. Aggregate Reports .........................................30
      7.3. Failure Reports ...........................................36
   8. Minimum Implementations ........................................37
   9. Privacy Considerations .........................................38
      9.1. Data Exposure Considerations ..............................38
      9.2. Report Recipients .........................................39







Kucherawy & Zwicky            Informational                     [Page 2]

RFC 7489                          DMARC                       March 2015


   10. Other Topics ..................................................39
      10.1. Issues Specific to SPF ...................................39
      10.2. DNS Load and Caching .....................................40
      10.3. Rejecting Messages .......................................40
      10.4. Identifier Alignment Considerations ......................41
      10.5. Interoperability Issues ..................................41
   11. IANA Considerations ...........................................42
      11.1. Authentication-Results Method Registry Update ............42
      11.2. Authentication-Results Result Registry Update ............42
      11.3. Feedback Report Header Fields Registry Update ............44
      11.4. DMARC Tag Registry .......................................44
      11.5. DMARC Report Format Registry .............................45
   12. Security Considerations .......................................46
      12.1. Authentication Methods ...................................46
      12.2. Attacks on Reporting URIs ................................46
      12.3. DNS Security .............................................47
      12.4. Display Name Attacks .....................................47
      12.5. External Reporting Addresses .............................48
      12.6. Secure Protocols .........................................48
   13. References ....................................................49
      13.1. Normative References .....................................49
      13.2. Informative References ...................................50
   Appendix A. Technology Considerations .............................52
     A.1. S/MIME .....................................................52
     A.2. Method Exclusion ...........................................53
     A.3. Sender Header Field ........................................53
     A.4. Domain Existence Test ......................................54
     A.5. Issues with ADSP in Operation ..............................54
     A.6. Organizational Domain Discovery Issues .....................55
   Appendix B. Examples ..............................................56
     B.1. Identifier Alignment Examples ..............................56
     B.2. Domain Owner Example .......................................58
     B.3. Mail Receiver Example  .....................................63
     B.4. Utilization of Aggregate Feedback: Example .................64
     B.5. mailto Transport Example ...................................65
   Appendix C. DMARC XML Schema ......................................66
   Acknowledgements ..................................................73
   Authors' Addresses ................................................73

1.  Introduction

   The Sender Policy Framework ([SPF]) and DomainKeys Identified Mail
   ([DKIM]) provide domain-level authentication.  They enable
   cooperating email receivers to detect mail authorized to use the
   domain name, which can permit differential handling.  (A detailed
   discussion of the threats these systems attempt to address can be
   found in [DKIM-THREATS].)  However, there has been no single widely
   accepted or publicly available mechanism to communication of



Kucherawy & Zwicky            Informational                     [Page 3]

RFC 7489                          DMARC                       March 2015


   domain-specific message-handling policies for receivers, or to
   request reporting of authentication and disposition of received mail.
   Absent the ability to obtain feedback reports, originators who have
   implemented email authentication have difficulty determining how
   effective their authentication is.  As a consequence, use of
   authentication failures to filter mail typically does not succeed.

   Over time, one-on-one relationships were established between select
   senders and receivers with privately communicated means to assert
   policy and receive message traffic and authentication disposition
   reporting.  Although these ad hoc practices have been generally
   successful, they require significant manual coordination between
   parties, and this model does not scale for general use on the
   Internet.

   This document defines Domain-based Message Authentication, Reporting,
   and Conformance (DMARC), a mechanism by which email operators
   leverage existing authentication and policy advertisement
   technologies to enable both message-stream feedback and enforcement
   of policies against unauthenticated email.

   DMARC allows Domain Owners and receivers to collaborate by:

   1.  Providing receivers with assertions about Domain Owners' policies

   2.  Providing feedback to senders so they can monitor authentication
       and judge threats

   The basic outline of DMARC is as follows:

   1.  Domain Owners publish policy assertions about domains via the
       DNS.

   2.  Receivers compare the RFC5322.From address in the mail to the SPF
       and DKIM results, if present, and the DMARC policy in DNS.

   3.  These receivers can use these results to determine how the mail
       should be handled.

   4.  The receiver sends reports to the Domain Owner or its designee
       about mail claiming to be from their domain.

   Security terms used in this document are defined in [SEC-TERMS].








Kucherawy & Zwicky            Informational                     [Page 4]

RFC 7489                          DMARC                       March 2015


   DMARC differs from previous approaches to policy advertisement (e.g.,
   [SPF] and [ADSP]) in that:

   o  Authentication technologies are:

      1.  decoupled from any technology-specific policy mechanisms, and

      2.  used solely to establish reliable per-message domain-level
          identifiers.

   o  Multiple authentication technologies are used to:

      1.  reduce the impact of transient authentication errors

      2.  reduce the impact of site-specific configuration errors and
          deployment gaps

      3.  enable more use cases than any individual technology supports
          alone

   o  Receiver-generated feedback is supported, allowing senders to
      establish confidence in authentication practices.

   o  The domain name extracted from a message's RFC5322.From field is
      the primary identifier in the DMARC mechanism.  This identifier is
      used in conjunction with the results of the underlying
      authentication technologies to evaluate results under DMARC.

   Experience with DMARC has revealed some issues of interoperability
   with email in general that require due consideration before
   deployment, particularly with configurations that can cause mail to
   be rejected.  These are discussed in Section 10.

2.  Requirements

   Specification of DMARC is guided by the following high-level goals,
   security dependencies, detailed requirements, and items that are
   documented as out of scope.

2.1.  High-Level Goals

   DMARC has the following high-level goals:

   o  Allow Domain Owners to assert the preferred handling of
      authentication failures, for messages purporting to have
      authorship within the domain.

   o  Allow Domain Owners to verify their authentication deployment.



Kucherawy & Zwicky            Informational                     [Page 5]

RFC 7489                          DMARC                       March 2015


   o  Minimize implementation complexity for both senders and receivers,
      as well as the impact on handling and delivery of legitimate
      messages.

   o  Reduce the amount of successfully delivered spoofed email.

   o  Work at Internet scale.

2.2.  Out of Scope

   Several topics and issues are specifically out of scope for the
   initial version of this work.  These include the following:

   o  different treatment of messages that are not authenticated versus
      those that fail authentication;

   o  evaluation of anything other than RFC5322.From;

   o  multiple reporting formats;

   o  publishing policy other than via the DNS;

   o  reporting or otherwise evaluating other than the last-hop IP
      address;

   o  attacks in the RFC5322.From field, also known as "display name"
      attacks;

   o  authentication of entities other than domains, since DMARC is
      built upon SPF and DKIM, which authenticate domains; and

   o  content analysis.

2.3.  Scalability

   Scalability is a major issue for systems that need to operate in a
   system as widely deployed as current SMTP email.  For this reason,
   DMARC seeks to avoid the need for third parties or pre-sending
   agreements between senders and receivers.  This preserves the
   positive aspects of the current email infrastructure.

   Although DMARC does not introduce third-party senders (namely
   external agents authorized to send on behalf of an operator) to the
   email-handling flow, it also does not preclude them.  Such third
   parties are free to provide services in conjunction with DMARC.






Kucherawy & Zwicky            Informational                     [Page 6]

RFC 7489                          DMARC                       March 2015


2.4.  Anti-Phishing

   DMARC is designed to prevent bad actors from sending mail that claims
   to come from legitimate senders, particularly senders of
   transactional email (official mail that is about business
   transactions).  One of the primary uses of this kind of spoofed mail
   is phishing (enticing users to provide information by pretending to
   be the legitimate service requesting the information).  Thus, DMARC
   is significantly informed by ongoing efforts to enact large-scale,
   Internet-wide anti-phishing measures.

   Although DMARC can only be used to combat specific forms of exact-
   domain spoofing directly, the DMARC mechanism has been found to be
   useful in the creation of reliable and defensible message streams.

   DMARC does not attempt to solve all problems with spoofed or
   otherwise fraudulent email.  In particular, it does not address the
   use of visually similar domain names ("cousin domains") or abuse of
   the RFC5322.From human-readable <display-name>.

3.  Terminology and Definitions

   This section defines terms used in the rest of the document.

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in [KEYWORDS].

   Readers are encouraged to be familiar with the contents of
   [EMAIL-ARCH].  In particular, that document defines various roles in
   the messaging infrastructure that can appear the same or separate in
   various contexts.  For example, a Domain Owner could, via the
   messaging security mechanisms on which DMARC is based, delegate the
   ability to send mail as the Domain Owner to a third party with
   another role.  This document does not address the distinctions among
   such roles; the reader is encouraged to become familiar with that
   material before continuing.

   The following terms are also used:

   Authenticated Identifiers:  Domain-level identifiers that are
      validated using authentication technologies are referred to as
      "Authenticated Identifiers".  See Section 4.1 for details about
      the supported mechanisms.

   Author Domain:  The domain name of the apparent author, as extracted
      from the RFC5322.From field.




Kucherawy & Zwicky            Informational                     [Page 7]

RFC 7489                          DMARC                       March 2015


   Domain Owner:  An entity or organization that owns a DNS domain.  The
      term "owns" here indicates that the entity or organization being
      referenced holds the registration of that DNS domain.  Domain
      Owners range from complex, globally distributed organizations, to
      service providers working on behalf of non-technical clients, to
      individuals responsible for maintaining personal domains.  This
      specification uses this term as analogous to an Administrative
      Management Domain as defined in [EMAIL-ARCH].  It can also refer
      to delegates, such as Report Receivers, when those are outside of
      their immediate management domain.

   Identifier Alignment:  When the domain in the RFC5322.From address
      matches a domain validated by SPF or DKIM (or both), it has
      Identifier Alignment.

   Mail Receiver:  The entity or organization that receives and
      processes email.  Mail Receivers operate one or more Internet-
      facing Mail Transport Agents (MTAs).

   Organizational Domain:  The domain that was registered with a domain
      name registrar.  In the absence of more accurate methods,
      heuristics are used to determine this, since it is not always the
      case that the registered domain name is simply a top-level DNS
      domain plus one component (e.g., "example.com", where "com" is a
      top-level domain).  The Organizational Domain is determined by
      applying the algorithm found in Section 3.2.

   Report Receiver:  An operator that receives reports from another
      operator implementing the reporting mechanism described in this
      document.  Such an operator might be receiving reports about its
      own messages, or reports about messages related to another
      operator.  This term applies collectively to the system components
      that receive and process these reports and the organizations that
      operate them.

3.1.  Identifier Alignment

   Email authentication technologies authenticate various (and
   disparate) aspects of an individual message.  For example, [DKIM]
   authenticates the domain that affixed a signature to the message,
   while [SPF] can authenticate either the domain that appears in the
   RFC5321.MailFrom (MAIL FROM) portion of [SMTP] or the RFC5321.EHLO/
   HELO domain, or both.  These may be different domains, and they are
   typically not visible to the end user.

   DMARC authenticates use of the RFC5322.From domain by requiring that
   it match (be aligned with) an Authenticated Identifier.  The
   RFC5322.From domain was selected as the central identity of the DMARC



Kucherawy & Zwicky            Informational                     [Page 8]

RFC 7489                          DMARC                       March 2015


   mechanism because it is a required message header field and therefore
   guaranteed to be present in compliant messages, and most Mail User
   Agents (MUAs) represent the RFC5322.From field as the originator of
   the message and render some or all of this header field's content to
   end users.

   Thus, this field is the one used by end users to identify the source
   of the message and therefore is a prime target for abuse.  Many
   high-profile email sources, such as email service providers, require
   that the sending agent have authenticated before email can be
   generated.  Thus, for these mailboxes, the mechanism described in
   this document provides recipient end users with strong evidence that
   the message was indeed originated by the agent they associate with
   that mailbox, if the end user knows that these various protections
   have been provided.

   Domain names in this context are to be compared in a case-insensitive
   manner, per [DNS-CASE].

   It is important to note that Identifier Alignment cannot occur with a
   message that is not valid per [MAIL], particularly one with a
   malformed, absent, or repeated RFC5322.From field, since in that case
   there is no reliable way to determine a DMARC policy that applies to
   the message.  Accordingly, DMARC operation is predicated on the input
   being a valid RFC5322 message object, and handling of such
   non-compliant cases is outside of the scope of this specification.
   Further discussion of this can be found in Section 6.6.1.

   Each of the underlying authentication technologies that DMARC takes
   as input yields authenticated domains as their outputs when they
   succeed.  From the perspective of DMARC, each can be operated in a
   "strict" mode or a "relaxed" mode.  A Domain Owner would normally
   select strict mode if it wanted Mail Receivers to apply DMARC
   processing only to messages bearing an RFC5322.From domain exactly
   matching the domains those mechanisms will verify.  Relaxed mode can
   be used when the operator also wishes to affect message flows bearing
   subdomains of the verified domains.

3.1.1.  DKIM-Authenticated Identifiers

   DMARC permits Identifier Alignment, based on the result of a DKIM
   authentication, to be strict or relaxed.  (Note that these are not
   related to DKIM's "simple" and "relaxed" canonicalization modes.)








Kucherawy & Zwicky            Informational                     [Page 9]

RFC 7489                          DMARC                       March 2015


   In relaxed mode, the Organizational Domains of both the [DKIM]-
   authenticated signing domain (taken from the value of the "d=" tag in
   the signature) and that of the RFC5322.From domain must be equal if
   the identifiers are to be considered aligned.  In strict mode, only
   an exact match between both of the Fully Qualified Domain Names
   (FQDNs) is considered to produce Identifier Alignment.

   To illustrate, in relaxed mode, if a validated DKIM signature
   successfully verifies with a "d=" domain of "example.com", and the
   RFC5322.From address is "alerts@news.example.com", the DKIM "d="
   domain and the RFC5322.From domain are considered to be "in
   alignment".  In strict mode, this test would fail, since the "d="
   domain does not exactly match the FQDN of the address.

   However, a DKIM signature bearing a value of "d=com" would never
   allow an "in alignment" result, as "com" should appear on all public
   suffix lists (see Appendix A.6.1) and therefore cannot be an
   Organizational Domain.

   Identifier Alignment is required because a message can bear a valid
   signature from any domain, including domains used by a mailing list
   or even a bad actor.  Therefore, merely bearing a valid signature is
   not enough to infer authenticity of the Author Domain.

   Note that a single email can contain multiple DKIM signatures, and it
   is considered to be a DMARC "pass" if any DKIM signature is aligned
   and verifies.

3.1.2.  SPF-Authenticated Identifiers

   DMARC permits Identifier Alignment, based on the result of an SPF
   authentication, to be strict or relaxed.

   In relaxed mode, the [SPF]-authenticated domain and RFC5322.From
   domain must have the same Organizational Domain.  In strict mode,
   only an exact DNS domain match is considered to produce Identifier
   Alignment.

   Note that the RFC5321.HELO identity is not typically used in the
   context of DMARC (except when required to "fake" an otherwise null
   reverse-path), even though a "pure SPF" implementation according to
   [SPF] would check that identifier.









Kucherawy & Zwicky            Informational                    [Page 10]

RFC 7489                          DMARC                       March 2015


   For example, if a message passes an SPF check with an
   RFC5321.MailFrom domain of "cbg.bounces.example.com", and the address
   portion of the RFC5322.From field contains "payments@example.com",
   the Authenticated RFC5321.MailFrom domain identifier and the
   RFC5322.From domain are considered to be "in alignment" in relaxed
   mode, but not in strict mode.

3.1.3.  Alignment and Extension Technologies

   If in the future DMARC is extended to include the use of other
   authentication mechanisms, the extensions will need to allow for
   domain identifier extraction so that alignment with the RFC5322.From
   domain can be verified.

3.2.  Organizational Domain

   The Organizational Domain is determined using the following
   algorithm:

   1.  Acquire a "public suffix" list, i.e., a list of DNS domain names
       reserved for registrations.  Some country Top-Level Domains
       (TLDs) make specific registration requirements, e.g., the United
       Kingdom places company registrations under ".co.uk"; other TLDs
       such as ".com" appear in the IANA registry of top-level DNS
       domains.  A public suffix list is the union of all of these.
       Appendix A.6.1 contains some discussion about obtaining a public
       suffix list.

   2.  Break the subject DNS domain name into a set of "n" ordered
       labels.  Number these labels from right to left; e.g., for
       "example.com", "com" would be label 1 and "example" would be
       label 2.

   3.  Search the public suffix list for the name that matches the
       largest number of labels found in the subject DNS domain.  Let
       that number be "x".

   4.  Construct a new DNS domain name using the name that matched from
       the public suffix list and prefixing to it the "x+1"th label from
       the subject domain.  This new name is the Organizational Domain.

   Thus, since "com" is an IANA-registered TLD, a subject domain of
   "a.b.c.d.example.com" would have an Organizational Domain of
   "example.com".

   The process of determining a suffix is currently a heuristic one.  No
   list is guaranteed to be accurate or current.




Kucherawy & Zwicky            Informational                    [Page 11]

RFC 7489                          DMARC                       March 2015


4.  Overview

   This section provides a general overview of the design and operation
   of the DMARC environment.

4.1.  Authentication Mechanisms

   The following mechanisms for determining Authenticated Identifiers
   are supported in this version of DMARC:

   o  [DKIM], which provides a domain-level identifier in the content of
      the "d=" tag of a validated DKIM-Signature header field.

   o  [SPF], which can authenticate both the domain found in an [SMTP]
      HELO/EHLO command (the HELO identity) and the domain found in an
      SMTP MAIL command (the MAIL FROM identity).  DMARC uses the result
      of SPF authentication of the MAIL FROM identity.  Section 2.4 of
      [SPF] describes MAIL FROM processing for cases in which the MAIL
      command has a null path.

4.2.  Key Concepts

   DMARC policies are published by the Domain Owner, and retrieved by
   the Mail Receiver during the SMTP session, via the DNS.

   DMARC's filtering function is based on whether the RFC5322.From field
   domain is aligned with (matches) an authenticated domain name from
   SPF or DKIM.  When a DMARC policy is published for the domain name
   found in the RFC5322.From field, and that domain name is not
   validated through SPF or DKIM, the disposition of that message can be
   affected by that DMARC policy when delivered to a participating
   receiver.

   It is important to note that the authentication mechanisms employed
   by DMARC authenticate only a DNS domain and do not authenticate the
   local-part of any email address identifier found in a message, nor do
   they validate the legitimacy of message content.

   DMARC's feedback component involves the collection of information
   about received messages claiming to be from the Organizational Domain
   for periodic aggregate reports to the Domain Owner.  The parameters
   and format for such reports are discussed in later sections of this
   document.

   A DMARC-enabled Mail Receiver might also generate per-message reports
   that contain information related to individual messages that fail SPF
   and/or DKIM.  Per-message failure reports are a useful source of
   information when debugging deployments (if messages can be determined



Kucherawy & Zwicky            Informational                    [Page 12]

RFC 7489                          DMARC                       March 2015


   to be legitimate even though failing authentication) or in analyzing
   attacks.  The capability for such services is enabled by DMARC but
   defined in other referenced material such as [AFRF].

   A message satisfies the DMARC checks if at least one of the supported
   authentication mechanisms:

   1.  produces a "pass" result, and

   2.  produces that result based on an identifier that is in alignment,
       as defined in Section 3.

4.3.  Flow Diagram

    +---------------+
    | Author Domain |< . . . . . . . . . . . . . . . . . . . . . . .
    +---------------+                        .           .         .
        |                                    .           .         .
        V                                    V           V         .
    +-----------+     +--------+       +----------+ +----------+   .
    |   MSA     |<***>|  DKIM  |       |   DKIM   | |    SPF   |   .
    |  Service  |     | Signer |       | Verifier | | Verifier |   .
    +-----------+     +--------+       +----------+ +----------+   .
        |                                    ^            ^        .
        |                                    **************        .
        V                                                 *        .
     +------+        (~~~~~~~~~~~~)      +------+         *        .
     | sMTA |------->( other MTAs )----->| rMTA |         *        .
     +------+        (~~~~~~~~~~~~)      +------+         *        .
                                            |             * ........
                                            |             * .
                                            V             * .
                                     +-----------+        V V
                       +---------+   |    MDA    |     +----------+
                       |  User   |<--| Filtering |<***>|  DMARC   |
                       | Mailbox |   |  Engine   |     | Verifier |
                       +---------+   +-----------+     +----------+

     MSA = Mail Submission Agent
     MDA = Mail Delivery Agent

   The above diagram shows a simple flow of messages through a DMARC-
   aware system.  Solid lines denote the actual message flow, dotted
   lines involve DNS queries used to retrieve message policy related to
   the supported message authentication schemes, and asterisk lines
   indicate data exchange between message-handling modules and message
   authentication modules.  "sMTA" is the sending MTA, and "rMTA" is the
   receiving MTA.



Kucherawy & Zwicky            Informational                    [Page 13]

RFC 7489                          DMARC                       March 2015


   In essence, the steps are as follows:

   1.   Domain Owner constructs an SPF policy and publishes it in its
        DNS database as per [SPF].  Domain Owner also configures its
        system for DKIM signing as described in [DKIM].  Finally, Domain
        Owner publishes via the DNS a DMARC message-handling policy.

   2.   Author generates a message and hands the message to Domain
        Owner's designated mail submission service.

   3.   Submission service passes relevant details to the DKIM signing
        module in order to generate a DKIM signature to be applied to
        the message.

   4.   Submission service relays the now-signed message to its
        designated transport service for routing to its intended
        recipient(s).

   5.   Message may pass through other relays but eventually arrives at
        a recipient's transport service.

   6.   Recipient delivery service conducts SPF and DKIM authentication
        checks by passing the necessary data to their respective
        modules, each of which requires queries to the Author Domain's
        DNS data (when identifiers are aligned; see below).

   7.   The results of these are passed to the DMARC module along with
        the Author's domain.  The DMARC module attempts to retrieve a
        policy from the DNS for that domain.  If none is found, the
        DMARC module determines the Organizational Domain and repeats
        the attempt to retrieve a policy from the DNS.  (This is
        described in further detail in Section 6.6.3.)

   8.   If a policy is found, it is combined with the Author's domain
        and the SPF and DKIM results to produce a DMARC policy result (a
        "pass" or "fail") and can optionally cause one of two kinds of
        reports to be generated (not shown).

   9.   Recipient transport service either delivers the message to the
        recipient inbox or takes other local policy action based on the
        DMARC result (not shown).

   10.  When requested, Recipient transport service collects data from
        the message delivery session to be used in providing feedback
        (see Section 7).






Kucherawy & Zwicky            Informational                    [Page 14]

RFC 7489                          DMARC                       March 2015


5.  Use of RFC5322.From

   One of the most obvious points of security scrutiny for DMARC is the
   choice to focus on an identifier, namely the RFC5322.From address,
   which is part of a body of data that has been trivially forged
   throughout the history of email.

   Several points suggest that it is the most correct and safest thing
   to do in this context:

   o  Of all the identifiers that are part of the message itself, this
      is the only one guaranteed to be present.

   o  It seems the best choice of an identifier on which to focus, as
      most MUAs display some or all of the contents of that field in a
      manner strongly suggesting those data as reflective of the true
      originator of the message.

   The absence of a single, properly formed RFC5322.From field renders
   the message invalid.  Handling of such a message is outside of the
   scope of this specification.

   Since the sorts of mail typically protected by DMARC participants
   tend to only have single Authors, DMARC participants generally
   operate under a slightly restricted profile of RFC5322 with respect
   to the expected syntax of this field.  See Section 6.6 for details.

6.  Policy

   DMARC policies are published by Domain Owners and applied by Mail
   Receivers.

   A Domain Owner advertises DMARC participation of one or more of its
   domains by adding a DNS TXT record (described in Section 6.1) to
   those domains.  In doing so, Domain Owners make specific requests of
   Mail Receivers regarding the disposition of messages purporting to be
   from one of the Domain Owner's domains and the provision of feedback
   about those messages.

   A Domain Owner may choose not to participate in DMARC evaluation by
   Mail Receivers.  In this case, the Domain Owner simply declines to
   advertise participation in those schemes.  For example, if the
   results of path authorization checks ought not be considered as part
   of the overall DMARC result for a given Author Domain, then the
   Domain Owner does not publish an SPF policy record that can produce
   an SPF pass result.





Kucherawy & Zwicky            Informational                    [Page 15]

RFC 7489                          DMARC                       March 2015


   A Mail Receiver implementing the DMARC mechanism SHOULD make a
   best-effort attempt to adhere to the Domain Owner's published DMARC
   policy when a message fails the DMARC test.  Since email streams can
   be complicated (due to forwarding, existing RFC5322.From
   domain-spoofing services, etc.), Mail Receivers MAY deviate from a
   Domain Owner's published policy during message processing and SHOULD
   make available the fact of and reason for the deviation to the Domain
   Owner via feedback reporting, specifically using the "PolicyOverride"
   feature of the aggregate report (see Section 7.2).

6.1.  DMARC Policy Record

   Domain Owner DMARC preferences are stored as DNS TXT records in
   subdomains named "_dmarc".  For example, the Domain Owner of
   "example.com" would post DMARC preferences in a TXT record at
   "_dmarc.example.com".  Similarly, a Mail Receiver wishing to query
   for DMARC preferences regarding mail with an RFC5322.From domain of
   "example.com" would issue a TXT query to the DNS for the subdomain of
   "_dmarc.example.com".  The DNS-located DMARC preference data will
   hereafter be called the "DMARC record".

   DMARC's use of the Domain Name Service is driven by DMARC's use of
   domain names and the nature of the query it performs.  The query
   requirement matches with the DNS, for obtaining simple parametric
   information.  It uses an established method of storing the
   information, associated with the target domain name, namely an
   isolated TXT record that is restricted to the DMARC context.  Use of
   the DNS as the query service has the benefit of reusing an extremely
   well-established operations, administration, and management
   infrastructure, rather than creating a new one.

   Per [DNS], a TXT record can comprise several "character-string"
   objects.  Where this is the case, the module performing DMARC
   evaluation MUST concatenate these strings by joining together the
   objects in order and parsing the result as a single string.

6.2.  DMARC URIs

   [URI] defines a generic syntax for identifying a resource.  The DMARC
   mechanism uses this as the format by which a Domain Owner specifies
   the destination for the two report types that are supported.

   The place such URIs are specified (see Section 6.3) allows a list of
   these to be provided.  A report is normally sent to each listed URI
   in the order provided by the Domain Owner.  Receivers MAY impose a
   limit on the number of URIs to which they will send reports but MUST
   support the ability to send to at least two.  The list of URIs is
   separated by commas (ASCII 0x2C).



Kucherawy & Zwicky            Informational                    [Page 16]

RFC 7489                          DMARC                       March 2015


   Each URI can have associated with it a maximum report size that may
   be sent to it.  This is accomplished by appending an exclamation
   point (ASCII 0x21), followed by a maximum-size indication, before a
   separating comma or terminating semicolon.

   Thus, a DMARC URI is a URI within which any commas or exclamation
   points are percent-encoded per [URI], followed by an OPTIONAL
   exclamation point and a maximum-size specification, and, if there are
   additional reporting URIs in the list, a comma and the next URI.

   For example, the URI "mailto:reports@example.com!50m" would request
   that a report be sent via email to "reports@example.com" so long as
   the report payload does not exceed 50 megabytes.

   A formal definition is provided in Section 6.4.

6.3.  General Record Format

   DMARC records follow the extensible "tag-value" syntax for DNS-based
   key records defined in DKIM [DKIM].

   Section 11 creates a registry for known DMARC tags and registers the
   initial set defined in this document.  Only tags defined in this
   document or in later extensions, and thus added to that registry, are
   to be processed; unknown tags MUST be ignored.

   The following tags are introduced as the initial valid DMARC tags:

   adkim:  (plain-text; OPTIONAL; default is "r".)  Indicates whether
      strict or relaxed DKIM Identifier Alignment mode is required by
      the Domain Owner.  See Section 3.1.1 for details.  Valid values
      are as follows:

      r: relaxed mode

      s: strict mode

   aspf:  (plain-text; OPTIONAL; default is "r".)  Indicates whether
      strict or relaxed SPF Identifier Alignment mode is required by the
      Domain Owner.  See Section 3.1.2 for details.  Valid values are as
      follows:

      r: relaxed mode

      s: strict mode






Kucherawy & Zwicky            Informational                    [Page 17]

RFC 7489                          DMARC                       March 2015


   fo:  Failure reporting options (plain-text; OPTIONAL; default is "0")
      Provides requested options for generation of failure reports.
      Report generators MAY choose to adhere to the requested options.
      This tag's content MUST be ignored if a "ruf" tag (below) is not
      also specified.  The value of this tag is a colon-separated list
      of characters that indicate failure reporting options as follows:

      0: Generate a DMARC failure report if all underlying
         authentication mechanisms fail to produce an aligned "pass"
         result.

      1: Generate a DMARC failure report if any underlying
         authentication mechanism produced something other than an
         aligned "pass" result.

      d: Generate a DKIM failure report if the message had a signature
         that failed evaluation, regardless of its alignment.  DKIM-
         specific reporting is described in [AFRF-DKIM].

      s: Generate an SPF failure report if the message failed SPF
         evaluation, regardless of its alignment.  SPF-specific
         reporting is described in [AFRF-SPF].

   p: Requested Mail Receiver policy (plain-text; REQUIRED for policy
      records).  Indicates the policy to be enacted by the Receiver at
      the request of the Domain Owner.  Policy applies to the domain
      queried and to subdomains, unless subdomain policy is explicitly
      described using the "sp" tag.  This tag is mandatory for policy
      records only, but not for third-party reporting records (see
      Section 7.1).  Possible values are as follows:

      none:  The Domain Owner requests no specific action be taken
         regarding delivery of messages.

      quarantine:  The Domain Owner wishes to have email that fails the
         DMARC mechanism check be treated by Mail Receivers as
         suspicious.  Depending on the capabilities of the Mail
         Receiver, this can mean "place into spam folder", "scrutinize
         with additional intensity", and/or "flag as suspicious".

      reject:  The Domain Owner wishes for Mail Receivers to reject
         email that fails the DMARC mechanism check.  Rejection SHOULD
         occur during the SMTP transaction.  See Section 10.3 for some
         discussion of SMTP rejection methods and their implications.

   pct:  (plain-text integer between 0 and 100, inclusive; OPTIONAL;
      default is 100).  Percentage of messages from the Domain Owner's
      mail stream to which the DMARC policy is to be applied.  However,



Kucherawy & Zwicky            Informational                    [Page 18]

RFC 7489                          DMARC                       March 2015


      this MUST NOT be applied to the DMARC-generated reports, all of
      which must be sent and received unhindered.  The purpose of the
      "pct" tag is to allow Domain Owners to enact a slow rollout
      enforcement of the DMARC mechanism.  The prospect of "all or
      nothing" is recognized as preventing many organizations from
      experimenting with strong authentication-based mechanisms.  See
      Section 6.6.4 for details.  Note that random selection based on
      this percentage, such as the following pseudocode, is adequate:

       if (random mod 100) < pct then
         selected = true
       else
         selected = false

   rf:  Format to be used for message-specific failure reports (colon-
      separated plain-text list of values; OPTIONAL; default is "afrf").
      The value of this tag is a list of one or more report formats as
      requested by the Domain Owner to be used when a message fails both
      [SPF] and [DKIM] tests to report details of the individual
      failure.  The values MUST be present in the registry of reporting
      formats defined in Section 11; a Mail Receiver observing a
      different value SHOULD ignore it or MAY ignore the entire DMARC
      record.  For this version, only "afrf" (the auth-failure report
      type defined in [AFRF]) is presently supported.  See Section 7.3
      for details.  For interoperability, the Authentication Failure
      Reporting Format (AFRF) MUST be supported.

   ri:  Interval requested between aggregate reports (plain-text 32-bit
      unsigned integer; OPTIONAL; default is 86400).  Indicates a
      request to Receivers to generate aggregate reports separated by no
      more than the requested number of seconds.  DMARC implementations
      MUST be able to provide daily reports and SHOULD be able to
      provide hourly reports when requested.  However, anything other
      than a daily report is understood to be accommodated on a best-
      effort basis.

   rua:  Addresses to which aggregate feedback is to be sent (comma-
      separated plain-text list of DMARC URIs; OPTIONAL).  A comma or
      exclamation point that is part of such a DMARC URI MUST be encoded
      per Section 2.1 of [URI] so as to distinguish it from the list
      delimiter or an OPTIONAL size limit.  Section 7.1 discusses
      considerations that apply when the domain name of a URI differs
      from that of the domain advertising the policy.  See Section 12.5
      for additional considerations.  Any valid URI can be specified.  A
      Mail Receiver MUST implement support for a "mailto:" URI, i.e.,
      the ability to send a DMARC report via electronic mail.  If not





Kucherawy & Zwicky            Informational                    [Page 19]

RFC 7489                          DMARC                       March 2015


      provided, Mail Receivers MUST NOT generate aggregate feedback
      reports.  URIs not supported by Mail Receivers MUST be ignored.
      The aggregate feedback report format is described in Section 7.2.

   ruf:  Addresses to which message-specific failure information is to
      be reported (comma-separated plain-text list of DMARC URIs;
      OPTIONAL).  If present, the Domain Owner is requesting Mail
      Receivers to send detailed failure reports about messages that
      fail the DMARC evaluation in specific ways (see the "fo" tag
      above).  The format of the message to be generated MUST follow the
      format specified for the "rf" tag.  Section 7.1 discusses
      considerations that apply when the domain name of a URI differs
      from that of the domain advertising the policy.  A Mail Receiver
      MUST implement support for a "mailto:" URI, i.e., the ability to
      send a DMARC report via electronic mail.  If not provided, Mail
      Receivers MUST NOT generate failure reports.  See Section 12.5 for
      additional considerations.

   sp:  Requested Mail Receiver policy for all subdomains (plain-text;
      OPTIONAL).  Indicates the policy to be enacted by the Receiver at
      the request of the Domain Owner.  It applies only to subdomains of
      the domain queried and not to the domain itself.  Its syntax is
      identical to that of the "p" tag defined above.  If absent, the
      policy specified by the "p" tag MUST be applied for subdomains.
      Note that "sp" will be ignored for DMARC records published on
      subdomains of Organizational Domains due to the effect of the
      DMARC policy discovery mechanism described in Section 6.6.3.

   v: Version (plain-text; REQUIRED).  Identifies the record retrieved
      as a DMARC record.  It MUST have the value of "DMARC1".  The value
      of this tag MUST match precisely; if it does not or it is absent,
      the entire retrieved record MUST be ignored.  It MUST be the first
      tag in the list.

   A DMARC policy record MUST comply with the formal specification found
   in Section 6.4 in that the "v" and "p" tags MUST be present and MUST
   appear in that order.  Unknown tags MUST be ignored.  Syntax errors
   in the remainder of the record SHOULD be discarded in favor of
   default values (if any) or ignored outright.

   Note that given the rules of the previous paragraph, addition of a
   new tag into the registered list of tags does not itself require a
   new version of DMARC to be generated (with a corresponding change to
   the "v" tag's value), but a change to any existing tags does require
   a new version of DMARC.






Kucherawy & Zwicky            Informational                    [Page 20]

RFC 7489                          DMARC                       March 2015


6.4.  Formal Definition

   The formal definition of the DMARC format, using [ABNF], is as
   follows:

     dmarc-uri       = URI [ "!" 1*DIGIT [ "k" / "m" / "g" / "t" ] ]
                       ; "URI" is imported from [URI]; commas (ASCII
                       ; 0x2C) and exclamation points (ASCII 0x21)
                       ; MUST be encoded; the numeric portion MUST fit
                       ; within an unsigned 64-bit integer

     dmarc-record    = dmarc-version dmarc-sep
                       [dmarc-request]
                       [dmarc-sep dmarc-srequest]
                       [dmarc-sep dmarc-auri]
                       [dmarc-sep dmarc-furi]
                       [dmarc-sep dmarc-adkim]
                       [dmarc-sep dmarc-aspf]
                       [dmarc-sep dmarc-ainterval]
                       [dmarc-sep dmarc-fo]
                       [dmarc-sep dmarc-rfmt]
                       [dmarc-sep dmarc-percent]
                       [dmarc-sep]
                       ; components other than dmarc-version and
                       ; dmarc-request may appear in any order

     dmarc-version   = "v" *WSP "=" *WSP %x44 %x4d %x41 %x52 %x43 %x31

     dmarc-sep       = *WSP %x3b *WSP

     dmarc-request   = "p" *WSP "=" *WSP
                       ( "none" / "quarantine" / "reject" )

     dmarc-srequest  = "sp" *WSP "=" *WSP
                       ( "none" / "quarantine" / "reject" )

     dmarc-auri      = "rua" *WSP "=" *WSP
                       dmarc-uri *(*WSP "," *WSP dmarc-uri)

     dmarc-furi      = "ruf" *WSP "=" *WSP
                       dmarc-uri *(*WSP "," *WSP dmarc-uri)

     dmarc-adkim     = "adkim" *WSP "=" *WSP
                       ( "r" / "s" )

     dmarc-aspf      = "aspf" *WSP "=" *WSP
                       ( "r" / "s" )




Kucherawy & Zwicky            Informational                    [Page 21]

RFC 7489                          DMARC                       March 2015


     dmarc-ainterval = "ri" *WSP "=" *WSP 1*DIGIT

     dmarc-fo        = "fo" *WSP "=" *WSP
                       ( "0" / "1" / "d" / "s" )
                       *(*WSP ":" *WSP ( "0" / "1" / "d" / "s" ))

     dmarc-rfmt      = "rf"  *WSP "=" *WSP Keyword *(*WSP ":" Keyword)
                       ; registered reporting formats only

     dmarc-percent   = "pct" *WSP "=" *WSP
                       1*3DIGIT

   "Keyword" is imported from Section 4.1.2 of [SMTP].

   A size limitation in a dmarc-uri, if provided, is interpreted as a
   count of units followed by an OPTIONAL unit size ("k" for kilobytes,
   "m" for megabytes, "g" for gigabytes, "t" for terabytes).  Without a
   unit, the number is presumed to be a basic byte count.  Note that the
   units are considered to be powers of two; a kilobyte is 2^10, a
   megabyte is 2^20, etc.

6.5.  Domain Owner Actions

   To implement the DMARC mechanism, the only action required of a
   Domain Owner is the creation of the DMARC policy record in the DNS.
   However, in order to make meaningful use of DMARC, a Domain Owner
   must at minimum either establish an address to receive reports, or
   deploy authentication technologies and ensure Identifier Alignment.
   Most Domain Owners will want to do both.

   DMARC reports will be of significant size, and the addresses that
   receive them are publicly visible, so we encourage Domain Owners to
   set up dedicated email addresses to receive and process reports, and
   to deploy abuse countermeasures on those email addresses as
   appropriate.

   Authentication technologies are discussed in [DKIM] (see also
   [DKIM-OVERVIEW] and [DKIM-DEPLOYMENT]) and [SPF].













Kucherawy & Zwicky            Informational                    [Page 22]

RFC 7489                          DMARC                       March 2015


6.6.  Mail Receiver Actions

   This section describes receiver actions in the DMARC environment.

6.6.1.  Extract Author Domain

   The domain in the RFC5322.From field is extracted as the domain to be
   evaluated by DMARC.  If the domain is encoded with UTF-8, the domain
   name must be converted to an A-label, as described in Section 2.3 of
   [IDNA], for further processing.

   In order to be processed by DMARC, a message typically needs to
   contain exactly one RFC5322.From domain (a single From: field with a
   single domain in it).  Not all messages meet this requirement, and
   handling of them is outside of the scope of this document.  Typical
   exceptions, and the way they have been historically handled by DMARC
   participants, are as follows:

   o  Messages with multiple RFC5322.From fields are typically rejected,
      since that form is forbidden under RFC 5322 [MAIL];

   o  Messages bearing a single RFC5322.From field containing multiple
      addresses (and, thus, multiple domain names to be evaluated) are
      typically rejected because the sorts of mail normally protected by
      DMARC do not use this format;

   o  Messages that have no RFC5322.From field at all are typically
      rejected, since that form is forbidden under RFC 5322 [MAIL];

   o  Messages with an RFC5322.From field that contains no meaningful
      domains, such as RFC 5322 [MAIL]'s "group" syntax, are typically
      ignored.

   The case of a syntactically valid multi-valued RFC5322.From field
   presents a particular challenge.  The process in this case is to
   apply the DMARC check using each of those domains found in the
   RFC5322.From field as the Author Domain and apply the most strict
   policy selected among the checks that fail.













Kucherawy & Zwicky            Informational                    [Page 23]

RFC 7489                          DMARC                       March 2015


6.6.2.  Determine Handling Policy

   To arrive at a policy for an individual message, Mail Receivers MUST
   perform the following actions or their semantic equivalents.
   Steps 2-4 MAY be done in parallel, whereas steps 5 and 6 require
   input from previous steps.

   The steps are as follows:

   1.  Extract the RFC5322.From domain from the message (as above).

   2.  Query the DNS for a DMARC policy record.  Continue if one is
       found, or terminate DMARC evaluation otherwise.  See
       Section 6.6.3 for details.

   3.  Perform DKIM signature verification checks.  A single email could
       contain multiple DKIM signatures.  The results of this step are
       passed to the remainder of the algorithm and MUST include the
       value of the "d=" tag from each checked DKIM signature.

   4.  Perform SPF validation checks.  The results of this step are
       passed to the remainder of the algorithm and MUST include the
       domain name used to complete the SPF check.

   5.  Conduct Identifier Alignment checks.  With authentication checks
       and policy discovery performed, the Mail Receiver checks to see
       if Authenticated Identifiers fall into alignment as described in
       Section 3.  If one or more of the Authenticated Identifiers align
       with the RFC5322.From domain, the message is considered to pass
       the DMARC mechanism check.  All other conditions (authentication
       failures, identifier mismatches) are considered to be DMARC
       mechanism check failures.

   6.  Apply policy.  Emails that fail the DMARC mechanism check are
       disposed of in accordance with the discovered DMARC policy of the
       Domain Owner.  See Section 6.3 for details.

   Heuristics applied in the absence of use by a Domain Owner of either
   SPF or DKIM (e.g., [Best-Guess-SPF]) SHOULD NOT be used, as it may be
   the case that the Domain Owner wishes a Message Receiver not to
   consider the results of that underlying authentication protocol at
   all.

   DMARC evaluation can only yield a "pass" result after one of the
   underlying authentication mechanisms passes for an aligned
   identifier.  If neither passes and one or both of them fail due to a
   temporary error, the Receiver evaluating the message is unable to
   conclude that the DMARC mechanism had a permanent failure; they



Kucherawy & Zwicky            Informational                    [Page 24]

RFC 7489                          DMARC                       March 2015


   therefore cannot apply the advertised DMARC policy.  When otherwise
   appropriate, Receivers MAY send feedback reports regarding temporary
   errors.

   Handling of messages for which SPF and/or DKIM evaluation encounter a
   permanent DNS error is left to the discretion of the Mail Receiver.

6.6.3.  Policy Discovery

   As stated above, the DMARC mechanism uses DNS TXT records to
   advertise policy.  Policy discovery is accomplished via a method
   similar to the method used for SPF records.  This method, and the
   important differences between DMARC and SPF mechanisms, are discussed
   below.

   To balance the conflicting requirements of supporting wildcarding,
   allowing subdomain policy overrides, and limiting DNS query load, the
   following DNS lookup scheme is employed:

   1.  Mail Receivers MUST query the DNS for a DMARC TXT record at the
       DNS domain matching the one found in the RFC5322.From domain in
       the message.  A possibly empty set of records is returned.

   2.  Records that do not start with a "v=" tag that identifies the
       current version of DMARC are discarded.

   3.  If the set is now empty, the Mail Receiver MUST query the DNS for
       a DMARC TXT record at the DNS domain matching the Organizational
       Domain in place of the RFC5322.From domain in the message (if
       different).  This record can contain policy to be asserted for
       subdomains of the Organizational Domain.  A possibly empty set of
       records is returned.

   4.  Records that do not start with a "v=" tag that identifies the
       current version of DMARC are discarded.

   5.  If the remaining set contains multiple records or no records,
       policy discovery terminates and DMARC processing is not applied
       to this message.












Kucherawy & Zwicky            Informational                    [Page 25]

RFC 7489                          DMARC                       March 2015


   6.  If a retrieved policy record does not contain a valid "p" tag, or
       contains an "sp" tag that is not valid, then:

       1.  if a "rua" tag is present and contains at least one
           syntactically valid reporting URI, the Mail Receiver SHOULD
           act as if a record containing a valid "v" tag and "p=none"
           was retrieved, and continue processing;

       2.  otherwise, the Mail Receiver applies no DMARC processing to
           this message.

   If the set produced by the mechanism above contains no DMARC policy
   record (i.e., any indication that there is no such record as opposed
   to a transient DNS error), Mail Receivers SHOULD NOT apply the DMARC
   mechanism to the message.

   Handling of DNS errors when querying for the DMARC policy record is
   left to the discretion of the Mail Receiver.  For example, to ensure
   minimal disruption of mail flow, transient errors could result in
   delivery of the message ("fail open"), or they could result in the
   message being temporarily rejected (i.e., an SMTP 4yx reply), which
   invites the sending MTA to try again after the condition has possibly
   cleared, allowing a definite DMARC conclusion to be reached ("fail
   closed").

6.6.4.  Message Sampling

   If the "pct" tag is present in the policy record, the Mail Receiver
   MUST NOT enact the requested policy ("p" tag or "sp" tag") on more
   than the stated percent of the totality of affected messages.
   However, regardless of whether or not the "pct" tag is present, the
   Mail Receiver MUST include all relevant message data in any reports
   produced.

   If email is subject to the DMARC policy of "quarantine", the Mail
   Receiver SHOULD quarantine the message.  If the email is not subject
   to the "quarantine" policy (due to the "pct" tag), the Mail Receiver
   SHOULD apply local message classification as normal.

   If email is subject to the DMARC policy of "reject", the Mail
   Receiver SHOULD reject the message (see Section 10.3).  If the email
   is not subject to the "reject" policy (due to the "pct" tag), the
   Mail Receiver SHOULD treat the email as though the "quarantine"
   policy applies.  This behavior allows Domain Owners to experiment
   with progressively stronger policies without relaxing existing
   policy.





Kucherawy & Zwicky            Informational                    [Page 26]

RFC 7489                          DMARC                       March 2015


   Mail Receivers implement "pct" via statistical mechanisms that
   achieve a close approximation to the requested percentage and provide
   a representative sample across a reporting period.

6.6.5.  Store Results of DMARC Processing

   The results of Mail Receiver-based DMARC processing should be stored
   for eventual presentation back to the Domain Owner in the form of
   aggregate feedback reports.  Sections 6.3 and 7.2 discuss aggregate
   feedback.

6.7.  Policy Enforcement Considerations

   Mail Receivers MAY choose to reject or quarantine email even if email
   passes the DMARC mechanism check.  The DMARC mechanism does not
   inform Mail Receivers whether an email stream is "good".  Mail
   Receivers are encouraged to maintain anti-abuse technologies to
   combat the possibility of DMARC-enabled criminal campaigns.

   Mail Receivers MAY choose to accept email that fails the DMARC
   mechanism check even if the Domain Owner has published a "reject"
   policy.  Mail Receivers need to make a best effort not to increase
   the likelihood of accepting abusive mail if they choose not to comply
   with a Domain Owner's reject, against policy.  At a minimum, addition
   of the Authentication-Results header field (see [AUTH-RESULTS]) is
   RECOMMENDED when delivery of failing mail is done.  When this is
   done, the DNS domain name thus recorded MUST be encoded as an
   A-label.

   Mail Receivers are only obligated to report reject or quarantine
   policy actions in aggregate feedback reports that are due to DMARC
   policy.  They are not required to report reject or quarantine actions
   that are the result of local policy.  If local policy information is
   exposed, abusers can gain insight into the effectiveness and delivery
   rates of spam campaigns.

   Final disposition of a message is always a matter of local policy.
   An operator that wishes to favor DMARC policy over SPF policy, for
   example, will disregard the SPF policy, since enacting an
   SPF-determined rejection prevents evaluation of DKIM; DKIM might
   otherwise pass, satisfying the DMARC evaluation.  There is a
   trade-off to doing so, namely acceptance and processing of the entire
   message body in exchange for the enhanced protection DMARC provides.

   DMARC-compliant Mail Receivers typically disregard any mail-handling
   directive discovered as part of an authentication mechanism (e.g.,
   Author Domain Signing Practices (ADSP), SPF) where a DMARC record is
   also discovered that specifies a policy other than "none".  Deviating



Kucherawy & Zwicky            Informational                    [Page 27]

RFC 7489                          DMARC                       March 2015


   from this practice introduces inconsistency among DMARC operators in
   terms of handling of the message.  However, such deviation is not
   proscribed.

   To enable Domain Owners to receive DMARC feedback without impacting
   existing mail processing, discovered policies of "p=none" SHOULD NOT
   modify existing mail disposition processing.

   Mail Receivers SHOULD also implement reporting instructions of DMARC,
   even in the absence of a request for DKIM reporting [AFRF-DKIM] or
   SPF reporting [AFRF-SPF].  Furthermore, the presence of such requests
   SHOULD NOT affect DMARC reporting.

7.  DMARC Feedback

   Providing Domain Owners with visibility into how Mail Receivers
   implement and enforce the DMARC mechanism in the form of feedback is
   critical to establishing and maintaining accurate authentication
   deployments.  When Domain Owners can see what effect their policies
   and practices are having, they are better willing and able to use
   quarantine and reject policies.

7.1.  Verifying External Destinations

   It is possible to specify destinations for the different reports that
   are outside the authority of the Domain Owner making the request.
   This allows domains that do not operate mail servers to request
   reports and have them go someplace that is able to receive and
   process them.

   Without checks, this would allow a bad actor to publish a DMARC
   policy record that requests that reports be sent to a victim address,
   and then send a large volume of mail that will fail both DKIM and SPF
   checks to a wide variety of destinations; the victim will in turn be
   flooded with unwanted reports.  Therefore, a verification mechanism
   is included.

   When a Mail Receiver discovers a DMARC policy in the DNS, and the
   Organizational Domain at which that record was discovered is not
   identical to the Organizational Domain of the host part of the
   authority component of a [URI] specified in the "rua" or "ruf" tag,
   the following verification steps are to be taken:

   1.  Extract the host portion of the authority component of the URI.
       Call this the "destination host", as it refers to a Report
       Receiver.

   2.  Prepend the string "_report._dmarc".



Kucherawy & Zwicky            Informational                    [Page 28]

RFC 7489                          DMARC                       March 2015


   3.  Prepend the domain name from which the policy was retrieved,
       after conversion to an A-label if needed.

   4.  Query the DNS for a TXT record at the constructed name.  If the
       result of this request is a temporary DNS error of some kind
       (e.g., a timeout), the Mail Receiver MAY elect to temporarily
       fail the delivery so the verification test can be repeated later.

   5.  For each record returned, parse the result as a series of
       "tag=value" pairs, i.e., the same overall format as the policy
       record (see Section 6.4).  In particular, the "v=DMARC1" tag is
       mandatory and MUST appear first in the list.  Discard any that do
       not pass this test.

   6.  If the result includes no TXT resource records that pass basic
       parsing, a positive determination of the external reporting
       relationship cannot be made; stop.

   7.  If at least one TXT resource record remains in the set after
       parsing, then the external reporting arrangement was authorized
       by the Report Receiver.

   8.  If a "rua" or "ruf" tag is thus discovered, replace the
       corresponding value extracted from the domain's DMARC policy
       record with the one found in this record.  This permits the
       Report Receiver to override the report destination.  However, to
       prevent loops or indirect abuse, the overriding URI MUST use the
       same destination host from the first step.

   For example, if a DMARC policy query for "blue.example.com" contained
   "rua=mailto:reports@red.example.net", the host extracted from the
   latter ("red.example.net") does not match "blue.example.com", so this
   procedure is enacted.  A TXT query for
   "blue.example.com._report._dmarc.red.example.net" is issued.  If a
   single reply comes back containing a tag of "v=DMARC1", then the
   relationship between the two is confirmed.  Moreover,
   "red.example.net" has the opportunity to override the report
   destination requested by "blue.example.com" if needed.

   Where the above algorithm fails to confirm that the external
   reporting was authorized by the Report Receiver, the URI MUST be
   ignored by the Mail Receiver generating the report.  Further, if the
   confirming record includes a URI whose host is again different than
   the domain publishing that override, the Mail Receiver generating the
   report MUST NOT generate a report to either the original or the
   override URI.





Kucherawy & Zwicky            Informational                    [Page 29]

RFC 7489                          DMARC                       March 2015


   A Report Receiver publishes such a record in its DNS if it wishes to
   receive reports for other domains.

   A Report Receiver that is willing to receive reports for any domain
   can use a wildcard DNS record.  For example, a TXT resource record at
   "*._report._dmarc.example.com" containing at least "v=DMARC1"
   confirms that example.com is willing to receive DMARC reports for any
   domain.

   If the Report Receiver is overcome by volume, it can simply remove
   the confirming DNS record.  However, due to positive caching, the
   change could take as long as the time-to-live (TTL) on the record to
   go into effect.

   A Mail Receiver might decide not to enact this procedure if, for
   example, it relies on a local list of domains for which external
   reporting addresses are permitted.

7.2.  Aggregate Reports

   The DMARC aggregate feedback report is designed to provide Domain
   Owners with precise insight into:

   o  authentication results,

   o  corrective action that needs to be taken by Domain Owners, and

   o  the effect of Domain Owner DMARC policy on email streams processed
      by Mail Receivers.

   Aggregate DMARC feedback provides visibility into real-world email
   streams that Domain Owners need to make informed decisions regarding
   the publication of DMARC policy.  When Domain Owners know what
   legitimate mail they are sending, what the authentication results are
   on that mail, and what forged mail receivers are getting, they can
   make better decisions about the policies they need and the steps they
   need to take to enable those policies.  When Domain Owners set
   policies appropriately and understand their effects, Mail Receivers
   can act on them confidently.

   Visibility comes in the form of daily (or more frequent) Mail
   Receiver-originated feedback reports that contain aggregate data on
   message streams relevant to the Domain Owner.  This information
   includes data about messages that passed DMARC authentication as well
   as those that did not.

   The format for these reports is defined in Appendix C.




Kucherawy & Zwicky            Informational                    [Page 30]

RFC 7489                          DMARC                       March 2015


   The report SHOULD include the following data:

   o  The DMARC policy discovered and applied, if any

   o  The selected message disposition

   o  The identifier evaluated by SPF and the SPF result, if any

   o  The identifier evaluated by DKIM and the DKIM result, if any

   o  For both DKIM and SPF, an indication of whether the identifier was
      in alignment

   o  Data for each Domain Owner's subdomain separately from mail from
      the sender's Organizational Domain, even if there is no explicit
      subdomain policy

   o  Sending and receiving domains

   o  The policy requested by the Domain Owner and the policy actually
      applied (if different)

   o  The number of successful authentications

   o  The counts of messages based on all messages received, even if
      their delivery is ultimately blocked by other filtering agents

   Note that Domain Owners or their agents may change the published
   DMARC policy for a domain or subdomain at any time.  From a Mail
   Receiver's perspective, this will occur during a reporting period and
   may be noticed during that period, at the end of that period when
   reports are generated, or during a subsequent reporting period, all
   depending on the Mail Receiver's implementation.  Under these
   conditions, it is possible that a Mail Receiver could do any of the
   following:

   o  generate for such a reporting period a single aggregate report
      that includes message dispositions based on the old policy, or a
      mix of the two policies, even though the report only contains a
      single "policy_published" element;

   o  generate multiple reports for the same period, one for each
      published policy occurring during the reporting period;

   o  generate a report whose end time occurs when the updated policy
      was detected, regardless of any requested report interval.





Kucherawy & Zwicky            Informational                    [Page 31]

RFC 7489                          DMARC                       March 2015


   Such policy changes are expected to be infrequent for any given
   domain, whereas more stringent policy monitoring requirements on the
   Mail Receiver would produce a very large burden at Internet scale.
   Therefore, it is the responsibility of report consumers and Domain
   Owners to be aware of this situation and allow for such mixed reports
   during the propagation of the new policy to Mail Receivers.

   Aggregate reports are most useful when they all cover a common time
   period.  By contrast, correlation of these reports from multiple
   generators when they cover incongruent time periods is difficult or
   impossible.  Report generators SHOULD, wherever possible, adhere to
   hour boundaries for the reporting period they are using.  For
   example, starting a per-day report at 00:00; starting per-hour
   reports at 00:00, 01:00, 02:00; etc.  Report generators using a
   24-hour report period are strongly encouraged to begin that period at
   00:00 UTC, regardless of local timezone or time of report production,
   in order to facilitate correlation.

   A Mail Receiver discovers reporting requests when it looks up a DMARC
   policy record that corresponds to an RFC5322.From domain on received
   mail.  The presence of the "rua" tag specifies where to send
   feedback.

7.2.1.  Transport

   Where the URI specified in a "rua" tag does not specify otherwise, a
   Mail Receiver generating a feedback report SHOULD employ a secure
   transport mechanism.

   The Mail Receiver, after preparing a report, MUST evaluate the
   provided reporting URIs in the order given.  Any reporting URI that
   includes a size limitation exceeded by the generated report (after
   compression and after any encoding required by the particular
   transport mechanism) MUST NOT be used.  An attempt MUST be made to
   deliver an aggregate report to every remaining URI, up to the
   Receiver's limits on supported URIs.

   If transport is not possible because the services advertised by the
   published URIs are not able to accept reports (e.g., the URI refers
   to a service that is unreachable, or all provided URIs specify size
   limits exceeded by the generated record), the Mail Receiver SHOULD
   send a short report (see Section 7.2.2) indicating that a report is
   available but could not be sent.  The Mail Receiver MAY cache that
   data and try again later, or MAY discard data that could not be sent.







Kucherawy & Zwicky            Informational                    [Page 32]

RFC 7489                          DMARC                       March 2015


7.2.1.1.  Email

   The message generated by the Mail Receiver MUST be a [MAIL] message
   formatted per [MIME].  The aggregate report itself MUST be included
   in one of the parts of the message.  A human-readable portion MAY be
   included as a MIME part (such as a text/plain part).

   The aggregate data MUST be an XML file that SHOULD be subjected to
   GZIP compression.  Declining to apply compression can cause the
   report to be too large for a receiver to process (a commonly observed
   receiver limit is ten megabytes); doing the compression increases the
   chances of acceptance of the report at some compute cost.  The
   aggregate data SHOULD be present using the media type "application/
   gzip" if compressed (see [GZIP]), and "text/xml" otherwise.  The
   filename is typically constructed using the following ABNF:

     filename = receiver "!" policy-domain "!" begin-timestamp
                "!" end-timestamp [ "!" unique-id ] "." extension

     unique-id = 1*(ALPHA / DIGIT)

     receiver = domain
                ; imported from [MAIL]

     policy-domain   = domain

     begin-timestamp = 1*DIGIT
                       ; seconds since 00:00:00 UTC January 1, 1970
                       ; indicating start of the time range contained
                       ; in the report

     end-timestamp = 1*DIGIT
                     ; seconds since 00:00:00 UTC January 1, 1970
                     ; indicating end of the time range contained
                     ; in the report

     extension = "xml" / "xml.gz"

   The extension MUST be "xml" for a plain XML file, or "xml.gz" for an
   XML file compressed using GZIP.

   "unique-id" allows an optional unique ID generated by the Mail
   Receiver to distinguish among multiple reports generated
   simultaneously by different sources within the same Domain Owner.







Kucherawy & Zwicky            Informational                    [Page 33]

RFC 7489                          DMARC                       March 2015


   For example, this is a possible filename for the gzip file of a
   report to the Domain Owner "example.com" from the Mail Receiver
   "mail.receiver.example":

     mail.receiver.example!example.com!1013662812!1013749130.gz

   No specific MIME message structure is required.  It is presumed that
   the aggregate reporting address will be equipped to extract MIME
   parts with the prescribed media type and filename and ignore the
   rest.

   Email streams carrying DMARC feedback data MUST conform to the DMARC
   mechanism, thereby resulting in an aligned "pass" (see Section 3.1).
   This practice minimizes the risk of report consumers processing
   fraudulent reports.

   The RFC5322.Subject field for individual report submissions SHOULD
   conform to the following ABNF:

     dmarc-subject = %x52.65.70.6f.72.74 1*FWS       ; "Report"
                     %x44.6f.6d.61.69.6e.3a 1*FWS    ; "Domain:"
                     domain-name 1*FWS               ; from RFC 6376
                     %x53.75.62.6d.69.74.74.65.72.3a ; "Submitter:"
                     1*FWS domain-name 1*FWS
                     %x52.65.70.6f.72.74.2d.49.44.3a ; "Report-ID:"
                     msg-id                          ; from RFC 5322

   The first domain-name indicates the DNS domain name about which the
   report was generated.  The second domain-name indicates the DNS
   domain name representing the Mail Receiver generating the report.
   The purpose of the Report-ID: portion of the field is to enable the
   Domain Owner to identify and ignore duplicate reports that might be
   sent by a Mail Receiver.

   For instance, this is a possible Subject field for a report to the
   Domain Owner "example.com" from the Mail Receiver
   "mail.receiver.example".  It is line-wrapped as allowed by [MAIL]:

     Subject: Report Domain: example.com
         Submitter: mail.receiver.example
         Report-ID: <2002.02.15.1>

   This transport mechanism potentially encounters a problem when
   feedback data size exceeds maximum allowable attachment sizes for
   either the generator or the consumer.  See Section 7.2.2 for further
   discussion.





Kucherawy & Zwicky            Informational                    [Page 34]

RFC 7489                          DMARC                       March 2015


7.2.1.2.  Other Methods

   The specification as written allows for the addition of other
   registered URI schemes to be supported in later versions.

7.2.2.  Error Reports

   When a Mail Receiver is unable to complete delivery of a report via
   any of the URIs listed by the Domain Owner, the Mail Receiver SHOULD
   generate an error message.  An attempt MUST be made to send this
   report to all listed "mailto" URIs, and it MAY also be sent to any or
   all other listed URIs.

   The error report MUST be formatted per [MIME].  A text/plain part
   MUST be included that contains field-value pairs such as those found
   in Section 2 of [DSN].  The fields required, which may appear in any
   order, are as follows:

   Report-Date:  A [MAIL]-formatted date expression indicating when the
      transport failure occurred.

   Report-Domain:  The domain-name about which the failed report was
      generated.

   Report-ID:  The Report-ID: that the report tried to use.

   Report-Size:  The size, in bytes, of the report that was unable to be
      sent.  This MUST represent the number of bytes that the Mail
      Receiver attempted to send.  Where more than one transport system
      was attempted, the sizes may be different; in such cases, separate
      error reports MUST be generated so that this value matches the
      actual attempt that was made.

   Submitter:  The domain-name representing the Mail Receiver that
      generated, but was unable to submit, the report.

   Submitting-URI:  The URI(s) to which the Mail Receiver tried, but
      failed, to submit the report.

   An additional text/plain part MAY be included that gives a human-
   readable explanation of the above and MAY also include a URI that can
   be used to seek assistance.









Kucherawy & Zwicky            Informational                    [Page 35]

RFC 7489                          DMARC                       March 2015


7.3.  Failure Reports

   Failure reports are normally generated and sent almost immediately
   after the Mail Receiver detects a DMARC failure.  Rather than waiting
   for an aggregate report, these reports are useful for quickly
   notifying the Domain Owners when there is an authentication failure.
   Whether the failure is due to an infrastructure problem or the
   message is inauthentic, failure reports also provide more information
   about the failed message than is available in an aggregate report.

   These reports SHOULD include any URI(s) from the message that failed
   authentication.  These reports SHOULD include as much of the message
   and message header as is reasonable to support the Domain Owner's
   investigation into what caused the message to fail authentication and
   track down the sender.

   When a Domain Owner requests failure reports for the purpose of
   forensic analysis, and the Mail Receiver is willing to provide such
   reports, the Mail Receiver generates and sends a message using the
   format described in [AFRF]; this document updates that reporting
   format, as described in Section 7.3.1.

   The destination(s) and nature of the reports are defined by the "ruf"
   and "fo" tags as defined in Section 6.3.

   Where multiple URIs are selected to receive failure reports, the
   report generator MUST make an attempt to deliver to each of them.

   An obvious consideration is the denial-of-service attack that can be
   perpetrated by an attacker who sends numerous messages purporting to
   be from the intended victim Domain Owner but that fail both SPF and
   DKIM; this would cause participating Mail Receivers to send failure
   reports to the Domain Owner or its delegate in potentially huge
   volumes.  Accordingly, participating Mail Receivers are encouraged to
   aggregate these reports as much as is practical, using the Incidents
   field of the Abuse Reporting Format ([ARF]).  Various aggregation
   techniques are possible, including the following:

   o  only send a report to the first recipient of multi-recipient
      messages;

   o  store reports for a period of time before sending them, allowing
      detection, collection, and reporting of like incidents;

   o  apply rate limiting, such as a maximum number of reports per
      minute that will be generated (and the remainder discarded).





Kucherawy & Zwicky            Informational                    [Page 36]

RFC 7489                          DMARC                       March 2015


7.3.1.  Reporting Format Update

   Operators implementing this specification also implement an augmented
   version of [AFRF] as follows:

   1.  A DMARC failure report includes the following ARF header fields,
       with the indicated normative requirement levels:

       *  Identity-Alignment (REQUIRED; defined below)

       *  Delivery-Result (OPTIONAL)

       *  DKIM-Domain, DKIM-Identity, DKIM-Selector (REQUIRED if the
          message was signed by DKIM)

       *  DKIM-Canonicalized-Header, DKIM-Canonicalized-Body (OPTIONAL
          if the message was signed by DKIM)

       *  SPF-DNS (REQUIRED)

   2.  The "Identity-Alignment" field is defined to contain a comma-
       separated list of authentication mechanism names that produced an
       aligned identity, or the keyword "none" if none did.  ABNF:

     id-align     = "Identity-Alignment:" [CFWS]
                    ( "none" /
                      dmarc-method *( [CFWS] "," [CFWS] dmarc-method ) )
                    [CFWS]

     dmarc-method = ( "dkim" / "spf" )
                    ; each may appear at most once in an id-align

   3.  Authentication Failure Type "dmarc" is defined, which is to be
       used when a failure report is generated because some or all of
       the authentication mechanisms failed to produce aligned
       identifiers.  Note that a failure report generator MAY also
       independently produce an AFRF message for any or all of the
       underlying authentication methods.

8.  Minimum Implementations

   A minimum implementation of DMARC has the following characteristics:

   o  Is able to send and/or receive reports at least daily;

   o  Is able to send and/or receive reports using "mailto" URIs;





Kucherawy & Zwicky            Informational                    [Page 37]

RFC 7489                          DMARC                       March 2015


   o  Other than in exceptional circumstances such as resource
      exhaustion, can generate or accept a report up to ten megabytes in
      size;

   o  If acting as a Mail Receiver, fully implements the provisions of
      Section 6.6.

9.  Privacy Considerations

   This section discusses security issues specific to private data that
   may be included in the interactions that are part of DMARC.

9.1.  Data Exposure Considerations

   Aggregate reports are limited in scope to DMARC policy and
   disposition results, to information pertaining to the underlying
   authentication mechanisms, and to the identifiers involved in DMARC
   validation.

   Failed-message reporting provides message-specific details pertaining
   to authentication failures.  Individual reports can contain message
   content as well as trace header fields.  Domain Owners are able to
   analyze individual reports and attempt to determine root causes of
   authentication mechanism failures, gain insight into
   misconfigurations or other problems with email and network
   infrastructure, or inspect messages for insight into abusive
   practices.

   Both report types may expose sender and recipient identifiers (e.g.,
   RFC5322.From addresses), and although the [AFRF] format used for
   failed-message reporting supports redaction, failed-message reporting
   is capable of exposing the entire message to the report recipient.

   Domain Owners requesting reports will receive information about mail
   claiming to be from them, which includes mail that was not, in fact,
   from them.  Information about the final destination of mail where it
   might otherwise be obscured by intermediate systems will therefore be
   exposed.

   When message-forwarding arrangements exist, Domain Owners requesting
   reports will also receive information about mail forwarded to domains
   that were not originally part of their messages' recipient lists.
   This means that destination domains previously unknown to the Domain
   Owner may now become visible.

   Disclosure of information about the messages is being requested by
   the entity generating the email in the first place, i.e., the Domain
   Owner and not the Mail Receiver, so this may not fit squarely within



Kucherawy & Zwicky            Informational                    [Page 38]

RFC 7489                          DMARC                       March 2015


   existing privacy policy provisions.  For some providers, aggregate
   reporting and failed-message reporting are viewed as a function
   similar to complaint reporting about spamming or phishing and are
   treated similarly under the privacy policy.  Report generators (i.e.,
   Mail Receivers) are encouraged to review their reporting limitations
   under such policies before enabling DMARC reporting.

9.2.  Report Recipients

   A DMARC record can specify that reports should be sent to an
   intermediary operating on behalf of the Domain Owner.  This is done
   when the Domain Owner contracts with an entity to monitor mail
   streams for abuse and performance issues.  Receipt by third parties
   of such data may or may not be permitted by the Mail Receiver's
   privacy policy, terms of use, or other similar governing document.
   Domain Owners and Mail Receivers should both review and understand if
   their own internal policies constrain the use and transmission of
   DMARC reporting.

   Some potential exists for report recipients to perform traffic
   analysis, making it possible to obtain metadata about the Receiver's
   traffic.  In addition to verifying compliance with policies,
   Receivers need to consider that before sending reports to a third
   party.

10.  Other Topics

   This section discusses some topics regarding choices made in the
   development of DMARC, largely to commit the history to record.

10.1.  Issues Specific to SPF

   Though DMARC does not inherently change the semantics of an SPF
   policy record, historically lax enforcement of such policies has led
   many to publish extremely broad records containing many large network
   ranges.  Domain Owners are strongly encouraged to carefully review
   their SPF records to understand which networks are authorized to send
   on behalf of the Domain Owner before publishing a DMARC record.

   Some receiver architectures might implement SPF in advance of any
   DMARC operations.  This means that a "-" prefix on a sender's SPF
   mechanism, such as "-all", could cause that rejection to go into
   effect early in handling, causing message rejection before any DMARC
   processing takes place.  Operators choosing to use "-all" should be
   aware of this.






Kucherawy & Zwicky            Informational                    [Page 39]

RFC 7489                          DMARC                       March 2015


10.2.  DNS Load and Caching

   DMARC policies are communicated using the DNS and therefore inherit a
   number of considerations related to DNS caching.  The inherent
   conflict between freshness and the impact of caching on the reduction
   of DNS-lookup overhead should be considered from the Mail Receiver's
   point of view.  Should Domain Owners publish a DNS record with a very
   short TTL, Mail Receivers can be provoked through the injection of
   large volumes of messages to overwhelm the Domain Owner's DNS.
   Although this is not a concern specific to DMARC, the implications of
   a very short TTL should be considered when publishing DMARC policies.

   Conversely, long TTLs will cause records to be cached for long
   periods of time.  This can cause a critical change to DMARC
   parameters advertised by a Domain Owner to go unnoticed for the
   length of the TTL (while waiting for DNS caches to expire).  Avoiding
   this problem can mean shorter TTLs, with the potential problems
   described above.  A balance should be sought to maintain
   responsiveness of DMARC preference changes while preserving the
   benefits of DNS caching.

10.3.  Rejecting Messages

   This proposal calls for rejection of a message during the SMTP
   session under certain circumstances.  This is preferable to
   generation of a Delivery Status Notification ([DSN]), since
   fraudulent messages caught and rejected using DMARC would then result
   in annoying generation of such failure reports that go back to the
   RFC5321.MailFrom address.

   This synchronous rejection is typically done in one of two ways:

   o  Full rejection, wherein the SMTP server issues a 5xy reply code as
      an indication to the SMTP client that the transaction failed; the
      SMTP client is then responsible for generating notification that
      delivery failed (see Section 4.2.5 of [SMTP]).

   o  A "silent discard", wherein the SMTP server returns a 2xy reply
      code implying to the client that delivery (or, at least, relay)
      was successfully completed, but then simply discarding the message
      with no further action.

   Each of these has a cost.  For instance, a silent discard can help to
   prevent backscatter, but it also effectively means that the SMTP
   server has to be programmed to give a false result, which can
   confound external debugging efforts.





Kucherawy & Zwicky            Informational                    [Page 40]

RFC 7489                          DMARC                       March 2015


   Similarly, the text portion of the SMTP reply may be important to
   consider.  For example, when rejecting a message, revealing the
   reason for the rejection might give an attacker enough information to
   bypass those efforts on a later attempt, though it might also assist
   a legitimate client to determine the source of some local issue that
   caused the rejection.

   In the latter case, when doing an SMTP rejection, providing a clear
   hint can be useful in resolving issues.  A receiver might indicate in
   plain text the reason for the rejection by using the word "DMARC"
   somewhere in the reply text.  Many systems are able to scan the SMTP
   reply text to determine the nature of the rejection.  Thus, providing
   a machine-detectable reason for rejection allows the problems causing
   rejections to be properly addressed by automated systems.  For
   example:

       550 5.7.1 Email rejected per DMARC policy for example.com

   If a Mail Receiver elects to defer delivery due to inability to
   retrieve or apply DMARC policy, this is best done with a 4xy SMTP
   reply code.

10.4.  Identifier Alignment Considerations

   The DMARC mechanism allows both DKIM and SPF-authenticated
   identifiers to authenticate email on behalf of a Domain Owner and,
   possibly, on behalf of different subdomains.  If malicious or unaware
   users can gain control of the SPF record or DKIM selector records for
   a subdomain, the subdomain can be used to generate DMARC-passing
   email on behalf of the Organizational Domain.

   For example, an attacker who controls the SPF record for
   "evil.example.com" can send mail with an RFC5322.From field
   containing "foo@example.com" that can pass both authentication and
   the DMARC check against "example.com".

   The Organizational Domain administrator should be careful not to
   delegate control of subdomains if this is an issue, and to consider
   using the "strict" Identifier Alignment option if appropriate.

10.5.  Interoperability Issues

   DMARC limits which end-to-end scenarios can achieve a "pass" result.

   Because DMARC relies on [SPF] and/or [DKIM] to achieve a "pass",
   their limitations also apply.





Kucherawy & Zwicky            Informational                    [Page 41]

RFC 7489                          DMARC                       March 2015


   Additional DMARC constraints occur when a message is processed by
   some Mediators, such as mailing lists.  Transiting a Mediator often
   causes either the authentication to fail or Identifier Alignment to
   be lost.  These transformations may conform to standards but will
   still prevent a DMARC "pass".

   In addition to Mediators, mail that is sent by authorized,
   independent third parties might not be sent with Identifier
   Alignment, also preventing a "pass" result.

   Issues specific to the use of policy mechanisms alongside DKIM are
   further discussed in [DKIM-LISTS], particularly Section 5.2.

11.  IANA Considerations

   This section describes actions completed by IANA.

11.1.  Authentication-Results Method Registry Update

   IANA has added the following to the "Email Authentication Methods"
   registry:

   Method:  dmarc

   Defined:  RFC 7489

   ptype:  header

   Property:  from

   Value:  the domain portion of the RFC5322.From field

   Status:  active

   Version:  1

11.2.  Authentication-Results Result Registry Update

   IANA has added the following in the "Email Authentication Result
   Names" registry:

   Code:  none

   Existing/New Code:  existing

   Defined:  [AUTH-RESULTS]

   Auth Method:  dmarc (added)



Kucherawy & Zwicky            Informational                    [Page 42]

RFC 7489                          DMARC                       March 2015


   Meaning:  No DMARC policy record was published for the aligned
      identifier, or no aligned identifier could be extracted.

   Status:  active


   Code:  pass

   Existing/New Code:  existing

   Defined:  [AUTH-RESULTS]

   Auth Method:  dmarc (added)

   Meaning:  A DMARC policy record was published for the aligned
      identifier, and at least one of the authentication mechanisms
      passed.

   Status:  active


   Code:  fail

   Existing/New Code:  existing

   Defined:  [AUTH-RESULTS]

   Auth Method:  dmarc (added)

   Meaning:  A DMARC policy record was published for the aligned
      identifier, and none of the authentication mechanisms passed.

   Status:  active


   Code:  temperror

   Existing/New Code:  existing

   Defined:  [AUTH-RESULTS]

   Auth Method:  dmarc (added)

   Meaning:  A temporary error occurred during DMARC evaluation.  A
      later attempt might produce a final result.

   Status:  active




Kucherawy & Zwicky            Informational                    [Page 43]

RFC 7489                          DMARC                       March 2015


   Code:  permerror

   Existing/New Code:  existing

   Defined:  [AUTH-RESULTS]

   Auth Method:  dmarc (added)

   Meaning:  A permanent error occurred during DMARC evaluation, such as
      encountering a syntactically incorrect DMARC record.  A later
      attempt is unlikely to produce a final result.

   Status:  active

11.3.  Feedback Report Header Fields Registry Update

   The following has been added to the "Feedback Report Header Fields"
   registry:

   Field Name:  Identity-Alignment

   Description:  indicates whether the message about which a report is
      being generated had any identifiers in alignment as defined in
      RFC 7489

   Multiple Appearances:  No

   Related "Feedback-Type":  auth-failure

   Reference:  RFC 7489

   Status:  current

11.4.  DMARC Tag Registry

   A new registry tree called "Domain-based Message Authentication,
   Reporting, and Conformance (DMARC) Parameters" has been created.
   Within it, a new sub-registry called the "DMARC Tag Registry" has
   been created.

   Names of DMARC tags must be registered with IANA in this new
   sub-registry.  New entries are assigned only for values that have
   been documented in a manner that satisfies the terms of Specification
   Required, per [IANA-CONSIDERATIONS].  Each registration must include
   the tag name; the specification that defines it; a brief description;
   and its status, which must be one of "current", "experimental", or
   "historic".  The Designated Expert needs to confirm that the provided




Kucherawy & Zwicky            Informational                    [Page 44]

RFC 7489                          DMARC                       March 2015


   specification adequately describes the new tag and clearly presents
   how it would be used within the DMARC context by Domain Owners and
   Mail Receivers.

   To avoid version compatibility issues, tags added to the DMARC
   specification are to avoid changing the semantics of existing records
   when processed by implementations conforming to prior specifications.

   The initial set of entries in this registry is as follows:

    +----------+-------------+---------+------------------------------+
    | Tag Name | Reference   | Status  | Description                  |
    +----------+-------------+---------+------------------------------+
    |  adkim   |  RFC 7489   | current | DKIM alignment mode          |
    +----------+-------------+---------+------------------------------+
    |   aspf   |  RFC 7489   | current | SPF alignment mode           |
    +----------+-------------+---------+------------------------------+
    |    fo    |  RFC 7489   | current | Failure reporting options    |
    +----------+-------------+---------+------------------------------+
    |     p    |  RFC 7489   | current | Requested handling policy    |
    +----------+-------------+---------+------------------------------+
    |    pct   |  RFC 7489   | current | Sampling rate                |
    +----------+-------------+---------+------------------------------+
    |    rf    |  RFC 7489   | current | Failure reporting format(s)  |
    +----------+-------------+---------+------------------------------+
    |    ri    |  RFC 7489   | current | Aggregate Reporting interval |
    +----------+-------------+---------+------------------------------+
    |    rua   |  RFC 7489   | current | Reporting URI(s) for         |
    |          |             |         | aggregate data               |
    +----------+-------------+---------+------------------------------+
    |    ruf   |  RFC 7489   | current | Reporting URI(s) for         |
    |          |             |         | failure data                 |
    +----------+-------------+---------+------------------------------+
    |    sp    |  RFC 7489   | current | Requested handling policy    |
    |          |             |         | for subdomains               |
    +----------+-------------+---------+------------------------------+
    |     v    |  RFC 7489   | current | Specification version        |
    +----------+-------------+---------+------------------------------+

11.5.  DMARC Report Format Registry

   Also within "Domain-based Message Authentication, Reporting, and
   Conformance (DMARC) Parameters", a new sub-registry called "DMARC
   Report Format Registry" has been created.

   Names of DMARC failure reporting formats must be registered with IANA
   in this registry.  New entries are assigned only for values that
   satisfy the definition of Specification Required, per



Kucherawy & Zwicky            Informational                    [Page 45]

RFC 7489                          DMARC                       March 2015


   [IANA-CONSIDERATIONS].  In addition to a reference to a permanent
   specification, each registration must include the format name; a
   brief description; and its status, which must be one of "current",
   "experimental", or "historic".  The Designated Expert needs to
   confirm that the provided specification adequately describes the
   report format and clearly presents how it would be used within the
   DMARC context by Domain Owners and Mail Receivers.

   The initial entry in this registry is as follows:

    +--------+-------------+---------+-----------------------------+
    | Format | Reference   | Status  | Description                 |
    |  Name  |             |         |                             |
    +--------+-------------+---------+-----------------------------+
    | afrf   |  RFC 7489   | current | Authentication Failure      |
    |        |             |         | Reporting Format (see       |
    |        |             |         | [AFRF])                     |
    +--------+-------------+---------+-----------------------------+

12.  Security Considerations

   This section discusses security issues and possible remediations
   (where available) for DMARC.

12.1.  Authentication Methods

   Security considerations from the authentication methods used by DMARC
   are incorporated here by reference.

12.2.  Attacks on Reporting URIs

   URIs published in DNS TXT records are well-understood possible
   targets for attack.  Specifications such as [DNS] and [ROLES] either
   expose or cause the exposure of email addresses that could be flooded
   by an attacker, for example; MX, NS, and other records found in the
   DNS advertise potential attack destinations; common DNS names such as
   "www" plainly identify the locations at which particular services can
   be found, providing destinations for targeted denial-of-service or
   penetration attacks.

   Thus, Domain Owners will need to harden these addresses against
   various attacks, including but not limited to:

   o  high-volume denial-of-service attacks;

   o  deliberate construction of malformed reports intended to identify
      or exploit parsing or processing vulnerabilities;




Kucherawy & Zwicky            Informational                    [Page 46]

RFC 7489                          DMARC                       March 2015


   o  deliberate construction of reports containing false claims for the
      Submitter or Reported-Domain fields, including the possibility of
      false data from compromised but known Mail Receivers.

12.3.  DNS Security

   The DMARC mechanism and its underlying technologies (SPF, DKIM)
   depend on the security of the DNS.  To reduce the risk of subversion
   of the DMARC mechanism due to DNS-based exploits, serious
   consideration should be given to the deployment of DNSSEC in parallel
   with the deployment of DMARC by both Domain Owners and Mail
   Receivers.

   Publication of data using DNSSEC is relevant to Domain Owners and
   third-party Report Receivers.  DNSSEC-aware resolution is relevant to
   Mail Receivers and Report Receivers.

12.4.  Display Name Attacks

   A common attack in messaging abuse is the presentation of false
   information in the display-name portion of the RFC5322.From field.
   For example, it is possible for the email address in that field to be
   an arbitrary address or domain name, while containing a well-known
   name (a person, brand, role, etc.) in the display name, intending to
   fool the end user into believing that the name is used legitimately.
   The attack is predicated on the notion that most common MUAs will
   show the display name and not the email address when both are
   available.

   Generally, display name attacks are out of scope for DMARC, as
   further exploration of possible defenses against these attacks needs
   to be undertaken.

   There are a few possible mechanisms that attempt mitigation of these
   attacks, such as the following:

   o  If the display name is found to include an email address (as
      specified in [MAIL]), execute the DMARC mechanism on the domain
      name found there rather than the domain name discovered
      originally.  However, this addresses only a very specific attack
      space, and spoofers can easily circumvent it by simply not using
      an email address in the display name.  There are also known cases
      of legitimate uses of an email address in the display name with a
      domain different from the one in the address portion, e.g.,

        From: "user@example.org via Bug Tracker" <support@example.com>





Kucherawy & Zwicky            Informational                    [Page 47]

RFC 7489                          DMARC                       March 2015


   o  In the MUA, only show the display name if the DMARC mechanism
      succeeds.  This too is easily defeated, as an attacker could
      arrange to pass the DMARC tests while fraudulently using another
      domain name in the display name.

   o  In the MUA, only show the display name if the DMARC mechanism
      passes and the email address thus validated matches one found in
      the receiving user's list of known addresses.

12.5.  External Reporting Addresses

   To avoid abuse by bad actors, reporting addresses generally have to
   be inside the domains about which reports are requested.  In order to
   accommodate special cases such as a need to get reports about domains
   that cannot actually receive mail, Section 7.1 describes a DNS-based
   mechanism for verifying approved external reporting.

   The obvious consideration here is an increased DNS load against
   domains that are claimed as external recipients.  Negative caching
   will mitigate this problem, but only to a limited extent, mostly
   dependent on the default TTL in the domain's SOA record.

   Where possible, external reporting is best achieved by having the
   report be directed to domains that can receive mail and simply having
   it automatically forwarded to the desired external destination.

   Note that the addresses shown in the "ruf" tag receive more
   information that might be considered private data, since it is
   possible for actual email content to appear in the failure reports.
   The URIs identified there are thus more attractive targets for
   intrusion attempts than those found in the "rua" tag.  Moreover,
   attacking the DNS of the subject domain to cause failure data to be
   routed fraudulently to an attacker's systems may be an attractive
   prospect.  Deployment of [DNSSEC] is advisable if this is a concern.

   The verification mechanism presented in Section 7.1 is currently not
   mandatory ("MUST") but strongly recommended ("SHOULD").  It is
   possible that it would be elevated to a "MUST" by later security
   review.

12.6.  Secure Protocols

   This document encourages use of secure transport mechanisms to
   prevent loss of private data to third parties that may be able to
   monitor such transmissions.  Unencrypted mechanisms should be
   avoided.





Kucherawy & Zwicky            Informational                    [Page 48]

RFC 7489                          DMARC                       March 2015


   In particular, a message that was originally encrypted or otherwise
   secured might appear in a report that is not sent securely, which
   could reveal private information.

13.  References

13.1.  Normative References

   [ABNF]     Crocker, D., Ed., and P. Overell, "Augmented BNF for
              Syntax Specifications: ABNF", STD 68, RFC 5234,
              January 2008, <http://www.rfc-editor.org/info/rfc5234>.

   [AFRF]     Fontana, H., "Authentication Failure Reporting Using the
              Abuse Reporting Format", RFC 6591, April 2012,
              <http://www.rfc-editor.org/info/rfc6591>.

   [AFRF-DKIM]
              Kucherawy, M., "Extensions to DomainKeys Identified Mail
              (DKIM) for Failure Reporting", RFC 6651, June 2012,
              <http://www.rfc-editor.org/info/rfc6651>.

   [AFRF-SPF] Kitterman, S., "Sender Policy Framework (SPF)
              Authentication Failure Reporting Using the Abuse Reporting
              Format", RFC 6652, June 2012,
              <http://www.rfc-editor.org/info/rfc6652>.

   [DKIM]     Crocker, D., Ed., Hansen, T., Ed., and M. Kucherawy, Ed.,
              "DomainKeys Identified Mail (DKIM) Signatures", STD 76,
              RFC 6376, September 2011, <http://www.rfc-editor.org/
              info/rfc6376>.

   [DNS]      Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, November 1987,
              <http://www.rfc-editor.org/info/rfc1035>.

   [DNS-CASE] Eastlake 3rd, D., "Domain Name System (DNS) Case
              Insensitivity Clarification", RFC 4343, January 2006,
              <http://www.rfc-editor.org/info/rfc4343>.

   [GZIP]     Levine, J., "The 'application/zlib' and 'application/gzip'
              Media Types", RFC 6713, August 2012,
              <http://www.rfc-editor.org/info/rfc6713>.

   [IDNA]     Klensin, J., "Internationalized Domain Names for
              Applications (IDNA): Definitions and Document Framework",
              RFC 5890, August 2010,
              <http://www.rfc-editor.org/info/rfc5890>.




Kucherawy & Zwicky            Informational                    [Page 49]

RFC 7489                          DMARC                       March 2015


   [KEYWORDS] Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997,
              <http://www.rfc-editor.org/info/rfc2119>.

   [MAIL]     Resnick, P., Ed., "Internet Message Format", RFC 5322,
              October 2008, <http://www.rfc-editor.org/info/rfc5322>.

   [MIME]     Freed, N. and N. Borenstein, "Multipurpose Internet Mail
              Extensions (MIME) Part One: Format of Internet Message
              Bodies", RFC 2045, November 1996,
              <http://www.rfc-editor.org/info/rfc2045>.

   [SEC-TERMS]
              Shirey, R., "Internet Security Glossary, Version 2",
              FYI 36, RFC 4949, August 2007,
              <http://www.rfc-editor.org/info/rfc4949>.

   [SMTP]     Klensin, J., "Simple Mail Transfer Protocol", RFC 5321,
              October 2008, <http://www.rfc-editor.org/info/rfc5321>.

   [SPF]      Kitterman, S., "Sender Policy Framework (SPF) for
              Authorizing Use of Domains in Email, Version 1", RFC 7208,
              April 2014, <http://www.rfc-editor.org/info/rfc7208>.

   [URI]      Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
              Resource Identifier (URI): Generic Syntax", STD 66,
              RFC 3986, January 2005,
              <http://www.rfc-editor.org/info/rfc3986>.

13.2.  Informative References

   [ADSP]     Allman, E., Fenton, J., Delany, M., and J. Levine,
              "DomainKeys Identified Mail (DKIM) Author Domain Signing
              Practices (ADSP)", RFC 5617, August 2009,
              <http://www.rfc-editor.org/info/rfc5617>.

   [ARF]      Shafranovich, Y., Levine, J., and M. Kucherawy, "An
              Extensible Format for Email Feedback Reports", RFC 5965,
              August 2010, <http://www.rfc-editor.org/info/rfc5965>.

   [AUTH-RESULTS]
              Kucherawy, M., "Message Header Field for Indicating
              Message Authentication Status", RFC 7001, September 2013,
              <http://www.rfc-editor.org/info/rfc7001>.







Kucherawy & Zwicky            Informational                    [Page 50]

RFC 7489                          DMARC                       March 2015


   [Best-Guess-SPF]
              Kitterman, S., "Sender Policy Framework: Best guess record
              (FAQ entry)", May 2010,
              <http://www.openspf.org/FAQ/Best_guess_record>.

   [DKIM-DEPLOYMENT]
              Hansen, T., Siegel, E., Hallam-Baker, P., and D. Crocker,
              "DomainKeys Identified Mail (DKIM) Development,
              Deployment, and Operations", RFC 5863, May 2010,
              <http://www.rfc-editor.org/info/rfc5863>.

   [DKIM-LISTS]
              Kucherawy, M., "DomainKeys Identified Mail (DKIM) and
              Mailing Lists", BCP 167, RFC 6377, September 2011,
              <http://www.rfc-editor.org/info/rfc6377>.

   [DKIM-OVERVIEW]
              Hansen, T., Crocker, D., and P. Hallam-Baker, "DomainKeys
              Identified Mail (DKIM) Service Overview", RFC 5585,
              July 2009, <http://www.rfc-editor.org/info/rfc5585>.

   [DKIM-THREATS]
              Fenton, J., "Analysis of Threats Motivating DomainKeys
              Identified Mail (DKIM)", RFC 4686, September 2006,
              <http://www.rfc-editor.org/info/rfc4686>.

   [DNSSEC]   Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, March 2005,
              <http://www.rfc-editor.org/info/rfc4033>.

   [DSN]      Moore, K. and G. Vaudreuil, "An Extensible Message Format
              for Delivery Status Notifications", RFC 3464,
              January 2003, <http://www.rfc-editor.org/info/rfc3464>.

   [EMAIL-ARCH]
              Crocker, D., "Internet Mail Architecture", RFC 5598,
              July 2009, <http://www.rfc-editor.org/info/rfc5598>.

   [IANA-CONSIDERATIONS]
              Narten, T. and H. Alvestrand, "Guidelines for Writing an
              IANA Considerations Section in RFCs", BCP 26, RFC 5226,
              May 2008, <http://www.rfc-editor.org/info/rfc5226>.

   [ROLES]    Crocker, D., "Mailbox Names for Common Services, Roles and
              Functions", RFC 2142, May 1997,
              <http://www.rfc-editor.org/info/rfc2142>.




Kucherawy & Zwicky            Informational                    [Page 51]

RFC 7489                          DMARC                       March 2015


Appendix A.  Technology Considerations

   This section documents some design decisions that were made in the
   development of DMARC.  Specifically, addressed here are some
   suggestions that were considered but not included in the design.
   This text is included to explain why they were considered and not
   included in this version.

A.1.  S/MIME

   S/MIME, or Secure Multipurpose Internet Mail Extensions, is a
   standard for encryption and signing of MIME data in a message.  This
   was suggested and considered as a third security protocol for
   authenticating the source of a message.

   DMARC is focused on authentication at the domain level (i.e., the
   Domain Owner taking responsibility for the message), while S/MIME is
   really intended for user-to-user authentication and encryption.  This
   alone appears to make it a bad fit for DMARC's goals.

   S/MIME also suffers from the heavyweight problem of Public Key
   Infrastructure, which means that distribution of keys used to verify
   signatures needs to be incorporated.  In many instances, this alone
   is a showstopper.  There have been consistent promises that PKI
   usability and deployment will improve, but these have yet to
   materialize.  DMARC can revisit this choice after those barriers are
   addressed.

   S/MIME has extensive deployment in specific market segments
   (government, for example) but does not enjoy similar widespread
   deployment over the general Internet, and this shows no signs of
   changing.  DKIM and SPF both are deployed widely over the general
   Internet, and their adoption rates continue to be positive.

   Finally, experiments have shown that including S/MIME support in the
   initial version of DMARC would neither cause nor enable a substantial
   increase in the accuracy of the overall mechanism.














Kucherawy & Zwicky            Informational                    [Page 52]

RFC 7489                          DMARC                       March 2015


A.2.  Method Exclusion

   It was suggested that DMARC include a mechanism by which a Domain
   Owner could tell Message Receivers not to attempt validation by one
   of the supported methods (e.g., "check DKIM, but not SPF").

   Specifically, consider a Domain Owner that has deployed one of the
   technologies, and that technology fails for some messages, but such
   failures don't cause enforcement action.  Deploying DMARC would cause
   enforcement action for policies other than "none", which would appear
   to exclude participation by that Domain Owner.

   The DMARC development team evaluated the idea of policy exception
   mechanisms on several occasions and invariably concluded that there
   was not a strong enough use case to include them.  The specific
   target audience for DMARC does not appear to have concerns about the
   failure modes of one or the other being a barrier to DMARC's
   adoption.

   In the scenario described above, the Domain Owner has a few options:

   1.  Tighten up its infrastructure to minimize the failure modes of
       the single deployed technology.

   2.  Deploy the other supported authentication mechanism, to offset
       the failure modes of the first.

   3.  Deploy DMARC in a reporting-only mode.

A.3.  Sender Header Field

   It has been suggested in several message authentication efforts that
   the Sender header field be checked for an identifier of interest, as
   the standards indicate this as the proper way to indicate a
   re-mailing of content such as through a mailing list.  Most recently,
   it was a protocol-level option for DomainKeys, but on evolution to
   DKIM, this property was removed.

   The DMARC development team considered this and decided not to include
   support for doing so, for the following reasons:

   1.  The main user protection approach is to be concerned with what
       the user sees when a message is rendered.  There is no consistent
       behavior among MUAs regarding what to do with the content of the
       Sender field, if present.  Accordingly, supporting checking of
       the Sender identifier would mean applying policy to an identifier





Kucherawy & Zwicky            Informational                    [Page 53]

RFC 7489                          DMARC                       March 2015


       the end user might never actually see, which can create a vector
       for attack against end users by simply forging a Sender field
       containing some identifier that DMARC will like.

   2.  Although it is certainly true that this is what the Sender field
       is for, its use in this way is also unreliable, making it a poor
       candidate for inclusion in the DMARC evaluation algorithm.

   3.  Allowing multiple ways to discover policy introduces unacceptable
       ambiguity into the DMARC evaluation algorithm in terms of which
       policy is to be applied and when.

A.4.  Domain Existence Test

   A common practice among MTA operators, and indeed one documented in
   [ADSP], is a test to determine domain existence prior to any more
   expensive processing.  This is typically done by querying the DNS for
   MX, A, or AAAA resource records for the name being evaluated and
   assuming that the domain is nonexistent if it could be determined
   that no such records were published for that domain name.

   The original pre-standardization version of this protocol included a
   mandatory check of this nature.  It was ultimately removed, as the
   method's error rate was too high without substantial manual tuning
   and heuristic work.  There are indeed use cases this work needs to
   address where such a method would return a negative result about a
   domain for which reporting is desired, such as a registered domain
   name that never sends legitimate mail and thus has none of these
   records present in the DNS.

A.5.  Issues with ADSP in Operation

   DMARC has been characterized as a "super-ADSP" of sorts.

   Contributors to DMARC have compiled a list of issues associated with
   ADSP, gained from operational experience, that have influenced the
   direction of DMARC:

   1.  ADSP has no support for subdomains, i.e., the ADSP record for
       example.com does not explicitly or implicitly apply to
       subdomain.example.com.  If wildcarding is not applied, then
       spammers can trivially bypass ADSP by sending from a subdomain
       with no ADSP record.








Kucherawy & Zwicky            Informational                    [Page 54]

RFC 7489                          DMARC                       March 2015


   2.  Nonexistent subdomains are explicitly out of scope in ADSP.
       There is nothing in ADSP that states receivers should simply
       reject mail from NXDOMAINs regardless of ADSP policy (which of
       course allows spammers to trivially bypass ADSP by sending email
       from nonexistent subdomains).

   3.  ADSP has no operational advice on when to look up the ADSP
       record.

   4.  ADSP has no support for using SPF as an auxiliary mechanism to
       DKIM.

   5.  ADSP has no support for a slow rollout, i.e., no way to configure
       a percentage of email on which the receiver should apply the
       policy.  This is important for large-volume senders.

   6.  ADSP has no explicit support for an intermediate phase where the
       receiver quarantines (e.g., sends to the recipient's "spam"
       folder) rather than rejects the email.

   7.  The binding between the "From" header domain and DKIM is too
       tight for ADSP; they must match exactly.

A.6.  Organizational Domain Discovery Issues

   Although protocols like ADSP are useful for "protecting" a specific
   domain name, they are not helpful at protecting subdomains.  If one
   wished to protect "example.com" by requiring via ADSP that all mail
   bearing an RFC5322.From domain of "example.com" be signed, this would
   "protect" that domain; however, one could then craft an email whose
   RFC5322.From domain is "security.example.com", and ADSP would not
   provide any protection.  One could use a DNS wildcard, but this can
   undesirably interfere with other DNS activity; one could add ADSP
   records as fraudulent domains are discovered, but this solution does
   not scale and is a purely reactive measure against abuse.

   The DNS does not provide a method by which the "domain of record", or
   the domain that was actually registered with a domain registrar, can
   be determined given an arbitrary domain name.  Suggestions have been
   made that attempt to glean such information from SOA or NS resource
   records, but these too are not fully reliable, as the partitioning of
   the DNS is not always done at administrative boundaries.

   When seeking domain-specific policy based on an arbitrary domain
   name, one could "climb the tree", dropping labels off the left end of
   the name until the root is reached or a policy is discovered, but
   then one could craft a name that has a large number of nonsense




Kucherawy & Zwicky            Informational                    [Page 55]

RFC 7489                          DMARC                       March 2015


   labels; this would cause a Mail Receiver to attempt a large number of
   queries in search of a policy record.  Sending many such messages
   constitutes an amplified denial-of-service attack.

   The Organizational Domain mechanism is a necessary component to the
   goals of DMARC.  The method described in Section 3.2 is far from
   perfect but serves this purpose reasonably well without adding undue
   burden or semantics to the DNS.  If a method is created to do so that
   is more reliable and secure than the use of a public suffix list,
   DMARC should be amended to use that method as soon as it is generally
   available.

A.6.1.  Public Suffix Lists

   A public suffix list for the purposes of determining the
   Organizational Domain can be obtained from various sources.  The most
   common one is maintained by the Mozilla Foundation and made public at
   <http://publicsuffix.org>.  License terms governing the use of that
   list are available at that URI.

   Note that if operators use a variety of public suffix lists,
   interoperability will be difficult or impossible to guarantee.

Appendix B.  Examples

   This section illustrates both the Domain Owner side and the Mail
   Receiver side of a DMARC exchange.

B.1.  Identifier Alignment Examples

   The following examples illustrate the DMARC mechanism's use of
   Identifier Alignment.  For brevity's sake, only message headers are
   shown, as message bodies are not considered when conducting DMARC
   checks.

B.1.1.  SPF

   The following SPF examples assume that SPF produces a passing result.

   Example 1: SPF in alignment:

        MAIL FROM: <sender@example.com>

        From: sender@example.com
        Date: Fri, Feb 15 2002 16:54:30 -0800
        To: receiver@example.org
        Subject: here's a sample




Kucherawy & Zwicky            Informational                    [Page 56]

RFC 7489                          DMARC                       March 2015


   In this case, the RFC5321.MailFrom parameter and the RFC5322.From
   field have identical DNS domains.  Thus, the identifiers are in
   alignment.

   Example 2: SPF in alignment (parent):

        MAIL FROM: <sender@child.example.com>

        From: sender@example.com
        Date: Fri, Feb 15 2002 16:54:30 -0800
        To: receiver@example.org
        Subject: here's a sample

   In this case, the RFC5322.From parameter includes a DNS domain that
   is a parent of the RFC5321.MailFrom domain.  Thus, the identifiers
   are in alignment if relaxed SPF mode is requested by the Domain
   Owner, and not in alignment if strict SPF mode is requested.

   Example 3: SPF not in alignment:

        MAIL FROM: <sender@example.net>

        From: sender@child.example.com
        Date: Fri, Feb 15 2002 16:54:30 -0800
        To: receiver@example.org
        Subject: here's a sample

   In this case, the RFC5321.MailFrom parameter includes a DNS domain
   that is neither the same as nor a parent of the RFC5322.From domain.
   Thus, the identifiers are not in alignment.

B.1.2.  DKIM

   The examples below assume that the DKIM signatures pass verification.
   Alignment cannot exist with a DKIM signature that does not verify.

   Example 1: DKIM in alignment:

        DKIM-Signature: v=1; ...; d=example.com; ...
        From: sender@example.com
        Date: Fri, Feb 15 2002 16:54:30 -0800
        To: receiver@example.org
        Subject: here's a sample

   In this case, the DKIM "d=" parameter and the RFC5322.From field have
   identical DNS domains.  Thus, the identifiers are in alignment.





Kucherawy & Zwicky            Informational                    [Page 57]

RFC 7489                          DMARC                       March 2015


   Example 2: DKIM in alignment (parent):

        DKIM-Signature: v=1; ...; d=example.com; ...
        From: sender@child.example.com
        Date: Fri, Feb 15 2002 16:54:30 -0800
        To: receiver@example.org
        Subject: here's a sample

   In this case, the DKIM signature's "d=" parameter includes a DNS
   domain that is a parent of the RFC5322.From domain.  Thus, the
   identifiers are in alignment for relaxed mode, but not for strict
   mode.

   Example 3: DKIM not in alignment:

        DKIM-Signature: v=1; ...; d=sample.net; ...
        From: sender@child.example.com
        Date: Fri, Feb 15 2002 16:54:30 -0800
        To: receiver@example.org
        Subject: here's a sample

   In this case, the DKIM signature's "d=" parameter includes a DNS
   domain that is neither the same as nor a parent of the RFC5322.From
   domain.  Thus, the identifiers are not in alignment.

B.2.  Domain Owner Example

   A Domain Owner that wants to use DMARC should have already deployed
   and tested SPF and DKIM.  The next step is to publish a DNS record
   that advertises a DMARC policy for the Domain Owner's Organizational
   Domain.

B.2.1.  Entire Domain, Monitoring Only

   The owner of the domain "example.com" has deployed SPF and DKIM on
   its messaging infrastructure.  The owner wishes to begin using DMARC
   with a policy that will solicit aggregate feedback from receivers
   without affecting how the messages are processed, in order to:

   o  Confirm that its legitimate messages are authenticating correctly

   o  Verify that all authorized message sources have implemented
      authentication measures

   o  Determine how many messages from other sources would be affected
      by a blocking policy





Kucherawy & Zwicky            Informational                    [Page 58]

RFC 7489                          DMARC                       March 2015


   The Domain Owner accomplishes this by constructing a policy record
   indicating that:

   o  The version of DMARC being used is "DMARC1" ("v=DMARC1")

   o  Receivers should not alter how they treat these messages because
      of this DMARC policy record ("p=none")

   o  Aggregate feedback reports should be sent via email to the address
      "dmarc-feedback@example.com"
      ("rua=mailto:dmarc-feedback@example.com")

   o  All messages from this Organizational Domain are subject to this
      policy (no "pct" tag present, so the default of 100% applies)

   The DMARC policy record might look like this when retrieved using a
   common command-line tool:

     % dig +short TXT _dmarc.example.com.
     "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com"

   To publish such a record, the DNS administrator for the Domain Owner
   creates an entry like the following in the appropriate zone file
   (following the conventional zone file format):

     ; DMARC record for the domain example.com

     _dmarc  IN TXT ( "v=DMARC1; p=none; "
                      "rua=mailto:dmarc-feedback@example.com" )

B.2.2.  Entire Domain, Monitoring Only, Per-Message Reports

   The Domain Owner from the previous example has used the aggregate
   reporting to discover some messaging systems that had not yet
   implemented DKIM correctly, but they are still seeing periodic
   authentication failures.  In order to diagnose these intermittent
   problems, they wish to request per-message failure reports when
   authentication failures occur.

   Not all Receivers will honor such a request, but the Domain Owner
   feels that any reports it does receive will be helpful enough to
   justify publishing this record.  The default per-message report
   format ([AFRF]) meets the Domain Owner's needs in this scenario.








Kucherawy & Zwicky            Informational                    [Page 59]

RFC 7489                          DMARC                       March 2015


   The Domain Owner accomplishes this by adding the following to its
   policy record from Appendix B.2:

   o  Per-message failure reports should be sent via email to the
      address "auth-reports@example.com"
      ("ruf=mailto:auth-reports@example.com")

   The DMARC policy record might look like this when retrieved using a
   common command-line tool (the output shown would appear on a single
   line but is wrapped here for publication):

     % dig +short TXT _dmarc.example.com.
     "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com;
      ruf=mailto:auth-reports@example.com"

   To publish such a record, the DNS administrator for the Domain Owner
   might create an entry like the following in the appropriate zone file
   (following the conventional zone file format):

    ; DMARC record for the domain example.com

    _dmarc  IN TXT ( "v=DMARC1; p=none; "
                     "rua=mailto:dmarc-feedback@example.com; "
                     "ruf=mailto:auth-reports@example.com" )

B.2.3.  Per-Message Failure Reports Directed to Third Party

   The Domain Owner from the previous example is maintaining the same
   policy but now wishes to have a third party receive and process the
   per-message failure reports.  Again, not all Receivers will honor
   this request, but those that do may implement additional checks to
   validate that the third party wishes to receive the failure reports
   for this domain.

   The Domain Owner needs to alter its policy record from Appendix B.2.2
   as follows:

   o  Per-message failure reports should be sent via email to the
      address "auth-reports@thirdparty.example.net"
      ("ruf=mailto:auth-reports@thirdparty.example.net")

   The DMARC policy record might look like this when retrieved using a
   common command-line tool (the output shown would appear on a single
   line but is wrapped here for publication):

     % dig +short TXT _dmarc.example.com.
     "v=DMARC1; p=none; rua=mailto:dmarc-feedback@example.com;
      ruf=mailto:auth-reports@thirdparty.example.net"



Kucherawy & Zwicky            Informational                    [Page 60]

RFC 7489                          DMARC                       March 2015


   To publish such a record, the DNS administrator for the Domain Owner
   might create an entry like the following in the appropriate zone file
   (following the conventional zone file format):

     ; DMARC record for the domain example.com

     _dmarc IN TXT ( "v=DMARC1; p=none; "
                     "rua=mailto:dmarc-feedback@example.com; "
                     "ruf=mailto:auth-reports@thirdparty.example.net" )

   Because the address used in the "ruf" tag is outside the
   Organizational Domain in which this record is published, conforming
   Receivers will implement additional checks as described in
   Section 7.1 of this document.  In order to pass these additional
   checks, the third party will need to publish an additional DNS record
   as follows:

   o  Given the DMARC record published by the Domain Owner at
      "_dmarc.example.com", the DNS administrator for the third party
      will need to publish a TXT resource record at
      "example.com._report._dmarc.thirdparty.example.net" with the value
      "v=DMARC1".

   The resulting DNS record might look like this when retrieved using a
   common command-line tool (the output shown would appear on a single
   line but is wrapped here for publication):

     % dig +short TXT example.com._report._dmarc.thirdparty.example.net
     "v=DMARC1"

   To publish such a record, the DNS administrator for example.net might
   create an entry like the following in the appropriate zone file
   (following the conventional zone file format):

     ; zone file for thirdparty.example.net
     ; Accept DMARC failure reports on behalf of example.com

     example.com._report._dmarc   IN   TXT    "v=DMARC1"

   Intermediaries and other third parties should refer to Section 7.1
   for the full details of this mechanism.

B.2.4.  Subdomain, Sampling, and Multiple Aggregate Report URIs

   The Domain Owner has implemented SPF and DKIM in a subdomain used for
   pre-production testing of messaging services.  It now wishes to
   request that participating receivers act to reject messages from this
   subdomain that fail to authenticate.



Kucherawy & Zwicky            Informational                    [Page 61]

RFC 7489                          DMARC                       March 2015


   As a first step, it will ask that a portion (1/4 in this example) of
   failing messages be quarantined, enabling examination of messages
   sent to mailboxes hosted by participating receivers.  Aggregate
   feedback reports will be sent to a mailbox within the Organizational
   Domain, and to a mailbox at a third party selected and authorized to
   receive same by the Domain Owner.  Aggregate reports sent to the
   third party are limited to a maximum size of ten megabytes.

   The Domain Owner will accomplish this by constructing a policy record
   indicating that:

   o  The version of DMARC being used is "DMARC1" ("v=DMARC1")

   o  It is applied only to this subdomain (record is published at
      "_dmarc.test.example.com" and not "_dmarc.example.com")

   o  Receivers should quarantine messages from this Organizational
      Domain that fail to authenticate ("p=quarantine")

   o  Aggregate feedback reports should be sent via email to the
      addresses "dmarc-feedback@example.com" and
      "example-tld-test@thirdparty.example.net", with the latter
      subjected to a maximum size limit ("rua=mailto:dmarc-feedback@
      example.com,mailto:tld-test@thirdparty.example.net!10m")

   o  25% of messages from this Organizational Domain are subject to
      action based on this policy ("pct=25")

   The DMARC policy record might look like this when retrieved using a
   common command-line tool (the output shown would appear on a single
   line but is wrapped here for publication):

     % dig +short TXT _dmarc.test.example.com
     "v=DMARC1; p=quarantine; rua=mailto:dmarc-feedback@example.com,
      mailto:tld-test@thirdparty.example.net!10m; pct=25"

   To publish such a record, the DNS administrator for the Domain Owner
   might create an entry like the following in the appropriate zone
   file:

     ; DMARC record for the domain example.com

     _dmarc IN  TXT  ( "v=DMARC1; p=quarantine; "
                       "rua=mailto:dmarc-feedback@example.com,"
                       "mailto:tld-test@thirdparty.example.net!10m; "
                       "pct=25" )





Kucherawy & Zwicky            Informational                    [Page 62]

RFC 7489                          DMARC                       March 2015


B.3.  Mail Receiver Example

   A Mail Receiver that wants to use DMARC should already be checking
   SPF and DKIM, and possess the ability to collect relevant information
   from various email-processing stages to provide feedback to Domain
   Owners (possibly via Report Receivers).

B.3.1.  Processing of SMTP Time

   An optimal DMARC-enabled Mail Receiver performs authentication and
   Identifier Alignment checking during the [SMTP] conversation.

   Prior to returning a final reply to the DATA command, the Mail
   Receiver's MTA has performed:

   1.  An SPF check to determine an SPF-authenticated Identifier.

   2.  DKIM checks that yield one or more DKIM-authenticated
       Identifiers.

   3.  A DMARC policy lookup.

   The presence of an Author Domain DMARC record indicates that the Mail
   Receiver should continue with DMARC-specific processing before
   returning a reply to the DATA command.

   Given a DMARC record and the set of Authenticated Identifiers, the
   Mail Receiver checks to see if the Authenticated Identifiers align
   with the Author Domain (taking into consideration any strict versus
   relaxed options found in the DMARC record).

   For example, the following sample data is considered to be from a
   piece of email originating from the Domain Owner of "example.com":

     Author Domain: example.com
     SPF-authenticated Identifier: mail.example.com
     DKIM-authenticated Identifier: example.com
     DMARC record:
       "v=DMARC1; p=reject; aspf=r;
        rua=mailto:dmarc-feedback@example.com"

   In the above sample, both the SPF-authenticated Identifier and the
   DKIM-authenticated Identifier align with the Author Domain.  The Mail
   Receiver considers the above email to pass the DMARC check, avoiding
   the "reject" policy that is to be applied to email that fails to pass
   the DMARC check.





Kucherawy & Zwicky            Informational                    [Page 63]

RFC 7489                          DMARC                       March 2015


   If no Authenticated Identifiers align with the Author Domain, then
   the Mail Receiver applies the DMARC-record-specified policy.
   However, before this action is taken, the Mail Receiver can consult
   external information to override the Domain Owner's policy.  For
   example, if the Mail Receiver knows that this particular email came
   from a known and trusted forwarder (that happens to break both SPF
   and DKIM), then the Mail Receiver may choose to ignore the Domain
   Owner's policy.

   The Mail Receiver is now ready to reply to the DATA command.  If the
   DMARC check yields that the message is to be rejected, then the Mail
   Receiver replies with a 5xy code to inform the sender of failure.  If
   the DMARC check cannot be resolved due to transient network errors,
   then the Mail Receiver replies with a 4xy code to inform the sender
   as to the need to reattempt delivery later.  If the DMARC check
   yields a passing message, then the Mail Receiver continues on with
   email processing, perhaps using the result of the DMARC check as an
   input to additional processing modules such as a domain reputation
   query.

   Before exiting DMARC-specific processing, the Mail Receiver checks to
   see if the Author Domain DMARC record requests AFRF-based reporting.
   If so, then the Mail Receiver can emit an AFRF to the reporting
   address supplied in the DMARC record.

   At the exit of DMARC-specific processing, the Mail Receiver captures
   (through logging or direct insertion into a data store) the result of
   DMARC processing.  Captured information is used to build feedback for
   Domain Owner consumption.  This is not necessary if the Domain Owner
   has not requested aggregate reports, i.e., no "rua" tag was found in
   the policy record.

B.4.  Utilization of Aggregate Feedback: Example

   Aggregate feedback is consumed by Domain Owners to verify a Domain
   Owner's understanding of how the Domain Owner's domain is being
   processed by the Mail Receiver.  Aggregate reporting data on emails
   that pass all DMARC-supporting authentication checks is used by
   Domain Owners to verify that authentication practices remain
   accurate.  For example, if a third party is sending on behalf of a
   Domain Owner, the Domain Owner can use aggregate report data to
   verify ongoing authentication practices of the third party.









Kucherawy & Zwicky            Informational                    [Page 64]

RFC 7489                          DMARC                       March 2015


   Data on email that only partially passes underlying authentication
   checks provides visibility into problems that need to be addressed by
   the Domain Owner.  For example, if either SPF or DKIM fails to pass,
   the Domain Owner is provided with enough information to either
   directly correct the problem or understand where authentication-
   breaking changes are being introduced in the email transmission path.
   If authentication-breaking changes due to email transmission path
   cannot be directly corrected, then the Domain Owner at least
   maintains an understanding of the effect of DMARC-based policies upon
   the Domain Owner's email.

   Data on email that fails all underlying authentication checks
   provides baseline visibility on how the Domain Owner's domain is
   being received at the Mail Receiver.  Based on this visibility, the
   Domain Owner can begin deployment of authentication technologies
   across uncovered email sources.  Additionally, the Domain Owner may
   come to an understanding of how its domain is being misused.

B.5.  mailto Transport Example

   A DMARC record can contain a "mailto" reporting address, such as:

     mailto:dmarc-feedback@example.com

   A sample aggregate report from the Mail Receiver at
   mail.receiver.example follows:

     DKIM-Signature: v=1; ...; d=mail.receiver.example; ...
     From: dmarc-reporting@mail.receiver.example
     Date: Fri, Feb 15 2002 16:54:30 -0800
     To: dmarc-feedback@example.com
     Subject: Report Domain: example.com
         Submitter: mail.receiver.example
         Report-ID: <2002.02.15.1>
     MIME-Version: 1.0
     Content-Type: multipart/alternative;
         boundary="----=_NextPart_000_024E_01CC9B0A.AFE54C00"
     Content-Language: en-us

     This is a multipart message in MIME format.

     ------=_NextPart_000_024E_01CC9B0A.AFE54C00
     Content-Type: text/plain; charset="us-ascii"
     Content-Transfer-Encoding: 7bit







Kucherawy & Zwicky            Informational                    [Page 65]

RFC 7489                          DMARC                       March 2015


     This is an aggregate report from mail.receiver.example.

     ------=_NextPart_000_024E_01CC9B0A.AFE54C00
     Content-Type: application/gzip
     Content-Transfer-Encoding: base64
     Content-Disposition: attachment;
         filename="mail.receiver.example!example.com!
                   1013662812!1013749130.gz"

     <gzipped content of report>

     ------=_NextPart_000_024E_01CC9B0A.AFE54C00--

   Not shown in the above example is that the Mail Receiver's feedback
   should be authenticated using SPF.  Also, the value of the "filename"
   MIME parameter is wrapped for printing in this specification but
   would normally appear as one continuous string.

Appendix C.  DMARC XML Schema

   The following is the proposed initial schema for producing
   XML-formatted aggregate reports as described in this document.

   NOTE: Per the definition of XML, unless otherwise specified in the
   schema below, the minOccurs and maxOccurs values for each element are
   set to 1.

   <?xml version="1.0"?>
   <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"
     targetNamespace="http://dmarc.org/dmarc-xml/0.1">

   <!-- The time range in UTC covered by messages in this report,
        specified in seconds since epoch. -->
   <xs:complexType name="DateRangeType">
     <xs:all>
       <xs:element name="begin" type="xs:integer"/>
       <xs:element name="end" type="xs:integer"/>
     </xs:all>
   </xs:complexType>

   <!-- Report generator metadata. -->
   <xs:complexType name="ReportMetadataType">
     <xs:sequence>
       <xs:element name="org_name" type="xs:string"/>
       <xs:element name="email" type="xs:string"/>
       <xs:element name="extra_contact_info" type="xs:string"
                   minOccurs="0"/>
       <xs:element name="report_id" type="xs:string"/>



Kucherawy & Zwicky            Informational                    [Page 66]

RFC 7489                          DMARC                       March 2015


       <xs:element name="date_range" type="DateRangeType"/>
       <xs:element name="error" type="xs:string" minOccurs="0"
                   maxOccurs="unbounded"/>
     </xs:sequence>
   </xs:complexType>

   <!-- Alignment mode (relaxed or strict) for DKIM and SPF. -->
   <xs:simpleType name="AlignmentType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="r"/>
       <xs:enumeration value="s"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- The policy actions specified by p and sp in the
        DMARC record. -->
   <xs:simpleType name="DispositionType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="none"/>
       <xs:enumeration value="quarantine"/>
       <xs:enumeration value="reject"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- The DMARC policy that applied to the messages in
        this report. -->
   <xs:complexType name="PolicyPublishedType">
     <xs:all>
       <!-- The domain at which the DMARC record was found. -->
       <xs:element name="domain" type="xs:string"/>
       <!-- The DKIM alignment mode. -->
       <xs:element name="adkim" type="AlignmentType"
                   minOccurs="0"/>
       <!-- The SPF alignment mode. -->
       <xs:element name="aspf" type="AlignmentType"
                   minOccurs="0"/>
       <!-- The policy to apply to messages from the domain. -->
       <xs:element name="p" type="DispositionType"/>
       <!-- The policy to apply to messages from subdomains. -->
       <xs:element name="sp" type="DispositionType"/>
       <!-- The percent of messages to which policy applies. -->
       <xs:element name="pct" type="xs:integer"/>
       <!-- Failure reporting options in effect. -->
       <xs:element name="fo" type="xs:string"/>
     </xs:all>
   </xs:complexType>





Kucherawy & Zwicky            Informational                    [Page 67]

RFC 7489                          DMARC                       March 2015


   <!-- The DMARC-aligned authentication result. -->
   <xs:simpleType name="DMARCResultType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="pass"/>
       <xs:enumeration value="fail"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- Reasons that may affect DMARC disposition or execution
        thereof. -->
   <xs:simpleType name="PolicyOverrideType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="forwarded"/>
       <xs:enumeration value="sampled_out"/>
       <xs:enumeration value="trusted_forwarder"/>
       <xs:enumeration value="mailing_list"/>
       <xs:enumeration value="local_policy"/>
       <xs:enumeration value="other"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- How do we allow report generators to include new
        classes of override reasons if they want to be more
        specific than "other"? -->
   <xs:complexType name="PolicyOverrideReason">
     <xs:all>
       <xs:element name="type" type="PolicyOverrideType"/>
       <xs:element name="comment" type="xs:string"
                   minOccurs="0"/>
     </xs:all>
   </xs:complexType>

   <!-- Taking into account everything else in the record,
        the results of applying DMARC. -->
   <xs:complexType name="PolicyEvaluatedType">
     <xs:sequence>
       <xs:element name="disposition" type="DispositionType"/>
       <xs:element name="dkim" type="DMARCResultType"/>
       <xs:element name="spf" type="DMARCResultType"/>
       <xs:element name="reason" type="PolicyOverrideReason"
                   minOccurs="0" maxOccurs="unbounded"/>
     </xs:sequence>
   </xs:complexType>








Kucherawy & Zwicky            Informational                    [Page 68]

RFC 7489                          DMARC                       March 2015


   <!-- Credit to Roger L. Costello for IPv4 regex
        http://mailman.ic.ac.uk/pipermail/xml-dev/1999-December/
             018018.html -->
   <!-- Credit to java2s.com for IPv6 regex
        http://www.java2s.com/Code/XML/XML-Schema/
             IPv6addressesareeasiertodescribeusingasimpleregex.htm -->
   <xs:simpleType name="IPAddress">
     <xs:restriction base="xs:string">
       <xs:pattern value="((1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5]).){3}
                   (1?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])|
                   ([A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"/>
     </xs:restriction>
   </xs:simpleType>

   <xs:complexType name="RowType">
     <xs:all>
       <!-- The connecting IP. -->
       <xs:element name="source_ip" type="IPAddress"/>
       <!-- The number of matching messages. -->
       <xs:element name="count" type="xs:integer"/>
       <!-- The DMARC disposition applying to matching
            messages. -->
       <xs:element name="policy_evaluated"
                   type="PolicyEvaluatedType"
                   minOccurs="1"/>
     </xs:all>
   </xs:complexType>

   <xs:complexType name="IdentifierType">
     <xs:all>
       <!-- The envelope recipient domain. -->
       <xs:element name="envelope_to" type="xs:string"
                   minOccurs="0"/>
       <!-- The RFC5321.MailFrom domain. -->
       <xs:element name="envelope_from" type="xs:string"
                   minOccurs="1"/>
       <!-- The RFC5322.From domain. -->
       <xs:element name="header_from" type="xs:string"
                   minOccurs="1"/>
     </xs:all>
   </xs:complexType>

   <!-- DKIM verification result, according to RFC 7001
        Section 2.6.1. -->
   <xs:simpleType name="DKIMResultType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="none"/>
       <xs:enumeration value="pass"/>



Kucherawy & Zwicky            Informational                    [Page 69]

RFC 7489                          DMARC                       March 2015


       <xs:enumeration value="fail"/>
       <xs:enumeration value="policy"/>
       <xs:enumeration value="neutral"/>
       <xs:enumeration value="temperror"/>
       <xs:enumeration value="permerror"/>
     </xs:restriction>
   </xs:simpleType>

   <xs:complexType name="DKIMAuthResultType">
     <xs:all>
       <!-- The "d=" parameter in the signature. -->
       <xs:element name="domain" type="xs:string"
                   minOccurs="1"/>
       <!-- The "s=" parameter in the signature. -->
       <xs:element name="selector" type="xs:string"
                   minOccurs="0"/>
       <!-- The DKIM verification result. -->
       <xs:element name="result" type="DKIMResultType"
                   minOccurs="1"/>
       <!-- Any extra information (e.g., from
            Authentication-Results). -->
       <xs:element name="human_result" type="xs:string"
                   minOccurs="0"/>
     </xs:all>
   </xs:complexType>

   <!-- SPF domain scope. -->
   <xs:simpleType name="SPFDomainScope">
     <xs:restriction base="xs:string">
       <xs:enumeration value="helo"/>
       <xs:enumeration value="mfrom"/>
     </xs:restriction>
   </xs:simpleType>

   <!-- SPF result. -->
   <xs:simpleType name="SPFResultType">
     <xs:restriction base="xs:string">
       <xs:enumeration value="none"/>
       <xs:enumeration value="neutral"/>
       <xs:enumeration value="pass"/>
       <xs:enumeration value="fail"/>
       <xs:enumeration value="softfail"/>
       <!-- "TempError" commonly implemented as "unknown". -->
       <xs:enumeration value="temperror"/>
       <!-- "PermError" commonly implemented as "error". -->
       <xs:enumeration value="permerror"/>
     </xs:restriction>
   </xs:simpleType>



Kucherawy & Zwicky            Informational                    [Page 70]

RFC 7489                          DMARC                       March 2015


   <xs:complexType name="SPFAuthResultType">
     <xs:all>
       <!-- The checked domain. -->
       <xs:element name="domain" type="xs:string" minOccurs="1"/>
       <!-- The scope of the checked domain. -->
       <xs:element name="scope" type="SPFDomainScope" minOccurs="1"/>
       <!-- The SPF verification result. -->
       <xs:element name="result" type="SPFResultType"
                   minOccurs="1"/>
     </xs:all>
   </xs:complexType>

   <!-- This element contains DKIM and SPF results, uninterpreted
        with respect to DMARC. -->
   <xs:complexType name="AuthResultType">
     <xs:sequence>
       <!-- There may be no DKIM signatures, or multiple DKIM
            signatures. -->
       <xs:element name="dkim" type="DKIMAuthResultType"
         minOccurs="0" maxOccurs="unbounded"/>
       <!-- There will always be at least one SPF result. -->
       <xs:element name="spf" type="SPFAuthResultType" minOccurs="1"
                   maxOccurs="unbounded"/>
     </xs:sequence>
   </xs:complexType>

   <!-- This element contains all the authentication results that
        were evaluated by the receiving system for the given set of
        messages. -->
   <xs:complexType name="RecordType">
     <xs:sequence>
       <xs:element name="row" type="RowType"/>
       <xs:element name="identifiers" type="IdentifierType"/>
       <xs:element name="auth_results" type="AuthResultType"/>
     </xs:sequence>
   </xs:complexType>

   <!-- Parent -->
   <xs:element name="feedback">
     <xs:complexType>
       <xs:sequence>
         <xs:element name="version"
                     type="xs:decimal"/>
         <xs:element name="report_metadata"
                     type="ReportMetadataType"/>
         <xs:element name="policy_published"
                     type="PolicyPublishedType"/>




Kucherawy & Zwicky            Informational                    [Page 71]

RFC 7489                          DMARC                       March 2015


         <xs:element name="record" type="RecordType"
                     maxOccurs="unbounded"/>
       </xs:sequence>
     </xs:complexType>
   </xs:element>
   </xs:schema>

   Descriptions of the PolicyOverrideTypes:

   forwarded:  The message was relayed via a known forwarder, or local
      heuristics identified the message as likely having been forwarded.
      There is no expectation that authentication would pass.

   local_policy:  The Mail Receiver's local policy exempted the message
      from being subjected to the Domain Owner's requested policy
      action.

   mailing_list:  Local heuristics determined that the message arrived
      via a mailing list, and thus authentication of the original
      message was not expected to succeed.

   other:  Some policy exception not covered by the other entries in
      this list occurred.  Additional detail can be found in the
      PolicyOverrideReason's "comment" field.

   sampled_out:  The message was exempted from application of policy by
      the "pct" setting in the DMARC policy record.

   trusted_forwarder:  Message authentication failure was anticipated by
      other evidence linking the message to a locally maintained list of
      known and trusted forwarders.

   The "version" for reports generated per this specification MUST be
   the value 1.0.

















Kucherawy & Zwicky            Informational                    [Page 72]

RFC 7489                          DMARC                       March 2015


Acknowledgements

   DMARC and the draft version of this document submitted to the
   Independent Submission Editor were the result of lengthy efforts by
   an informal industry consortium: DMARC.org (see <http://dmarc.org>).
   Participating companies included Agari, American Greetings, AOL, Bank
   of America, Cloudmark, Comcast, Facebook, Fidelity Investments,
   Google, JPMorgan Chase & Company, LinkedIn, Microsoft, Netease,
   PayPal, ReturnPath, The Trusted Domain Project, and Yahoo!.  Although
   the contributors and supporters are too numerous to mention, notable
   individual contributions were made by J. Trent Adams, Michael Adkins,
   Monica Chew, Dave Crocker, Tim Draegen, Steve Jones, Franck Martin,
   Brett McDowell, and Paul Midgen.  The contributors would also like to
   recognize the invaluable input and guidance that was provided early
   on by J.D. Falk.

   Additional contributions within the IETF context were made by Kurt
   Anderson, Michael Jack Assels, Les Barstow, Anne Bennett, Jim Fenton,
   J. Gomez, Mike Jones, Scott Kitterman, Eliot Lear, John Levine,
   S. Moonesamy, Rolf Sonneveld, Henry Timmes, and Stephen J. Turnbull.

Authors' Addresses

   Murray S. Kucherawy (editor)

   EMail: superuser@gmail.com


   Elizabeth Zwicky (editor)
   Yahoo!

   EMail: zwicky@yahoo-inc.com



















Kucherawy & Zwicky            Informational                    [Page 73]


```

---

# RFC 6698 — DANE — TLSA (base)

```






Internet Engineering Task Force (IETF)                        P. Hoffman
Request for Comments: 6698                                VPN Consortium
Category: Standards Track                                    J. Schlyter
ISSN: 2070-1721                                                 Kirei AB
                                                             August 2012


         The DNS-Based Authentication of Named Entities (DANE)
             Transport Layer Security (TLS) Protocol: TLSA

Abstract

   Encrypted communication on the Internet often uses Transport Layer
   Security (TLS), which depends on third parties to certify the keys
   used.  This document improves on that situation by enabling the
   administrators of domain names to specify the keys used in that
   domain's TLS servers.  This requires matching improvements in TLS
   client software, but no change in TLS server software.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 5741.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc6698.

Copyright Notice

   Copyright (c) 2012 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.




Hoffman & Schlyter           Standards Track                    [Page 1]

RFC 6698            DNS-Based Authentication for TLS         August 2012


Table of Contents

   1. Introduction ....................................................3
      1.1. Background and Motivation ..................................3
      1.2. Securing the Association of a Domain Name with a
           Server's Certificate .......................................4
      1.3. Method for Securing Certificate Associations ...............5
      1.4. Terminology ................................................6
   2. The TLSA Resource Record ........................................7
      2.1. TLSA RDATA Wire Format .....................................7
           2.1.1. The Certificate Usage Field .........................7
           2.1.2. The Selector Field ..................................8
           2.1.3. The Matching Type Field .............................9
           2.1.4. The Certificate Association Data Field ..............9
      2.2. TLSA RR Presentation Format ................................9
      2.3. TLSA RR Examples ..........................................10
   3. Domain Names for TLSA Certificate Associations .................10
   4. Use of TLSA Records in TLS .....................................11
      4.1. Usable Certificate Associations ...........................11
   5. TLSA and DANE Use Cases and Requirements .......................13
   6. Mandatory-to-Implement Features ................................15
   7. IANA Considerations ............................................15
      7.1. TLSA RRtype ...............................................15
      7.2. TLSA Certificate Usages ...................................15
      7.3. TLSA Selectors ............................................16
      7.4. TLSA Matching Types .......................................16
   8. Security Considerations ........................................16
      8.1. Comparing DANE to Public CAs ..............................18
           8.1.1. Risk of Key Compromise .............................19
           8.1.2. Impact of Key Compromise ...........................20
           8.1.3. Detection of Key Compromise ........................20
           8.1.4. Spoofing Hostnames .................................20
      8.2. DNS Caching ...............................................21
      8.3. External DNSSEC Validators ................................21
   9. Acknowledgements ...............................................22
   10. References ....................................................22
      10.1. Normative References .....................................22
      10.2. Informative References ...................................23
   Appendix A. Operational Considerations for Deploying TLSA
               Records ...............................................25
     A.1. Creating TLSA Records ......................................25
       A.1.1. Ambiguities and Corner Cases When TLS Clients
              Build Trust Chains .....................................26
       A.1.2. Choosing a Selector Type ...............................26
     A.2. Provisioning TLSA Records in DNS ...........................28
       A.2.1. Provisioning TLSA Records with Aliases .................28
     A.3. Securing the Last Hop ......................................30
     A.4. Handling Certificate Rollover ..............................31



Hoffman & Schlyter           Standards Track                    [Page 2]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   Appendix B. Pseudocode for Using TLSA .............................32
     B.1. Helper Functions ...........................................32
     B.2. Main TLSA Pseudocode .......................................33
   Appendix C. Examples ..............................................35

1.  Introduction

1.1.  Background and Motivation

   Applications that communicate over the Internet often need to prevent
   eavesdropping, tampering, or forgery of their communications.  The
   Transport Layer Security (TLS) protocol provides this kind of
   communications security over the Internet, using channel encryption.

   The security properties of encryption systems depend strongly on the
   keys that they use.  If secret keys are revealed, or if public keys
   can be replaced by fake keys (that is, a key not corresponding to the
   entity identified in the certificate), these systems provide little
   or no security.

   TLS uses certificates to bind keys and names.  A certificate combines
   a published key with other information such as the name of the
   service that uses the key, and this combination is digitally signed
   by another key.  Having a key in a certificate is only helpful if one
   trusts the other key that signed the certificate.  If that other key
   was itself revealed or substituted, then its signature is worthless
   in proving anything about the first key.

   On the Internet, this problem has been solved for years by entities
   called "Certification Authorities" (CAs).  CAs protect their secret
   key vigorously, while supplying their public key to the software
   vendors who build TLS clients.  They then sign certificates, and
   supply those to TLS servers.  TLS client software uses a set of these
   CA keys as "trust anchors" to validate the signatures on certificates
   that the client receives from TLS servers.  Client software typically
   allows any CA to usefully sign any other certificate.

   The public CA model upon which TLS has depended is fundamentally
   vulnerable because it allows any of these CAs to issue a certificate
   for any domain name.  A single trusted CA that betrays its trust,
   either voluntarily or by providing less-than-vigorous protection for
   its secrets and capabilities, can undermine the security offered by
   any certificates employed with TLS.  This problem arises because a
   compromised CA can issue a replacement certificate that contains a
   fake key.  Recent experiences with compromises of CAs or their
   trusted partners have led to very serious security problems, such as
   the governments of multiple countries attempting to wiretap and/or
   subvert major TLS-protected web sites trusted by millions of users.



Hoffman & Schlyter           Standards Track                    [Page 3]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   The DNS Security Extensions (DNSSEC) provide a similar model that
   involves trusted keys signing the information for untrusted keys.
   However, DNSSEC provides three significant improvements.  Keys are
   tied to names in the Domain Name System (DNS), rather than to
   arbitrary identifying strings; this is more convenient for Internet
   protocols.  Signed keys for any domain are accessible online through
   a straightforward query using the standard DNSSEC protocol, so there
   is no problem distributing the signed keys.  Most significantly, the
   keys associated with a domain name can only be signed by a key
   associated with the parent of that domain name; for example, the keys
   for "example.com" can only be signed by the keys for "com", and the
   keys for "com" can only be signed by the DNS root.  This prevents an
   untrustworthy signer from compromising anyone's keys except those in
   their own subdomains.  Like TLS, DNSSEC relies on public keys that
   come built into the DNSSEC client software, but these keys come only
   from a single root domain rather than from a multiplicity of CAs.

   DNS-Based Authentication of Named Entities (DANE) offers the option
   to use the DNSSEC infrastructure to store and sign keys and
   certificates that are used by TLS.  DANE is envisioned as a
   preferable basis for binding public keys to DNS names, because the
   entities that vouch for the binding of public key data to DNS names
   are the same entities responsible for managing the DNS names in
   question.  While the resulting system still has residual security
   vulnerabilities, it restricts the scope of assertions that can be
   made by any entity, consistent with the naming scope imposed by the
   DNS hierarchy.  As a result, DANE embodies the security "principle of
   least privilege" that is lacking in the current public CA model.

1.2.  Securing the Association of a Domain Name with a Server's
      Certificate

   A TLS client begins a connection by exchanging messages with a TLS
   server.  For many application protocols, it looks up the server's
   name using the DNS to get an Internet Protocol (IP) address
   associated with the name.  It then begins a connection to a
   particular port at that address, and sends an initial message there.
   However, the client does not yet know whether an adversary is
   intercepting and/or altering its communication before it reaches the
   TLS server.  It does not even know whether the real TLS server
   associated with that domain name has ever received its initial
   messages.

   The first response from the server in TLS may contain a certificate.
   In order for the TLS client to authenticate that it is talking to the
   expected TLS server, the client must validate that this certificate
   is associated with the domain name used by the client to get to the
   server.  Currently, the client must extract the domain name from the



Hoffman & Schlyter           Standards Track                    [Page 4]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   certificate and must successfully validate the certificate, including
   chaining to a trust anchor.

   There is a different way to authenticate the association of the
   server's certificate with the intended domain name without trusting
   an external CA.  Given that the DNS administrator for a domain name
   is authorized to give identifying information about the zone, it
   makes sense to allow that administrator to also make an authoritative
   binding between the domain name and a certificate that might be used
   by a host at that domain name.  The easiest way to do this is to use
   the DNS, securing the binding with DNSSEC.

   There are many use cases for such functionality.  [RFC6394] lists the
   ones to which the DNS RRtype in this document apply.  [RFC6394] also
   lists many requirements, most of which this document is believed to
   meet.  Section 5 covers the applicability of this document to the use
   cases in detail.  The protocol in this document can generally be
   referred to as the "DANE TLSA" protocol.  ("TLSA" does not stand for
   anything; it is just the name of the RRtype.)

   This document applies to both TLS [RFC5246] and Datagram TLS (DTLS)
   [RFC6347].  In order to make the document more readable, it mostly
   only talks about "TLS", but in all cases, it means "TLS or DTLS".
   Although the references in this paragraph are to TLS and DTLS
   version 1.2, the DANE TLSA protocol can also be used with earlier
   versions of TLS and DTLS.

   This document only relates to securely associating certificates for
   TLS and DTLS with host names; retrieving certificates from DNS for
   other protocols is handled in other documents.  For example, keys for
   IPsec are covered in [RFC4025], and keys for Secure SHell (SSH) are
   covered in [RFC4255].

1.3.  Method for Securing Certificate Associations

   A certificate association is formed from a piece of information
   identifying a certificate and the domain name where the server
   application runs.  The combination of a trust anchor and a domain
   name can also be a certificate association.

   A DNS query can return multiple certificate associations, such as in
   the case of a server that is changing from one certificate to another
   (described in more detail in Appendix A.4).

   This document only applies to PKIX [RFC5280] certificates, not
   certificates of other formats.





Hoffman & Schlyter           Standards Track                    [Page 5]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   This document defines a secure method to associate the certificate
   that is obtained from the TLS server with a domain name using DNS;
   the DNS information needs to be protected by DNSSEC.  Because the
   certificate association was retrieved based on a DNS query, the
   domain name in the query is by definition associated with the
   certificate.  Note that this document does not cover how to associate
   certificates with domain names for application protocols that depend
   on SRV, NAPTR, and similar DNS resource records.  It is expected that
   future documents will cover methods for making those associations,
   and those documents may or may not need to update this one.

   DNSSEC, which is defined in [RFC4033], [RFC4034], and [RFC4035], uses
   cryptographic keys and digital signatures to provide authentication
   of DNS data.  Information that is retrieved from the DNS and that is
   validated using DNSSEC is thereby proved to be the authoritative
   data.  The DNSSEC signature needs to be validated on all responses
   that use DNSSEC in order to assure the proof of origin of the data.

   This document does not specify how DNSSEC validation occurs because
   there are many different proposals for how a client might get
   validated DNSSEC results, such as from a DNSSEC-aware resolver that
   is coded in the application, from a trusted DNSSEC resolver on the
   machine on which the application is running, or from a trusted DNSSEC
   resolver with which the application is communicating over an
   authenticated and integrity-protected channel or network.  This is
   described in more detail in Section 7 of [RFC4033].

   This document only relates to getting the DNS information for the
   certificate association securely using DNSSEC; other secure DNS
   mechanisms are out of scope.

1.4.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in RFC 2119 [RFC2119].

   This document also makes use of standard PKIX, DNSSEC, TLS, and DNS
   terminology.  See [RFC5280], [RFC4033], [RFC5246], and STD 13
   [RFC1034] [RFC1035], respectively, for these terms.  In addition,
   terms related to TLS-protected application services and DNS names are
   taken from [RFC6125].









Hoffman & Schlyter           Standards Track                    [Page 6]

RFC 6698            DNS-Based Authentication for TLS         August 2012


2.  The TLSA Resource Record

   The TLSA DNS resource record (RR) is used to associate a TLS server
   certificate or public key with the domain name where the record is
   found, thus forming a "TLSA certificate association".  The semantics
   of how the TLSA RR is interpreted are given later in this document.

   The type value for the TLSA RR type is defined in Section 7.1.

   The TLSA RR is class independent.

   The TLSA RR has no special Time to Live (TTL) requirements.

2.1.  TLSA RDATA Wire Format

   The RDATA for a TLSA RR consists of a one-octet certificate usage
   field, a one-octet selector field, a one-octet matching type field,
   and the certificate association data field.

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Cert. Usage  |   Selector    | Matching Type |               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               /
   /                                                               /
   /                 Certificate Association Data                  /
   /                                                               /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

2.1.1.  The Certificate Usage Field

   A one-octet value, called "certificate usage", specifies the provided
   association that will be used to match the certificate presented in
   the TLS handshake.  This value is defined in a new IANA registry (see
   Section 7.2) in order to make it easier to add additional certificate
   usages in the future.  The certificate usages defined in this
   document are:

      0 -- Certificate usage 0 is used to specify a CA certificate, or
      the public key of such a certificate, that MUST be found in any of
      the PKIX certification paths for the end entity certificate given
      by the server in TLS.  This certificate usage is sometimes
      referred to as "CA constraint" because it limits which CA can be
      used to issue certificates for a given service on a host.  The
      presented certificate MUST pass PKIX certification path
      validation, and a CA certificate that matches the TLSA record MUST
      be included as part of a valid certification path.  Because this
      certificate usage allows both trust anchors and CA certificates,



Hoffman & Schlyter           Standards Track                    [Page 7]

RFC 6698            DNS-Based Authentication for TLS         August 2012


      the certificate might or might not have the basicConstraints
      extension present.

      1 -- Certificate usage 1 is used to specify an end entity
      certificate, or the public key of such a certificate, that MUST be
      matched with the end entity certificate given by the server in
      TLS.  This certificate usage is sometimes referred to as "service
      certificate constraint" because it limits which end entity
      certificate can be used by a given service on a host.  The target
      certificate MUST pass PKIX certification path validation and MUST
      match the TLSA record.

      2 -- Certificate usage 2 is used to specify a certificate, or the
      public key of such a certificate, that MUST be used as the trust
      anchor when validating the end entity certificate given by the
      server in TLS.  This certificate usage is sometimes referred to as
      "trust anchor assertion" and allows a domain name administrator to
      specify a new trust anchor -- for example, if the domain issues
      its own certificates under its own CA that is not expected to be
      in the end users' collection of trust anchors.  The target
      certificate MUST pass PKIX certification path validation, with any
      certificate matching the TLSA record considered to be a trust
      anchor for this certification path validation.

      3 -- Certificate usage 3 is used to specify a certificate, or the
      public key of such a certificate, that MUST match the end entity
      certificate given by the server in TLS.  This certificate usage is
      sometimes referred to as "domain-issued certificate" because it
      allows for a domain name administrator to issue certificates for a
      domain without involving a third-party CA.  The target certificate
      MUST match the TLSA record.  The difference between certificate
      usage 1 and certificate usage 3 is that certificate usage 1
      requires that the certificate pass PKIX validation, but PKIX
      validation is not tested for certificate usage 3.

   The certificate usages defined in this document explicitly only apply
   to PKIX-formatted certificates in DER encoding [X.690].  If TLS
   allows other formats later, or if extensions to this RRtype are made
   that accept other formats for certificates, those certificates will
   need their own certificate usage values.

2.1.2.  The Selector Field

   A one-octet value, called "selector", specifies which part of the TLS
   certificate presented by the server will be matched against the
   association data.  This value is defined in a new IANA registry (see
   Section 7.3).  The selectors defined in this document are:




Hoffman & Schlyter           Standards Track                    [Page 8]

RFC 6698            DNS-Based Authentication for TLS         August 2012


      0 -- Full certificate: the Certificate binary structure as defined
      in [RFC5280]

      1 -- SubjectPublicKeyInfo: DER-encoded binary structure as defined
      in [RFC5280]

   (Note that the use of "selector" in this document is completely
   unrelated to the use of "selector" in DomainKeys Identified Mail
   (DKIM) [RFC6376].)

2.1.3.  The Matching Type Field

   A one-octet value, called "matching type", specifies how the
   certificate association is presented.  This value is defined in a new
   IANA registry (see Section 7.4).  The types defined in this document
   are:

      0 -- Exact match on selected content

      1 -- SHA-256 hash of selected content [RFC6234]

      2 -- SHA-512 hash of selected content [RFC6234]

   If the TLSA record's matching type is a hash, having the record use
   the same hash algorithm that was used in the signature in the
   certificate (if possible) will assist clients that support a small
   number of hash algorithms.

2.1.4.  The Certificate Association Data Field

   This field specifies the "certificate association data" to be
   matched.  These bytes are either raw data (that is, the full
   certificate or its SubjectPublicKeyInfo, depending on the selector)
   for matching type 0, or the hash of the raw data for matching types 1
   and 2.  The data refers to the certificate in the association, not to
   the TLS ASN.1 Certificate object.

2.2.  TLSA RR Presentation Format

   The presentation format of the RDATA portion (as defined in
   [RFC1035]) is as follows:

   o  The certificate usage field MUST be represented as an 8-bit
      unsigned integer.

   o  The selector field MUST be represented as an 8-bit unsigned
      integer.




Hoffman & Schlyter           Standards Track                    [Page 9]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   o  The matching type field MUST be represented as an 8-bit unsigned
      integer.

   o  The certificate association data field MUST be represented as a
      string of hexadecimal characters.  Whitespace is allowed within
      the string of hexadecimal characters, as described in [RFC1035].

2.3.  TLSA RR Examples

   In the following examples, the domain name is formed using the rules
   in Section 3.

   An example of a hashed (SHA-256) association of a PKIX CA
   certificate:

   _443._tcp.www.example.com. IN TLSA (
      0 0 1 d2abde240d7cd3ee6b4b28c54df034b9
            7983a1d16e8a410e4561cb106618e971 )

   An example of a hashed (SHA-512) subject public key association of a
   PKIX end entity certificate:

   _443._tcp.www.example.com. IN TLSA (
      1 1 2 92003ba34942dc74152e2f2c408d29ec
            a5a520e7f2e06bb944f4dca346baf63c
            1b177615d466f6c4b71c216a50292bd5
            8c9ebdd2f74e38fe51ffd48c43326cbc )

   An example of a full certificate association of a PKIX end entity
   certificate:

   _443._tcp.www.example.com. IN TLSA (
      3 0 0 30820307308201efa003020102020... )

3.  Domain Names for TLSA Certificate Associations

   Unless there is a protocol-specific specification that is different
   than this one, TLSA resource records are stored at a prefixed DNS
   domain name.  The prefix is prepared in the following manner:

   1.  The decimal representation of the port number on which a TLS-
       based service is assumed to exist is prepended with an underscore
       character ("_") to become the left-most label in the prepared
       domain name.  This number has no leading zeros.







Hoffman & Schlyter           Standards Track                   [Page 10]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   2.  The protocol name of the transport on which a TLS-based service
       is assumed to exist is prepended with an underscore character
       ("_") to become the second left-most label in the prepared domain
       name.  The transport names defined for this protocol are "tcp",
       "udp", and "sctp".

   3.  The base domain name is appended to the result of step 2 to
       complete the prepared domain name.  The base domain name is the
       fully qualified DNS domain name [RFC1035] of the TLS server, with
       the additional restriction that every label MUST meet the rules
       of [RFC0952].  The latter restriction means that, if the query is
       for an internationalized domain name, it MUST use the A-label
       form as defined in [RFC5890].

   For example, to request a TLSA resource record for an HTTP server
   running TLS on port 443 at "www.example.com",
   "_443._tcp.www.example.com" is used in the request.  To request a
   TLSA resource record for an SMTP server running the STARTTLS protocol
   on port 25 at "mail.example.com", "_25._tcp.mail.example.com" is
   used.

4.  Use of TLSA Records in TLS

   Section 2.1 of this document defines the mandatory matching rules for
   the data from the TLSA certificate associations and the certificates
   received from the TLS server.

   The TLS session that is to be set up MUST be for the specific port
   number and transport name that was given in the TLSA query.

   Some specifications for applications that run over TLS, such as
   [RFC2818] for HTTP, require that the server's certificate have a
   domain name that matches the host name expected by the client.  Some
   specifications, such as [RFC6125], detail how to match the identity
   given in a PKIX certificate with those expected by the user.

   If a TLSA record has certificate usage 2, the corresponding TLS
   server SHOULD send the certificate that is referenced just like it
   currently sends intermediate certificates.

4.1.  Usable Certificate Associations

   An implementation of this protocol makes a DNS query for TLSA
   records, validates these records using DNSSEC, and uses the resulting
   TLSA records and validation status to modify its responses to the TLS
   server.





Hoffman & Schlyter           Standards Track                   [Page 11]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   Determining whether a TLSA RRSet can be used MUST be based on the
   DNSSEC validation state (as defined in [RFC4033]).

   o  A TLSA RRSet whose DNSSEC validation state is secure MUST be used
      as a certificate association for TLS unless a local policy would
      prohibit the use of the specific certificate association in the
      secure TLSA RRSet.

   o  If the DNSSEC validation state on the response to the request for
      the TLSA RRSet is bogus, this MUST cause TLS not to be started or,
      if the TLS negotiation is already in progress, MUST cause the
      connection to be aborted.

   o  A TLSA RRSet whose DNSSEC validation state is indeterminate or
      insecure cannot be used for TLS and MUST be considered unusable.

   Clients that validate the DNSSEC signatures themselves MUST use
   standard DNSSEC validation procedures.  Clients that rely on another
   entity to perform the DNSSEC signature validation MUST use a secure
   mechanism between themselves and the validator.  Examples of secure
   transports to other hosts include TSIG [RFC2845], SIG(0) [RFC2931],
   and IPsec [RFC6071].  Note that it is not sufficient to use secure
   transport to a DNS resolver that does not do DNSSEC signature
   validation.  See Section 8.3 for more security considerations related
   to external validators.

   If a certificate association contains a certificate usage, selector,
   or matching type that is not understood by the TLS client, that
   certificate association MUST be considered unusable.  If the
   comparison data for a certificate is malformed, the certificate
   association MUST be considered unusable.

   If a certificate association contains a matching type or certificate
   association data that uses a cryptographic algorithm that is
   considered too weak for the TLS client's policy, the certificate
   association MUST be considered unusable.

   If an application receives zero usable certificate associations from
   a DNS request or from its cache, it processes TLS in the normal
   fashion without any input from the TLSA records.  If an application
   receives one or more usable certificate associations, it attempts to
   match each certificate association with the TLS server's end entity
   certificate until a successful match is found.  During the TLS
   handshake, if none of the certificate associations matches the
   certificate given by the TLS server, the TLS client MUST abort the
   handshake.





Hoffman & Schlyter           Standards Track                   [Page 12]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   An attacker who is able to divert a user to a server under his
   control is also likely to be able to block DNS requests from the user
   or DNS responses being sent to the user.  Thus, in order to achieve
   any security benefit from certificate usage 0 or 1, an application
   that sends a request for TLSA records needs to get either a valid
   signed response containing TLSA records or verification that the
   domain is insecure or indeterminate.  If a request for a TLSA record
   does not meet one of those two criteria but the application continues
   with the TLS handshake anyway, the application has gotten no benefit
   from TLSA and SHOULD NOT make any internal or external indication
   that TLSA was applied.  If an application has a configuration setting
   that has turned on TLSA use, or has any indication that TLSA is in
   use (regardless of whether or not this is configurable), that
   application either MUST NOT start a TLS connection or it MUST abort a
   TLS handshake if both of the two criteria above are not met.

   The application can perform the TLSA lookup before initiating the TLS
   handshake, or do it during the TLS handshake: the choice is up to the
   client.

5.  TLSA and DANE Use Cases and Requirements

   The different types of certificate associations defined in TLSA are
   matched with various sections of [RFC6394].  The use cases from
   Section 3 of [RFC6394] are covered in this document as follows:

   3.1 CA Constraints -- Implemented using certificate usage 0.

   3.2 Certificate Constraints -- Implemented using certificate usage 1.

   3.3 Trust Anchor Assertion and Domain-Issued Certificates --
      Implemented using certificate usages 2 and 3, respectively.

   The requirements from Section 4 of [RFC6394] are covered in this
   document as follows:

   Multiple Ports -- The TLSA records for different application services
      running on a single host can be distinguished through the service
      name and port number prefixed to the host name (see Section 3).

   No Downgrade -- Section 4 specifies the conditions under which a
      client can process and act upon TLSA records.  Specifically, if
      the DNSSEC status for the TLSA resource record set is determined
      to be bogus, the TLS connection (if started) will fail.

   Encapsulation -- Encapsulation is covered in the TLSA response
      semantics.




Hoffman & Schlyter           Standards Track                   [Page 13]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   Predictability -- The appendices of this specification provide
      operational considerations and implementation guidance in order to
      enable application developers to form a consistent interpretation
      of the recommended client behavior.

   Opportunistic Security -- If a client conformant to this
      specification can reliably determine the presence of a TLSA
      record, it will attempt to use this information.  Conversely, if a
      client can reliably determine the absence of any TLSA record, it
      will fall back to processing TLS in the normal fashion.  This is
      discussed in Section 4.

   Combination -- Multiple TLSA records can be published for a given
      host name, thus enabling the client to construct multiple TLSA
      certificate associations that reflect different assertions.  No
      support is provided to combine two TLSA certificate associations
      in a single operation.

   Roll-over -- TLSA records are processed in the normal manner within
      the scope of the DNS protocol, including the TTL expiration of the
      records.  This ensures that clients will not latch onto assertions
      made by expired TLSA records, and will be able to transition from
      using one public key or certificate usage to another.

   Simple Key Management -- The SubjectPublicKeyInfo selector in the
      TLSA record provides a mode that enables a domain holder to only
      have to maintain a single long-lived public/private key pair
      without the need to manage certificates.  Appendix A outlines the
      usefulness and the potential downsides to using this mode.

   Minimal Dependencies -- This specification relies on DNSSEC to
      protect the origin authenticity and integrity of the TLSA resource
      record set.  Additionally, if DNSSEC validation is not performed
      on the system that wishes to use TLSA certificate bindings, this
      specification requires that the "last mile" be over a secure
      transport.  There are no other deployment dependencies for this
      approach.

   Minimal Options -- The operating modes map precisely to the DANE use
      cases and requirements.  DNSSEC use is mandatory in that this
      specification encourages applications to use only those TLSA
      records that are shown to be validated.

   Wildcards -- Wildcards are covered in a limited manner in the TLSA
      request syntax; see Appendix A.

   Redirection -- Redirection is covered in the TLSA request syntax; see
      Appendix A.



Hoffman & Schlyter           Standards Track                   [Page 14]

RFC 6698            DNS-Based Authentication for TLS         August 2012


6.  Mandatory-to-Implement Features

   TLS clients conforming to this specification MUST be able to
   correctly interpret TLSA records with certificate usages 0, 1, 2,
   and 3.  TLS clients conforming to this specification MUST be able to
   compare a certificate association with a certificate from the TLS
   handshake using selector types 0 and 1, and matching type 0 (no hash
   used) and matching type 1 (SHA-256), and SHOULD be able to make such
   comparisons with matching type 2 (SHA-512).

7.  IANA Considerations

   IANA has made the assignments in this section.

   In the following sections, "RFC Required" was chosen for TLSA
   certificate usages and "Specification Required" for selectors and
   matching types because of the amount of detail that is likely to be
   needed for implementers to correctly implement new certificate usages
   as compared to new selectors and matching types.

7.1.  TLSA RRtype

   This document uses a new DNS RR type, TLSA, whose value (52) was
   allocated by IANA from the Resource Record (RR) TYPEs subregistry of
   the Domain Name System (DNS) Parameters registry.

7.2.  TLSA Certificate Usages

   This document creates a new registry, "TLSA Certificate Usages".  The
   registry policy is "RFC Required".  The initial entries in the
   registry are:

   Value    Short description                       Reference
   ----------------------------------------------------------
   0        CA constraint                           RFC 6698
   1        Service certificate constraint          RFC 6698
   2        Trust anchor assertion                  RFC 6698
   3        Domain-issued certificate               RFC 6698
   4-254    Unassigned
   255      Private use

   Applications to the registry can request specific values that have
   yet to be assigned.








Hoffman & Schlyter           Standards Track                   [Page 15]

RFC 6698            DNS-Based Authentication for TLS         August 2012


7.3.  TLSA Selectors

   This document creates a new registry, "TLSA Selectors".  The registry
   policy is "Specification Required".  The initial entries in the
   registry are:

   Value    Short description                       Reference
   ----------------------------------------------------------
   0        Full certificate                        RFC 6698
   1        SubjectPublicKeyInfo                    RFC 6698
   2-254    Unassigned
   255      Private use

   Applications to the registry can request specific values that have
   yet to be assigned.

7.4.  TLSA Matching Types

   This document creates a new registry, "TLSA Matching Types".  The
   registry policy is "Specification Required".  The initial entries in
   the registry are:

   Value    Short description                       Reference
   ----------------------------------------------------------
   0        No hash used                            RFC 6698
   1        SHA-256                                 RFC 6234
   2        SHA-512                                 RFC 6234
   3-254    Unassigned
   255      Private use

   Applications to the registry can request specific values that have
   yet to be assigned.

8.  Security Considerations

   The security of the DNS RRtype described in this document relies on
   the security of DNSSEC to verify that the TLSA record has not been
   altered.

   A rogue DNS administrator who changes the A, AAAA, and/or TLSA
   records for a domain name can cause the client to go to an
   unauthorized server that will appear authorized, unless the client
   performs PKIX certification path validation and rejects the
   certificate.  That administrator could probably get a certificate
   issued by some CA anyway, so this is not an additional threat.






Hoffman & Schlyter           Standards Track                   [Page 16]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   If the authentication mechanism for adding or changing TLSA data in a
   zone is weaker than the authentication mechanism for changing the A
   and/or AAAA records, a man-in-the-middle who can redirect traffic to
   his site may be able to impersonate the attacked host in TLS if he
   can use the weaker authentication mechanism.  A better design for
   authenticating DNS would be to have the same level of authentication
   used for all DNS additions and changes for a particular domain name.

   Secure Socket Layer (SSL) proxies can sometimes act as a man-in-the-
   middle for TLS clients.  In these scenarios, the clients add a new
   trust anchor whose private key is kept on the SSL proxy; the proxy
   intercepts TLS requests, creates a new TLS session with the intended
   host, and sets up a TLS session with the client using a certificate
   that chains to the trust anchor installed in the client by the proxy.
   In such environments, using TLSA records will prevent the SSL proxy
   from functioning as expected because the TLS client will get a
   certificate association from the DNS that will not match the
   certificate that the SSL proxy uses with the client.  The client,
   seeing the proxy's new certificate for the supposed destination, will
   not set up a TLS session.

   Client treatment of any information included in the trust anchor is a
   matter of local policy.  This specification does not mandate that
   such information be inspected or validated by the server's domain
   name administrator.

   If a server's certificate is revoked, or if an intermediate CA in a
   chain between the server and a trust anchor has its certificate
   revoked, a TLSA record with a certificate usage of 2 that matches the
   revoked certificate would in essence override the revocation because
   the client would treat that revoked certificate as a trust anchor and
   thus not check its revocation status.  Because of this, domain
   administrators need to be responsible for being sure that the keys or
   certificates used in TLSA records with a certificate usage of 2 are
   in fact able to be used as reliable trust anchors.

   Certificates that are delivered in TLSA with certificate usage 2
   fundamentally change the way the TLS server's end entity certificate
   is evaluated.  For example, the server's certificate might chain to
   an existing CA through an intermediate CA that has certain policy
   restrictions, and the certificate would not pass those restrictions
   and thus normally be rejected.  That intermediate CA could issue
   itself a new certificate without the policy restrictions and tell its
   customers to use that certificate with certificate usage 2.  This in
   essence allows an intermediate CA to become a trust anchor for
   certificates that the end user might have expected to chain to an
   existing trust anchor.




Hoffman & Schlyter           Standards Track                   [Page 17]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   If an administrator wishes to stop using a TLSA record, the
   administrator can simply remove it from the DNS.  Normal clients will
   stop using the TLSA record after the TTL has expired.  Replay attacks
   against the TLSA record are not possible after the expiration date on
   the RRsig of the TLSA record that was removed.

   Generators of TLSA records should be aware that the client's full
   trust of a certificate association retrieved from a TLSA record may
   be a matter of local policy.  While such trust is limited to the
   specific domain name, protocol, and port for which the TLSA query was
   made, local policy may decline to accept the certificate (for reasons
   such as weak cryptography), as is also the case with PKIX trust
   anchors.

8.1.  Comparing DANE to Public CAs

   As stated above, the security of the DNS RRtype described in this
   document relies on the security of DNSSEC to verify that the TLSA
   record has not been altered.  This section describes where the
   security of public CAs and the security of TLSA are similar and
   different.  This section applies equally to other security-related
   DNS RRtypes such as keys for IPsec and SSH.

   DNSSEC forms certificates (the binding of an identity to a key) by
   combining a DNSKEY, DS, or DLV resource record with an associated
   RRSIG record.  These records then form a signing chain extending from
   the client's trust anchors to the RR of interest.

   Although the DNSSEC protocol does not enforce it, DNSKEYs are often
   marked with a SEP flag indicating whether the key is a Zone Signing
   Key (ZSK) or a Key Signing Key (KSK).  ZSKs protect records in the
   zone (including DS and DLV records), and KSKs protect ZSK DNSKEY
   records.  This allows KSKs to be stored offline.

   The TLSA RRtype allows keys from the DNSSEC PKI hierarchy to
   authenticate keys wrapped in PKIX certificates for a particular host
   name, protocol, and port.

   With the exception of the DLV RRtype, all of these certificates
   constrain the keys they identify to names that are within the zone
   signing the certificate.  In order for a domain's DLV resource
   records to be honored, the domain must be configured as a DLV domain,
   and the domain's DNSKEYs must be configured as trust anchors or be
   authentic [RFC5074].







Hoffman & Schlyter           Standards Track                   [Page 18]

RFC 6698            DNS-Based Authentication for TLS         August 2012


8.1.1.  Risk of Key Compromise

   The risk that a given certificate that has a valid signing chain is
   fake is related to the number of keys that can contribute to the
   validation of the certificate, the quality of protection each private
   key receives, the value of each key to an attacker, and the value of
   falsifying the certificate.

   DNSSEC allows any set of domains to be configured as trust anchors
   and/or DLVs, but most clients are likely to use the root zone as
   their only trust anchor.  Also, because a given DNSKEY can only sign
   resource records for that zone, the number of private keys capable of
   compromising a given TLSA resource record is limited to the number of
   zones between the TLSA resource record and the nearest trust anchor,
   plus any configured DLV domains.  Typically, this will be six keys,
   half of which will be KSKs.

   PKIX only describes how to validate a certificate based on a client-
   chosen set of trust anchors, but says nothing about how many trust
   anchors to use or how they should be constrained.  As currently
   deployed, most PKIX clients use a large number of trust anchors
   provided with the client or operating system software.  These trust
   anchors are selected carefully, but with a desire for broad
   interoperability.  The trust anchors and CA certificates for public
   CAs rarely have name constraints applied.

   A combination of technical protections, process controls, and
   personnel experience contribute to the quality of security that keys
   receive.

   o  The security surrounding DNSSEC DNSKEYs varies significantly.  The
      KSK/ZSK split allows the KSK to be stored offline and protected
      more carefully than the ZSK, but not all domains do so.  The
      security applied to a zone's DNSKEYs should be proportional to the
      value of the domain, but that is difficult to estimate.  For
      example, the root DNSKEY has protections and controls comparable
      to or exceeding those of public CAs.  On the other end of the
      spectrum, small domains might provide no more protection to their
      keys than they do to their other data.

   o  The security surrounding public CAs also varies.  However, due to
      financial incentives and standards imposed by clients for
      acceptance into their trust anchor stores, CAs generally employ
      security experts and protect their keys carefully, though highly
      public compromises have occurred.






Hoffman & Schlyter           Standards Track                   [Page 19]

RFC 6698            DNS-Based Authentication for TLS         August 2012


8.1.2.  Impact of Key Compromise

   The impact of a key compromise differs significantly between the two
   models.

   o  DNSKEYs are inherently limited in what they can sign, so a
      compromise of the DNSKEY for "example.com" provides no avenue of
      attack against "example.org".  Even the impact of a compromise of
      .com's DNSKEY, while considerable, would be limited to .com
      domains.  Only the compromise of the root DNSKEY would have the
      equivalent impact of an unconstrained public CA.

   o  Public CAs are not typically constrained in what names they can
      sign, and therefore a compromise of even one CA allows the
      attacker to generate a certificate for any name in the DNS.  A
      domain holder can get a certificate from any willing CA, or even
      multiple CAs simultaneously, making it impossible for a client to
      determine whether the certificate it is validating is legitimate
      or fraudulent.

   Because a TLSA certificate association is constrained to its
   associated name, protocol, and port, the PKIX certificate is
   similarly constrained, even if its public CAs signing the certificate
   (if any) are not.

8.1.3.  Detection of Key Compromise

   If a key is compromised, rapid and reliable detection is important in
   order to limit the impact of the compromise.  In this regard, neither
   model prevents an attacker from near-invisibly attacking their
   victim, provided that the necessary keys are compromised.

   If a public CA is compromised, only the victim will see the
   fraudulent certificate, as there is typically no publicly accessible
   directory of all the certificates issued by a CA that can be
   inspected.  DNS resource records are typically published publicly.
   However, the attacker could also allow the uncompromised records to
   be published to the Internet as usual but provide a compromised DNS
   view to the victim to achieve the same effect.

8.1.4.  Spoofing Hostnames

   Some CAs implement technical controls to ensure that certificates are
   not issued to domains with names similar to domains that are popular
   and prone to attack.  Of course, an attacker can attempt to
   circumvent this restriction by finding a CA willing to issue the
   certificate anyway.  However, by using DNSSEC and TLSA, the attacker
   can circumvent this check completely.



Hoffman & Schlyter           Standards Track                   [Page 20]

RFC 6698            DNS-Based Authentication for TLS         August 2012


8.2.  DNS Caching

   Implementations of this protocol rely heavily on the DNS, and are
   thus prone to security attacks based on the deliberate
   mis-association of TLSA records and DNS names.  Implementations need
   to be cautious in assuming the continuing validity of an association
   between a TLSA record and a DNS name.

   In particular, implementations SHOULD rely on their DNS resolver for
   confirmation of an association between a TLSA record and a DNS name,
   rather than caching the result of previous domain name lookups.  Many
   platforms already can cache domain name lookups locally when
   appropriate, and they SHOULD be configured to do so.  It is proper
   for these lookups to be cached, however, only when the TTL (Time To
   Live) information reported by the DNS makes it likely that the cached
   information will remain useful.

   If implementations cache the results of domain name lookups in order
   to achieve a performance improvement, they MUST observe the TTL
   information reported by DNS.  Implementations that fail to follow
   this rule could be spoofed or have access denied when a previously
   accessed server's TLSA record changes, such as during a certificate
   rollover.

8.3.  External DNSSEC Validators

   Due to a lack of DNSSEC support in the most commonly deployed stub
   resolvers today, some ISPs have begun checking DNSSEC in the
   recursive resolvers they provide to their customers, setting the
   Authentic Data (AD) flag as appropriate.  DNSSEC-aware clients could
   use that data, ignoring the fact that the DNSSEC data has been
   validated externally.  Because there is typically no authentication
   of the recursive resolver or integrity protection of the data and AD
   flag between the client and the recursive resolver, this can be
   trivially spoofed by an attacker.

   However, even with secure communications between a host and the
   external validating resolver, there is a risk that the external
   validator could become compromised.  Nothing prevents a compromised
   external DNSSEC validator from claiming that all the records it
   provides are secure, even if the data is falsified, unless the client
   checks the DNSSEC data itself (rendering the external validator
   unnecessary).

   For this reason, DNSSEC validation is best performed on-host, even
   when a secure path to an external validator is available.





Hoffman & Schlyter           Standards Track                   [Page 21]

RFC 6698            DNS-Based Authentication for TLS         August 2012


9.  Acknowledgements

   Many of the ideas in this document have been discussed over many
   years.  More recently, the ideas have been discussed by the authors
   and others in a more focused fashion.  In particular, some of the
   ideas and words here originated with Paul Vixie, Dan Kaminsky, Jeff
   Hodges, Phillip Hallam-Baker, Simon Josefsson, Warren Kumari, Adam
   Langley, Ben Laurie, Ilari Liusvaara, Ondrej Mikle, Scott Schmit,
   Ondrej Sury, Richard Barnes, Jim Schaad, Stephen Farrell, Suresh
   Krishnaswamy, Peter Palfrader, Pieter Lexis, Wouter Wijngaards, John
   Gilmore, and Murray Kucherawy.

   This document has also been greatly helped by many active
   participants of the DANE Working Group.

10.  References

10.1.  Normative References

   [RFC1034]  Mockapetris, P., "Domain names - concepts and facilities",
              STD 13, RFC 1034, November 1987.

   [RFC1035]  Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, November 1987.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, March 2005.

   [RFC4034]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Resource Records for the DNS Security Extensions",
              RFC 4034, March 2005.

   [RFC4035]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Protocol Modifications for the DNS Security
              Extensions", RFC 4035, March 2005.

   [RFC5246]  Dierks, T. and E. Rescorla, "The Transport Layer Security
              (TLS) Protocol Version 1.2", RFC 5246, August 2008.

   [RFC5280]  Cooper, D., Santesson, S., Farrell, S., Boeyen, S.,
              Housley, R., and W. Polk, "Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 5280, May 2008.




Hoffman & Schlyter           Standards Track                   [Page 22]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   [RFC6125]  Saint-Andre, P. and J. Hodges, "Representation and
              Verification of Domain-Based Application Service Identity
              within Internet Public Key Infrastructure Using X.509
              (PKIX) Certificates in the Context of Transport Layer
              Security (TLS)", RFC 6125, March 2011.

   [RFC6347]  Rescorla, E. and N. Modadugu, "Datagram Transport Layer
              Security Version 1.2", RFC 6347, January 2012.

10.2.  Informative References

   [RFC0952]  Harrenstien, K., Stahl, M., and E. Feinler, "DoD Internet
              host table specification", RFC 952, October 1985.

   [RFC2782]  Gulbrandsen, A., Vixie, P., and L. Esibov, "A DNS RR for
              specifying the location of services (DNS SRV)", RFC 2782,
              February 2000.

   [RFC2818]  Rescorla, E., "HTTP Over TLS", RFC 2818, May 2000.

   [RFC2845]  Vixie, P., Gudmundsson, O., Eastlake 3rd, D., and B.
              Wellington, "Secret Key Transaction Authentication for DNS
              (TSIG)", RFC 2845, May 2000.

   [RFC2931]  Eastlake 3rd, D., "DNS Request and Transaction Signatures
              ( SIG(0)s)", RFC 2931, September 2000.

   [RFC4025]  Richardson, M., "A Method for Storing IPsec Keying
              Material in DNS", RFC 4025, March 2005.

   [RFC4255]  Schlyter, J. and W. Griffin, "Using DNS to Securely
              Publish Secure Shell (SSH) Key Fingerprints", RFC 4255,
              January 2006.

   [RFC4641]  Kolkman, O. and R. Gieben, "DNSSEC Operational Practices",
              RFC 4641, September 2006.

   [RFC5074]  Weiler, S., "DNSSEC Lookaside Validation (DLV)", RFC 5074,
              November 2007.

   [RFC5890]  Klensin, J., "Internationalized Domain Names for
              Applications (IDNA): Definitions and Document Framework",
              RFC 5890, August 2010.

   [RFC6066]  Eastlake 3rd, D., "Transport Layer Security (TLS)
              Extensions: Extension Definitions", RFC 6066,
              January 2011.




Hoffman & Schlyter           Standards Track                   [Page 23]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   [RFC6071]  Frankel, S. and S. Krishnan, "IP Security (IPsec) and
              Internet Key Exchange (IKE) Document Roadmap", RFC 6071,
              February 2011.

   [RFC6234]  Eastlake 3rd, D. and T. Hansen, "US Secure Hash Algorithms
              (SHA and SHA-based HMAC and HKDF)", RFC 6234, May 2011.

   [RFC6376]  Crocker, D., Ed., Hansen, T., Ed., and M. Kucherawy, Ed.,
              "DomainKeys Identified Mail (DKIM) Signatures", RFC 6376,
              September 2011.

   [RFC6394]  Barnes, R., "Use Cases and Requirements for DNS-Based
              Authentication of Named Entities (DANE)", RFC 6394,
              October 2011.

   [X.690]    "Recommendation ITU-T X.690 (2002) | ISO/IEC 8825-1:2002,
              Information technology - ASN.1 encoding rules:
              Specification of Basic Encoding Rules (BER), Canonical
              Encoding Rules (CER) and Distinguished Encoding Rules
              (DER)", July 2002.































Hoffman & Schlyter           Standards Track                   [Page 24]

RFC 6698            DNS-Based Authentication for TLS         August 2012


Appendix A.  Operational Considerations for Deploying TLSA Records

A.1.  Creating TLSA Records

   When creating TLSA records, care must be taken to avoid
   misconfigurations.  Section 4 of this document states that a TLSA
   RRSet whose validation state is secure MUST be used.  This means that
   the existence of such a RRSet effectively disables other forms of
   name and path validation.  A misconfigured TLSA RRSet will
   effectively disable access to the TLS server for all conforming
   clients, and this document does not provide any means of making a
   gradual transition to using TLSA.

   When creating TLSA records with certificate usage 0 (CA certificate)
   or usage 2 (trust anchor), one needs to understand the implications
   when choosing between selector type 0 (Full certificate) and 1
   (SubjectPublicKeyInfo).  A careful choice is required because
   different methods for building trust chains are used by different TLS
   clients.  The following outlines the cases that one ought to be aware
   of and discusses the implications of the choice of selector type.

   Certificate usage 2 is not affected by the different types of chain
   building when the end entity certificate is the same as the trust
   anchor certificate.

A.1.1.  Ambiguities and Corner Cases When TLS Clients Build Trust Chains

   TLS clients can implement their own chain-building code rather than
   rely on the chain presented by the TLS server.  This means that,
   except for the end entity certificate, any certificate presented in
   the suggested chain might or might not be present in the final chain
   built by the client.

   Certificates that the client can use to replace certificates from the
   original chain include:

   o  Client's trust anchors

   o  Certificates cached locally

   o  Certificates retrieved from a URI listed in an Authority
      Information Access X.509v3 extension

   CAs frequently reissue certificates with different validity periods,
   signature algorithms (such as a different hash algorithm in the
   signature algorithm), CA key pairs (such as for a cross-certificate),





Hoffman & Schlyter           Standards Track                   [Page 25]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   or PKIX extensions where the public key and subject remain the same.
   These reissued certificates are the certificates that the TLS client
   can use in place of an original certificate.

   Clients are known to exchange or remove certificates that could cause
   TLSA certificate associations that rely on the full certificate to
   fail.  For example:

   o  The client considers the signature algorithm of a certificate to
      no longer be sufficiently secure.

   o  The client might not have an associated root certificate in its
      trust store and instead uses a cross-certificate with an identical
      subject and public key.

A.1.2.  Choosing a Selector Type

   In this section, "false-negative failure" means that a client will
   not accept the TLSA certificate association for a certificate
   designated by the DNS administrator.  Also, "false-positive
   acceptance" means that the client accepts a TLSA association for a
   certificate that is not designated by the DNS administrator.

A.1.2.1.  Selector Type 0 (Full Certificate)

   The "Full certificate" selector provides the most precise
   specification of a TLSA certificate association, capturing all
   fields of the PKIX certificate.  For a DNS administrator, the best
   course to avoid false-negative failures in the client when using this
   selector is:

   1.  If a CA issued a replacement certificate, don't associate to CA
       certificates that have a signature algorithm with a hash that is
       considered weak by local policy.

   2.  Determine how common client applications process the TLSA
       certificate association using a fresh client installation -- that
       is, with the local certificate cache empty.













Hoffman & Schlyter           Standards Track                   [Page 26]

RFC 6698            DNS-Based Authentication for TLS         August 2012


A.1.2.2.  Selector Type 1 (SubjectPublicKeyInfo)

   A SubjectPublicKeyInfo selector gives greater flexibility in avoiding
   some false-negative failures caused by trust-chain-building
   algorithms used in clients.

   One specific use case ought to be noted: creating a TLSA certificate
   association to CA certificate I1 that directly signed end entity
   certificate S1 of the server.  The case can be illustrated by the
   following graph:

           +----+                      +----+
           | I1 |                      | I2 |
           +----+                      +----+
              |                           |
              v                           v
           +----+                      +----+
           | S1 |                      | S1 |
           +----+                      +----+
   Certificate chain sent by    A different validation path
   server in TLS handshake      built by the TLS client

   I2 is a reissued version of CA certificate I1 (that is, it has a
   different hash in its signature algorithm).

   In the above scenario, both certificates I1 and I2 that sign S1 need
   to have identical SubjectPublicKeyInfo fields because the key used to
   sign S1 is fixed.  An association to SubjectPublicKeyInfo (selector
   type 1) will always succeed in such a case, but an association with a
   full certificate (selector type 0) might not work due to a false-
   negative failure.

   The attack surface is a bit broader compared to the "Full
   certificate" selector: the DNS administrator might unintentionally
   specify an association that would lead to false-positive acceptance.

   o  The administrator must know or trust that the CA does not engage
      in bad practices, such as not sharing the key of I1 for unrelated
      CA certificates (which would lead to trust-chain redirection).  If
      possible, the administrator ought to review all CA certificates
      that have the same SubjectPublicKeyInfo field.

   o  The administrator ought to understand whether some PKIX extension
      may adversely affect security of the association.  If possible,
      administrators ought to review all CA certificates that share the
      SubjectPublicKeyInfo.





Hoffman & Schlyter           Standards Track                   [Page 27]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   o  The administrator ought to understand that any CA could, in the
      future, issue a certificate that contains the same
      SubjectPublicKeyInfo.  Therefore, new chains can crop up in the
      future without any warning.

   Using the SubjectPublicKeyInfo selector for association with a
   certificate in a chain above I1 needs to be decided on a case-by-case
   basis: there are too many possibilities based on the issuing CA's
   practices.  Unless the full implications of such an association are
   understood by the administrator, using selector type 0 is a better
   option from a security perspective.

A.2.  Provisioning TLSA Records in DNS

A.2.1.  Provisioning TLSA Records with Aliases

   The TLSA resource record is not special in the DNS; it acts exactly
   like any other RRtype where the queried name has one or more labels
   prefixed to the base name, such as the SRV RRtype [RFC2782].  This
   affects the way that the TLSA resource record is used when aliasing
   in the DNS.

   Note that the IETF sometimes adds new types of aliasing in the DNS.
   If that happens in the future, those aliases might affect TLSA
   records, hopefully in a good way.

A.2.1.1.  Provisioning TLSA Records with CNAME Records

   Using CNAME to alias in DNS only aliases from the exact name given,
   not any zones below the given name.  For example, assume that a zone
   file has only the following:

   sub1.example.com.          IN CNAME sub2.example.com.

   In this case, a request for the A record at "bottom.sub1.example.com"
   would not return any records because the CNAME given only aliases the
   name given.  Assume, instead, the zone file has the following:

   sub3.example.com.          IN CNAME sub4.example.com.
   bottom.sub3.example.com.   IN CNAME bottom.sub4.example.com.

   In this case, a request for the A record at bottom.sub3.example.com
   would in fact return whatever value for the A record exists at
   bottom.sub4.example.com.







Hoffman & Schlyter           Standards Track                   [Page 28]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   Application implementations and full-service resolvers request DNS
   records using libraries that automatically follow CNAME (and DNAME)
   aliasing.  This allows hosts to put TLSA records in their own zones
   or to use CNAME to do redirection.

   If the owner of the original domain wants a TLSA record for the same,
   they simply enter it under the defined prefix:

   ; No TLSA record in target domain
   ;
   sub5.example.com.            IN CNAME sub6.example.com.
   _443._tcp.sub5.example.com.  IN TLSA 1 1 1 308202c5308201ab...
   sub6.example.com.            IN A 192.0.2.1
   sub6.example.com.            IN AAAA 2001:db8::1

   If the owner of the original domain wants to have the target domain
   host the TLSA record, the original domain uses a CNAME record:

   ; TLSA record for original domain has CNAME to target domain
   ;
   sub5.example.com.            IN CNAME sub6.example.com.
   _443._tcp.sub5.example.com.  IN CNAME _443._tcp.sub6.example.com.
   sub6.example.com.            IN A 192.0.2.1
   sub6.example.com.            IN AAAA 2001:db8::1
   _443._tcp.sub6.example.com.  IN TLSA 1 1 1 536a570ac49d9ba4...

   Note that it is acceptable for both the original domain and the
   target domain to have TLSA records, but the two records are
   unrelated.  Consider the following:

   ; TLSA record in both the original and target domain
   ;
   sub5.example.com.            IN CNAME sub6.example.com.
   _443._tcp.sub5.example.com.  IN TLSA 1 1 1 308202c5308201ab...
   sub6.example.com.            IN A 192.0.2.1
   sub6.example.com.            IN AAAA 2001:db8::1
   _443._tcp.sub6.example.com.  IN TLSA 1 1 1 ac49d9ba4570ac49...

   In this example, someone looking for the TLSA record for
   sub5.example.com would always get the record whose value starts with
   "308202c5308201ab"; the TLSA record whose value starts with
   "ac49d9ba4570ac49" would only be sought by someone who is looking for
   the TLSA record for sub6.example.com, and never for sub5.example.com.
   Note that deploying different certificates for multiple services
   located at a shared TLS listener often requires the use of TLS SNI
   (Server Name Indication) [RFC6066].





Hoffman & Schlyter           Standards Track                   [Page 29]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   Note that these methods use the normal method for DNS aliasing using
   CNAME: the DNS client requests the record type that they actually
   want.

A.2.1.2.  Provisioning TLSA Records with DNAME Records

   Using DNAME records allows a zone owner to alias an entire subtree of
   names below the name that has the DNAME.  This allows the wholesale
   aliasing of prefixed records such as those used by TLSA, SRV, and so
   on without aliasing the name itself.  However, because DNAME can only
   be used for subtrees of a base name, it is rarely used to alias
   individual hosts that might also be running TLS.

   ; TLSA record in target domain, visible in original domain via DNAME
   ;
   sub5.example.com.            IN CNAME sub6.example.com.
   _tcp.sub5.example.com.       IN DNAME _tcp.sub6.example.com.
   sub6.example.com.            IN A 192.0.2.1
   sub6.example.com.            IN AAAA 2001:db8::1
   _443._tcp.sub6.example.com.  IN TLSA 1 1 1 536a570ac49d9ba4...

A.2.1.3.  Provisioning TLSA Records with Wildcards

   Wildcards are generally not terribly useful for RRtypes that require
   prefixing because one can only wildcard at a layer below the host
   name.  For example, if one wants to have the same TLSA record for
   every TCP port for www.example.com, the result might be:

   *._tcp.www.example.com.    IN TLSA 1 1 1 5c1502a6549c423b...

   This is possibly useful in some scenarios where the same service is
   offered on many ports or the same certificate and/or key is used for
   all services on a host.  Note that the domain being searched for is
   not necessarily related to the domain name found in the certificate,
   so a certificate with a wildcard in it is not searched for using a
   wildcard in the search request.

A.3.  Securing the Last Hop

   As described in Section 4, an application processing TLSA records
   must know the DNSSEC validity of those records.  There are many ways
   for the application to determine this securely, and this
   specification does not mandate any single method.








Hoffman & Schlyter           Standards Track                   [Page 30]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   Some common methods for an application to know the DNSSEC validity of
   TLSA records include:

   o  The application can have its own DNS resolver and DNSSEC
      validation stack.

   o  The application can communicate through a trusted channel (such as
      requests to the operating system under which the application is
      running) to a local DNS resolver that does DNSSEC validation.

   o  The application can communicate through a secured channel (such as
      requests running over TLS, IPsec, TSIG, or SIG(0)) to a non-local
      DNS resolver that does DNSSEC validation.

   o  The application can communicate through a secured channel (such as
      requests running over TLS, IPsec, TSIG, or SIG(0)) to a non-local
      DNS resolver that does not do DNSSEC validation, but gets
      responses through a secured channel from a different DNS resolver
      that does DNSSEC validation.

A.4.  Handling Certificate Rollover

   Certificate rollover is handled in much the same way as for rolling
   DNSSEC zone signing keys using the pre-publish key rollover method
   [RFC4641].  Suppose example.com has a single TLSA record for a TLS
   service on TCP port 990:

   _990._tcp.example.com IN TLSA 1 1 1 1CFC98A706BCF3683015...

   To start the rollover process, obtain or generate the new certificate
   or SubjectPublicKeyInfo to be used after the rollover and generate
   the new TLSA record.  Add that record alongside the old one:

   _990._tcp.example.com IN TLSA 1 1 1 1CFC98A706BCF3683015...
   _990._tcp.example.com IN TLSA 1 1 1 62D5414CD1CC657E3D30...

   After the new records have propagated to the authoritative
   nameservers and the TTL of the old record has expired, switch to the
   new certificate on the TLS server.  Once this has occurred, the old
   TLSA record can be removed:

   _990._tcp.example.com IN TLSA 1 1 1 62D5414CD1CC657E3D30...

   This completes the certificate rollover.







Hoffman & Schlyter           Standards Track                   [Page 31]

RFC 6698            DNS-Based Authentication for TLS         August 2012


Appendix B.  Pseudocode for Using TLSA

   This appendix describes, in pseudocode format, the interactions given
   earlier in this specification.  If the steps below disagree with the
   text earlier in the document, the steps earlier in the document ought
   to be considered correct and this text incorrect.

   Note that this pseudocode is more strict than the normative text.
   For instance, it forces an order on the evaluation of criteria, which
   is not mandatory from the normative text.

B.1.  Helper Functions

   // implement the function for exiting
   function Finish (F) = {
     if (F == ABORT_TLS) {
       abort the TLS handshake or prevent TLS from starting
       exit
     }

     if (F == NO_TLSA) {
       fall back to non-TLSA certificate validation
       exit
     }

     if (F == ACCEPT) {
       accept the TLS connection
       exit
     }

     // unreachable
   }

   // implement the selector function
   function Select (S, X) = {
     // Full certificate
     if (S == 0) {
       return X in DER encoding
     }

     // SubjectPublicKeyInfo
     if (S == 1) {
       return X.SubjectPublicKeyInfo in DER encoding
     }

     // unreachable
   }




Hoffman & Schlyter           Standards Track                   [Page 32]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   // implement the matching function
   function Match (M, X, Y) {
     // Exact match on selected content
     if (M == 0) {
       return (X == Y)
     }

     // SHA-256 hash of selected content
     if (M == 1) {
       return (SHA-256(X) == Y)
     }

     // SHA-512 hash of selected content
     if (M == 2) {
       return (SHA-512(X) == Y)
     }

     // unreachable
   }

B.2.  Main TLSA Pseudocode

   TLS connect using [transport] to [name] on [port] and receiving end
   entity cert C for the TLS server:

   (TLSArecords, ValState) = DNSSECValidatedLookup(
     domainname=_[port]._[transport].[name], RRtype=TLSA)

   // check for states that would change processing
   if (ValState == BOGUS) {
     Finish(ABORT_TLS)
   }
   if ((ValState == INDETERMINATE) or (ValState == INSECURE)) {
     Finish(NO_TLSA)
   }
   // if here, ValState must be SECURE

   for each R in TLSArecords {
     // unusable records include unknown certUsage, unknown
     // selectorType, unknown matchingType, erroneous RDATA, and
     // prohibited by local policy
     if (R is unusable) {
       remove R from TLSArecords
     }
   }
   if (length(TLSArecords) == 0) {
     Finish(NO_TLSA)
   }



Hoffman & Schlyter           Standards Track                   [Page 33]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   // A TLS client might have multiple trust anchors that it might use
   //    when validating the TLS server's end entity (EE) certificate.
   //    Also, there can be multiple PKIX certification paths for the
   //    certificates given by the server in TLS.  Thus, there are
   //    possibly many chains that might need to be tested during
   //    PKIX path validation.

   for each R in TLSArecords {

     // pass PKIX certificate validation and chain through a CA cert
     //    that comes from TLSA
     if (R.certUsage == 0) {
       for each PKIX certification path H {
         if (C passes PKIX certification path validation in H) {
           for each D in H {
             if ((D is a CA certificate) and
                 Match(R.matchingType, Select(R.selectorType, D),
                       R.cert)) {
               Finish(ACCEPT)
             }
           }
         }
       }
     }

     // pass PKIX certificate validation and match EE cert from TLSA
     if (R.certUsage == 1) {
       for each PKIX certification path H {
         if ((C passes PKIX certificate validation in H) and
                 Match(R.matchingType, Select(R.selectorType, C),
                 R.cert)) {
             Finish(ACCEPT)
         }
       }
     }

     // pass PKIX certification validation using TLSA record as the
     //    trust anchor
     if (R.certUsage == 2) {
       // the following assert() is merely a formalization of the
       // "trust anchor" condition for a certificate D matching R
       assert(Match(R.matchingType, Select(R.selectorType, D), R.cert))









Hoffman & Schlyter           Standards Track                   [Page 34]

RFC 6698            DNS-Based Authentication for TLS         August 2012


       for each PKIX certification path H that has certificate D
           matching R as the trust anchor {
         if (C passes PKIX validation in H) {
           Finish(ACCEPT);
         }
       }
     }

     // match the TLSA record and the TLS certificate
     if (R.certUsage == 3) {
       if Match(R.matchingType, Select(R.selectorType, C), R.cert)
         Finish(ACCEPT)
       }
     }

   }

   // if here, then none of the TLSA records ended in "Finish(ACCEPT)"
   //   so abort TLS
   Finish(ABORT_TLS)

Appendix C.  Examples

   The following are examples of self-signed certificates that have been
   generated with various selectors and matching types.  They were
   generated with one piece of software, and validated by an individual
   using other tools.

   S = Selector
   M = Matching Type

   S M Association Data
   0 0 30820454308202BC020900AB58D24E77AD2AF6300D06092A86
       4886F70D0101050500306C310B3009060355040613024E4C31163014
       0603550408130D4E6F6F72642D486F6C6C616E643112301006035504
       071309416D7374657264616D310C300A060355040A13034F53333123
       30210603550403131A64616E652E6B6965762E70726163746963756D
       2E6F73332E6E6C301E170D3132303131363136353730335A170D3232
       303131333136353730335A306C310B3009060355040613024E4C3116
       30140603550408130D4E6F6F72642D486F6C6C616E64311230100603
       5504071309416D7374657264616D310C300A060355040A13034F5333
       312330210603550403131A64616E652E6B6965762E70726163746963
       756D2E6F73332E6E6C308201A2300D06092A864886F70D0101010500
       0382018F003082018A0282018100E62C84A5AFE59F0A2A6B250DEE68
       7AC8C5C604F57D26CEB2119140FFAC38C4B9CBBE8923082E7F81626B
       6AD5DEA0C8771C74E3CAA7F613054AEFA3673E48FFE47B3F7AF987DE
       281A68230B24B9DA1A98DCBE51195B60E42FD7517C328D983E26A827
       C877AB914EE4C1BFDEAD48BD25BE5F2C473BA9C1CBBDDDA0C374D0D5



Hoffman & Schlyter           Standards Track                   [Page 35]

RFC 6698            DNS-Based Authentication for TLS         August 2012


       8C389CC3D6D8C20662E19CF768F32441B7F7D14AEA8966CE7C32A172
       2AB38623D008029A9E4702883F8B977A1A1E5292BF8AD72239D40393
       37B86A3AC60FA001290452177BF1798609A05A130F033457A5212629
       FBDDB8E70E2A9E6556873C4F7CA46AE4A8B178F05FB319005E1C1C7D
       4BD77DFA34035563C126AA2C3328B900E7990AC9787F01DA82F74C3D
       4B6674CCECE1FD4C6EF9E6644F4635EDEDA39D8B0E2F7C8E06DAE775
       6213BD3D60831175BE290442B4AFC5AE6F46B769855A067C1097E617
       962529E166F22AEE10DDB981B8CD6FF17D3D70723169038DBFBC1A44
       9C8D0D31BC683C5F3CE26148E42EC9BBD4D9F261569B25B53C1D7FC2
       DDFF6B4CAC050203010001300D06092A864886F70D01010505000382
       0181002B2ABE063E9C86AC4A1F7835372091079C8276A9C2C5D1EC57
       64DE523FDDABDEAB3FD34E6FE6CBA054580A6785A663595D90132B93
       D473929E81FA0887D2FFF78A81C7D014B97778AB6AC9E5E690F6F5A9
       E92BB5FBAB71B857AE69B6E18BDCCB0BA6FCD9D4B084A34F3635148C
       495D48FE635903B888EC1DEB2610548EDD48D63F86513A4562469831
       48C0D5DB82D73A4C350A42BB661D763430FC6C8E5F9D13EA1B76AA52
       A4C358E5EA04000F794618303AB6CEEA4E9A8E9C74D73C1B0B7BAF16
       DEDE7696B5E2F206F777100F5727E1684D4132F5E692F47AF6756EA8
       B421000BE031B5D8F0220E436B51FB154FE9595333C13A2403F9DE08
       E5DDC5A22FD6182E339593E26374450220BC14F3E40FF33F084526B0
       9C34250702E8A352B332CCCB0F9DE2CF2B338823B92AFC61C0B6B8AB
       DB5AF718ED8DDA97C298E46B82A01B14814868CFA4F2C36268BFFF4A
       591F42658BF75918902D3E426DFE1D5FF0FC6A212071F6DA8BD833FE
       2E560D87775E8EE9333C05B6FB8EB56589D910DB5EA903

   0 1 EFDDF0D915C7BDC5782C0881E1B2A95AD099FBDD06D7B1F779
       82D9364338D955

   0 2 81EE7F6C0ECC6B09B7785A9418F54432DE630DD54DC6EE9E3C
       49DE547708D236D4C413C3E97E44F969E635958AA410495844127C04
       883503E5B024CF7A8F6A94

   1 0 308201A2300D06092A864886F70D01010105000382018F0030
       82018A0282018100E62C84A5AFE59F0A2A6B250DEE687AC8C5C604F5
       7D26CEB2119140FFAC38C4B9CBBE8923082E7F81626B6AD5DEA0C877
       1C74E3CAA7F613054AEFA3673E48FFE47B3F7AF987DE281A68230B24
       B9DA1A98DCBE51195B60E42FD7517C328D983E26A827C877AB914EE4
       C1BFDEAD48BD25BE5F2C473BA9C1CBBDDDA0C374D0D58C389CC3D6D8
       C20662E19CF768F32441B7F7D14AEA8966CE7C32A1722AB38623D008
       029A9E4702883F8B977A1A1E5292BF8AD72239D4039337B86A3AC60F
       A001290452177BF1798609A05A130F033457A5212629FBDDB8E70E2A
       9E6556873C4F7CA46AE4A8B178F05FB319005E1C1C7D4BD77DFA3403
       5563C126AA2C3328B900E7990AC9787F01DA82F74C3D4B6674CCECE1
       FD4C6EF9E6644F4635EDEDA39D8B0E2F7C8E06DAE7756213BD3D6083
       1175BE290442B4AFC5AE6F46B769855A067C1097E617962529E166F2
       2AEE10DDB981B8CD6FF17D3D70723169038DBFBC1A449C8D0D31BC68
       3C5F3CE26148E42EC9BBD4D9F261569B25B53C1D7FC2DDFF6B4CAC05
       0203010001



Hoffman & Schlyter           Standards Track                   [Page 36]

RFC 6698            DNS-Based Authentication for TLS         August 2012


   1 1 8755CDAA8FE24EF16CC0F2C918063185E433FAAF1415664911
       D9E30A924138C4

   1 2 D43165B4CDF8F8660AECCCC5344D9D9AE45FFD7E6AAB7AB9EE
       C169B58E11F227ED90C17330CC17B5CCEF0390066008C720CEC6AAE5
       33A934B3A2D7E232C94AB4

Authors' Addresses

   Paul Hoffman
   VPN Consortium

   EMail: paul.hoffman@vpnc.org


   Jakob Schlyter
   Kirei AB

   EMail: jakob@kirei.se
































Hoffman & Schlyter           Standards Track                   [Page 37]


```

---

# RFC 7671 — DANE — TLSA (opérationnel)

```






Internet Engineering Task Force (IETF)                       V. Dukhovni
Request for Comments: 7671                                     Two Sigma
Updates: 6698                                                W. Hardaker
Category: Standards Track                                        Parsons
ISSN: 2070-1721                                             October 2015


    The DNS-Based Authentication of Named Entities (DANE) Protocol:
                    Updates and Operational Guidance

Abstract

   This document clarifies and updates the DNS-Based Authentication of
   Named Entities (DANE) TLSA specification (RFC 6698), based on
   subsequent implementation experience.  It also contains guidance for
   implementers, operators, and protocol developers who want to use DANE
   records.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 5741.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc7671.

Copyright Notice

   Copyright (c) 2015 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.





Dukhovni & Hardaker          Standards Track                    [Page 1]

RFC 7671                     DANE Operations                October 2015


Table of Contents

   1. Introduction ....................................................3
      1.1. Terminology ................................................4
   2. DANE TLSA Record Overview .......................................5
      2.1. Example TLSA Record ........................................6
   3. DANE TLS Requirements ...........................................6
   4. DANE Certificate Usage Selection Guidelines .....................7
      4.1. Opportunistic Security and PKIX Usages .....................7
      4.2. Interaction with Certificate Transparency ..................8
      4.3. Switching from/to PKIX-TA/EE to/from DANE-TA/EE ............9
   5. Certificate-Usage-Specific DANE Updates and Guidelines ..........9
      5.1. Certificate Usage DANE-EE(3) ...............................9
      5.2. Certificate Usage DANE-TA(2) ..............................11
      5.3. Certificate Usage PKIX-EE(1) ..............................15
      5.4. Certificate Usage PKIX-TA(0) ..............................15
   6. Service Provider and TLSA Publisher Synchronization ............16
   7. TLSA Base Domain and CNAMEs ....................................18
   8. TLSA Publisher Requirements ....................................19
      8.1. Key Rollover with Fixed TLSA Parameters ...................20
      8.2. Switching to DANE-TA(2) from DANE-EE(3) ...................21
      8.3. Switching to New TLSA Parameters ..........................22
      8.4. TLSA Publisher Requirements: Summary ......................23
   9. Digest Algorithm Agility .......................................23
   10. General DANE Guidelines .......................................25
      10.1. DANE DNS Record Size Guidelines ..........................25
      10.2. Certificate Name Check Conventions .......................26
      10.3. Design Considerations for Protocols Using DANE ...........27
   11. Note on DNSSEC Security .......................................28
   12. Summary of Updates to RFC 6698 ................................29
   13. Operational Considerations ....................................29
   14. Security Considerations .......................................30
   15. References ....................................................30
      15.1. Normative References .....................................30
      15.2. Informative References ...................................32
   Acknowledgements ..................................................33
   Authors' Addresses ................................................33














Dukhovni & Hardaker          Standards Track                    [Page 2]

RFC 7671                     DANE Operations                October 2015


1.  Introduction

   The DNS-Based Authentication of Named Entities (DANE) specification
   [RFC6698] introduces the DNS "TLSA" resource record (RR) type ("TLSA"
   is not an acronym).  TLSA records associate a certificate or a public
   key of an end-entity or a trusted issuing authority with the
   corresponding Transport Layer Security (TLS) [RFC5246] or Datagram
   Transport Layer Security (DTLS) [RFC6347] transport endpoint.  DANE
   relies on the DNS Security Extensions (DNSSEC) [RFC4033].  DANE TLSA
   records validated by DNSSEC can be used to augment or replace the use
   of trusted public Certification Authorities (CAs).

   The TLS and DTLS protocols provide secured TCP and UDP communication,
   respectively, over IP.  In the context of this document, channel
   security is assumed to be provided by TLS or DTLS.  By convention,
   "TLS" will be used throughout this document; unless otherwise
   specified, the text applies equally well to DTLS over UDP.  Used
   without authentication, TLS provides protection only against
   eavesdropping through its use of encryption.  With authentication,
   TLS also protects the transport against man-in-the-middle (MITM)
   attacks.

   [RFC6698] defines three TLSA record fields: the first with four
   possible values, the second with two, and the third with three.
   These yield 24 distinct combinations of TLSA record types.  This
   document recommends a smaller set of best-practice combinations of
   these fields to simplify protocol design, implementation, and
   deployment.

   This document explains and recommends DANE-specific strategies to
   simplify "virtual hosting", where a single Service Provider transport
   endpoint simultaneously supports multiple hosted Customer Domains.

   Other related documents that build on [RFC6698] are [RFC7673] and
   [RFC7672].

   Section 12 summarizes the normative updates this document makes to
   [RFC6698].













Dukhovni & Hardaker          Standards Track                    [Page 3]

RFC 7671                     DANE Operations                October 2015


1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   [RFC2119].

   The following terms are used throughout this document:

   Web PKI:  The Public Key Infrastructure (PKI) model employed by
      browsers to authenticate web servers.  This employs a set of
      trusted public CAs to vouch for the authenticity of public keys
      associated with a particular party (the subject).

   Service Provider:  A company or organization that offers to host a
      service on behalf of the owner of a Customer Domain.  The original
      domain name associated with the service often remains under the
      control of the customer.  Connecting applications may be directed
      to the Service Provider via a redirection RR.  Example redirection
      records include MX, SRV, and CNAME.  The Service Provider
      frequently provides services for many customers and needs to
      ensure that the TLS credentials presented to connecting
      applications authenticate it as a valid server for the requested
      domain.

   Customer Domain:  As described above, a TLS client may be interacting
      with a service that is hosted by a third party.  This document
      refers to the domain name used to locate the service (prior to any
      redirection) as the "Customer Domain".

   TLSA Publisher:  The entity responsible for publishing a TLSA record
      within a DNS zone.  This zone will be assumed DNSSEC-signed and
      validatable to a trust anchor (TA), unless otherwise specified.
      If the Customer Domain is not outsourcing its DNS service, the
      TLSA Publisher will be the customer itself.  Otherwise, the TLSA
      Publisher may be the operator of the outsourced DNS service.

   Public key:  The term "public key" is shorthand for the
      subjectPublicKeyInfo component of a PKIX [RFC5280] certificate.

   SNI:  The Server Name Indication (SNI) TLS protocol extension allows
      a TLS client to request a connection to a particular service name
      of a TLS server ([RFC6066], Section 3).  Without this TLS
      extension, a TLS server has no choice but to offer a certificate
      with a default list of server names, making it difficult to host
      multiple Customer Domains at the same IP-address-based TLS service
      endpoint (i.e., provide "secure virtual hosting").




Dukhovni & Hardaker          Standards Track                    [Page 4]

RFC 7671                     DANE Operations                October 2015


   TLSA parameters:  In [RFC6698], the TLSA record is defined to consist
      of four fields.  The first three of these are numeric parameters
      that specify the meaning of the data in the fourth and final
      field.  This document refers to the first three fields as "TLSA
      parameters", or sometimes just "parameters" when obvious from
      context.

   TLSA base domain:  Per Section 3 of [RFC6698], TLSA records are
      stored at a DNS domain name that is a combination of a port and
      protocol prefix and a "base domain".  In [RFC6698], the "base
      domain" is the fully qualified domain name of the TLS server.
      This document modifies the TLSA record lookup strategy to prefer
      the fully CNAME-expanded name of the TLS server, provided that
      expansion is "secure" (DNSSEC validated) at each stage of the
      expansion, and TLSA records are published for this fully expanded
      name.  Thus, the "TLSA base domain" is either the fully
      CNAME-expanded TLS server name or otherwise the initial fully
      qualified TLS server name, whichever is used in combination with a
      port and protocol prefix to obtain the TLSA RRset.

2.  DANE TLSA Record Overview

   DANE TLSA [RFC6698] specifies a protocol for publishing TLS server
   certificate associations via DNSSEC [RFC4033] [RFC4034] [RFC4035].
   DANE TLSA records consist of four fields.  The record type is
   determined by the values of the first three fields, which this
   document refers to as the "TLSA parameters" to distinguish them from
   the fourth and last field.  The numeric values of these parameters
   were given symbolic names in [RFC7218].  The four fields are as
   follows:

   The Certificate Usage field:  Section 2.1.1 of [RFC6698] specifies
      four values: PKIX-TA(0), PKIX-EE(1), DANE-TA(2), and DANE-EE(3).
      There is an additional private-use value: PrivCert(255), which,
      given its private scope, shall not be considered further in this
      document.  All other values are reserved for use by future
      specifications.

   The Selector field:  Section 2.1.2 of [RFC6698] specifies two values:
      Cert(0) and SPKI(1).  There is an additional private-use value:
      PrivSel(255).  All other values are reserved for use by future
      specifications.

   The Matching Type field:  Section 2.1.3 of [RFC6698] specifies three
      values: Full(0), SHA2-256(1), and SHA2-512(2).  There is an
      additional private-use value: PrivMatch(255).  All other values
      are reserved for use by future specifications.




Dukhovni & Hardaker          Standards Track                    [Page 5]

RFC 7671                     DANE Operations                October 2015


   The Certificate Association Data field:  See Section 2.1.4 of
      [RFC6698].  This field stores the full value or digest of the
      certificate or subject public key as determined by the matching
      type and selector, respectively.

   In the Matching Type field, of the two digest algorithms --
   SHA2-256(1) and SHA2-512(2) -- as of the time of this writing, only
   SHA2-256(1) is mandatory to implement.  Clients SHOULD implement
   SHA2-512(2), but servers SHOULD NOT exclusively publish SHA2-512(2)
   digests.  The digest algorithm agility protocol defined in Section 9
   SHOULD be used by clients to decide how to process TLSA RRsets that
   employ multiple digest algorithms.  Server operators MUST publish
   TLSA RRsets that are compatible (see Section 8) with digest algorithm
   agility (Section 9).

2.1.  Example TLSA Record

   In the example TLSA record below, the TLSA certificate usage is
   DANE-TA(2), the selector is Cert(0), and the matching type is
   SHA2-256(1).  The last field is the Certificate Association Data
   field, which in this case contains the SHA2-256 digest of the server
   certificate.

   _25._tcp.mail.example.com. IN TLSA 2 0 1 (
                              E8B54E0B4BAA815B06D3462D65FBC7C0
                              CF556ECCF9F5303EBFBB77D022F834C0 )

3.  DANE TLS Requirements

   [RFC6698] does not discuss what versions of TLS are required when
   using DANE records.  This document specifies that TLS clients that
   support DANE/TLSA MUST support at least TLS 1.0 and SHOULD support
   TLS 1.2 or later.

   TLS clients using DANE MUST support the SNI extension of TLS
   [RFC6066].  Servers MAY support SNI and respond with a matching
   certificate chain but MAY also ignore SNI and respond with a default
   certificate chain.  When a server supports SNI but is not configured
   with a certificate chain that exactly matches the client's SNI
   extension, the server SHOULD respond with another certificate chain
   (a default or closest match).  This is because clients might support
   more than one server name but can only put a single name in the SNI
   extension.








Dukhovni & Hardaker          Standards Track                    [Page 6]

RFC 7671                     DANE Operations                October 2015


4.  DANE Certificate Usage Selection Guidelines

   As mentioned in Section 2, the TLSA Certificate Usage field takes one
   of four possible values.  With PKIX-TA(0) and PKIX-EE(1), the
   validation of peer certificate chains requires additional
   preconfigured CA TAs that are mutually trusted by the operators of
   the TLS server and client.  With DANE-TA(2) and DANE-EE(3), no
   preconfigured CA TAs are required and the published DANE TLSA records
   are sufficient to verify the peer's certificate chain.

   Standards for application protocols that employ DANE TLSA can specify
   more specific guidance than [RFC6698] or this document.  Such
   application-specific standards need to carefully consider which set
   of DANE certificate usages to support.  Simultaneous support for all
   four usages is NOT RECOMMENDED for DANE clients.  When all four
   usages are supported, an attacker capable of compromising the
   integrity of DNSSEC needs only to replace the server's TLSA RRset
   with one that lists suitable DANE-EE(3) or DANE-TA(2) records,
   effectively bypassing any added verification via public CAs.  In
   other words, when all four usages are supported, PKIX-TA(0) and
   PKIX-EE(1) offer only illusory incremental security over DANE-TA(2)
   and DANE-EE(3).

   Designs in which clients support just the DANE-TA(2) and DANE-EE(3)
   certificate usages are RECOMMENDED.  With DANE-TA(2) and DANE-EE(3),
   clients don't need to track a large changing list of X.509 TAs in
   order to successfully authenticate servers whose certificates are
   issued by a CA that is brand new or not widely trusted.

   The DNSSEC TLSA records for servers MAY include both sets of usages
   if the server needs to support a mixture of clients, some supporting
   one pair of usages and some the other.

4.1.  Opportunistic Security and PKIX Usages

   When the client's protocol design is based on "Opportunistic
   Security" (OS) [RFC7435] and the use of authentication is based on
   the presence of server TLSA records, it is especially important to
   avoid the PKIX-EE(1) and PKIX-TA(0) certificate usages.

   When authenticated TLS is used opportunistically based on the
   presence of DANE TLSA records and no secure TLSA records are present,
   unauthenticated TLS is used if possible, and if TLS is not possible,
   perhaps even cleartext.  However, if usable secure TLSA records are
   published, then authentication MUST succeed.  Also, outside the
   browser space, there is no preordained canon of trusted CAs, and in
   any case there is no security advantage in using PKIX-TA(0) or




Dukhovni & Hardaker          Standards Track                    [Page 7]

RFC 7671                     DANE Operations                October 2015


   PKIX-EE(1) when the DANE-TA(2) and DANE-EE(3) usages are also
   supported (as an attacker who can compromise DNS can replace the
   former with the latter).

   Authentication via the PKIX-TA(0) and PKIX-EE(1) certificate usages
   is more brittle; the client and server need to happen to agree on a
   mutually trusted CA, but with OS the client is just trying to protect
   the communication channel at the request of the server and would
   otherwise be willing to use cleartext or unauthenticated TLS.  The
   use of fragile mechanisms (like public CA authentication for some
   unspecified set of trusted CAs) is not sufficiently reliable for an
   OS client to honor the server's request for authentication.  OS needs
   to be non-intrusive and to require few, if any, workarounds for valid
   but mismatched peers.

   Because the PKIX-TA(0) and PKIX-EE(1) usages offer no more security
   and are more prone to failure, they are a poor fit for OS and
   SHOULD NOT be used in that context.

4.2.  Interaction with Certificate Transparency

   Certificate Transparency (CT) [RFC6962] defines an experimental
   approach that could be used to mitigate the risk of rogue or
   compromised public CAs issuing unauthorized certificates.  This
   section clarifies the interaction of the experimental CT and DANE.
   This section may need to be revised in light of any future Standards
   Track version of CT.

   When a server is authenticated via a DANE TLSA RR with TLSA
   certificate usage DANE-EE(3), the domain owner has directly specified
   the certificate associated with the given service without reference
   to any public CA.  Therefore, when a TLS client authenticates the TLS
   server via a TLSA record with usage DANE-EE(3), CT checks SHOULD NOT
   be performed.  Publication of the server certificate or public key
   (digest) in a TLSA record in a DNSSEC-signed zone by the domain owner
   assures the TLS client that the certificate is not an unauthorized
   certificate issued by a rogue CA without the domain owner's consent.

   When a server is authenticated via a DANE TLSA record with TLSA usage
   DANE-TA(2) and the server certificate does not chain to a known
   public root CA, CT cannot apply (CT logs only accept chains that
   start with a known public root).  Since TLSA certificate usage
   DANE-TA(2) is generally intended to support non-public TAs, TLS
   clients SHOULD NOT perform CT checks with usage DANE-TA(2).







Dukhovni & Hardaker          Standards Track                    [Page 8]

RFC 7671                     DANE Operations                October 2015


   With certificate usages PKIX-TA(0) and PKIX-EE(1), CT applies just as
   it would without DANE.  TLSA records of this type only constrain
   which CAs are acceptable in PKIX validation.  All checks used in the
   absence of DANE still apply when validating certificate chains with
   DANE PKIX-TA(0) and PKIX-EE(1) constraints.

4.3.  Switching from/to PKIX-TA/EE to/from DANE-TA/EE

   The choice of preferred certificate usages may need to change as an
   application protocol evolves.  When transitioning between PKIX-TA/
   PKIX-EE and DANE-TA/DANE-EE, clients begin to enable support for the
   new certificate usage values.  If the new preferred certificate
   usages are PKIX-TA/EE, this requires installing and managing the
   appropriate set of CA TAs.  During this time, servers will publish
   both types of TLSA records.  At some later time, when the vast
   majority of servers have published the new preferred TLSA records,
   clients can stop supporting the legacy certificate usages.
   Similarly, servers can stop publishing legacy TLSA records once the
   vast majority of clients support the new certificate usages.

5.  Certificate-Usage-Specific DANE Updates and Guidelines

   The four certificate usage values from the TLSA record -- DANE-EE(3),
   DANE-TA(2), PKIX-EE(1), and PKIX-TA(0) -- are discussed below.

5.1.  Certificate Usage DANE-EE(3)

   In this section, the meaning of DANE-EE(3) is updated from [RFC6698]
   to specify that peer identity matching and validity period
   enforcement are based solely on the TLSA RRset properties.  This
   document also extends [RFC6698] to cover the use of DANE
   authentication of raw public keys [RFC7250] via TLSA records with
   certificate usage DANE-EE(3) and selector SPKI(1).

   Authentication via certificate usage DANE-EE(3) TLSA records involves
   simply checking that the server's leaf certificate matches the TLSA
   record.  In particular, the binding of the server public key to its
   name is based entirely on the TLSA record association.  The server
   MUST be considered authenticated even if none of the names in the
   certificate match the client's reference identity for the server.
   This simplifies the operation of servers that host multiple Customer
   Domains, as a single certificate can be associated with multiple
   domains without having to match each of the corresponding reference
   identifiers.







Dukhovni & Hardaker          Standards Track                    [Page 9]

RFC 7671                     DANE Operations                October 2015


   ; Multiple Customer Domains hosted by an example.net
   ; Service Provider:
   ;
   www.example.com.              IN CNAME ex-com.example.net.
   www.example.org.              IN CNAME ex-org.example.net.
   ;
   ; In the provider's DNS zone, a single certificate and TLSA
   ; record support multiple Customer Domains, greatly simplifying
   ; "virtual hosting".
   ;
   ex-com.example.net.           IN A 192.0.2.1
   ex-org.example.net.           IN A 192.0.2.1
   _443._tcp.ex-com.example.net. IN CNAME tlsa._dane.example.net.
   _443._tcp.ex-org.example.net. IN CNAME tlsa._dane.example.net.
   tlsa._dane.example.net.       IN TLSA 3 1 1 e3b0c44298fc1c14...

   Also, with DANE-EE(3), the expiration date of the server certificate
   MUST be ignored.  The validity period of the TLSA record key binding
   is determined by the validity period of the TLSA record DNSSEC
   signatures.  Validity is reaffirmed on an ongoing basis by continuing
   to publish the TLSA record and signing the zone in which the record
   is contained, rather than via dates "set in stone" in the
   certificate.  The expiration becomes a reminder to the administrator
   that it is likely time to rotate the key, but missing the date no
   longer causes an outage.  When keys are rotated (for whatever
   reason), it is important to follow the procedures outlined in
   Section 8.

   If a server uses just DANE-EE(3) TLSA records and all its clients are
   DANE clients, the server need not employ SNI (i.e., it may ignore the
   client's SNI message) even when the server is known via multiple
   domain names that would otherwise require separate certificates.  It
   is instead sufficient for the TLSA RRsets for all the domain names in
   question to match the server's default certificate.  For application
   protocols where the server name is obtained indirectly via SRV
   records, MX records, or similar records, it is simplest to publish a
   single hostname as the target server name for all the hosted domains.

   In organizations where it is practical to make coordinated changes in
   DNS TLSA records before server key rotation, it is generally best to
   publish end-entity DANE-EE(3) certificate associations in preference
   to other choices of certificate usage.  DANE-EE(3) TLSA records
   support multiple server names without SNI, don't suddenly stop
   working when leaf or intermediate certificates expire, and don't fail
   when a server operator neglects to include all the required issuer
   certificates in the server certificate chain.





Dukhovni & Hardaker          Standards Track                   [Page 10]

RFC 7671                     DANE Operations                October 2015


   More specifically, it is RECOMMENDED that at most sites TLSA records
   published for DANE servers be "DANE-EE(3) SPKI(1) SHA2-256(1)"
   records.  Selector SPKI(1) is chosen because it is compatible with
   raw public keys [RFC7250] and the resulting TLSA record need not
   change across certificate renewals with the same key.  Matching type
   SHA2-256(1) is chosen because all DANE implementations are required
   to support SHA2-256.  This TLSA record type easily supports hosting
   arrangements with a single certificate matching all hosted domains.
   It is also the easiest to implement correctly in the client.

   Clients that support raw public keys can use DANE TLSA records with
   certificate usage DANE-EE(3) and selector SPKI(1) to authenticate
   servers that negotiate the use of raw public keys.  Provided the
   server adheres to the requirements of Section 8, the fact that raw
   public keys are not compatible with any other TLSA record types will
   not get in the way of successful authentication.  Clients that employ
   DANE to authenticate the peer server SHOULD NOT negotiate the use of
   raw public keys unless the server's TLSA RRset includes "DANE-EE(3)
   SPKI(1)" TLSA records.

   While it is, in principle, also possible to authenticate raw public
   keys via "DANE-EE(3) Cert(0) Full(0)" records by extracting the
   public key from the certificate in DNS, extracting just the public
   key from a "3 0 0" TLSA record requires extra logic on clients that
   not all implementations are expected to provide.  Servers that wish
   to support [RFC7250] raw public keys need to publish TLSA records
   with a certificate usage of DANE-EE(3) and a selector of SPKI(1).

   While DANE-EE(3) TLSA records are expected to be by far the most
   prevalent, as explained in Section 5.2, DANE-TA(2) records are a
   valid alternative for sites with many DANE services.  Note, however,
   that virtual hosting is more complex with DANE-TA(2).  Also, with
   DANE-TA(2), server operators MUST ensure that the server is
   configured with a sufficiently complete certificate chain and need to
   remember to replace certificates prior to their expiration dates.

5.2.  Certificate Usage DANE-TA(2)

   This section updates [RFC6698] by specifying a new operational
   requirement for servers publishing TLSA records with a usage of
   DANE-TA(2): such servers MUST include the TA certificate in their TLS
   server certificate message unless all such TLSA records are "2 0 0"
   records that publish the server certificate in full.

   Some domains may prefer to avoid the operational complexity of
   publishing unique TLSA RRs for each TLS service.  If the domain
   employs a common issuing CA to create certificates for multiple TLS
   services, it may be simpler to publish the issuing authority as a TA



Dukhovni & Hardaker          Standards Track                   [Page 11]

RFC 7671                     DANE Operations                October 2015


   for the certificate chains of all relevant services.  The TLSA query
   domain (TLSA base domain with port and protocol prefix labels) for
   each service issued by the same TA may then be set to a CNAME alias
   that points to a common TLSA RRset that matches the TA.  For example:

   ; Two servers, each with its own certificate, that share
   ; a common issuer (TA).
   ;
   www1.example.com.            IN A 192.0.2.1
   www2.example.com.            IN A 192.0.2.2
   _443._tcp.www1.example.com.  IN CNAME tlsa._dane.example.com.
   _443._tcp.www2.example.com.  IN CNAME tlsa._dane.example.com.
   tlsa._dane.example.com.      IN TLSA 2 0 1 e3b0c44298fc1c14...

   The above configuration simplifies server key rotation, because while
   the servers continue to receive new certificates from a CA matched by
   the shared (target of the CNAMEs) TLSA record, server certificates
   can be updated without making any DNS changes.  As the list of active
   issuing CAs changes, the shared TLSA record will be updated (much
   less frequently) by the administrators who manage the CAs.  Those
   administrators still need to perform TLSA record updates with care,
   as described in Section 8.

   With usage DANE-TA(2), the server certificates will need to have
   names that match one of the client's reference identifiers (see
   [RFC6125]).  When hosting multiple unrelated Customer Domains (that
   can't all appear in a single certificate), such a server SHOULD
   employ SNI to select the appropriate certificate to present to the
   client.

5.2.1.  Recommended Record Combinations

   TLSA records with a matching type of Full(0) are NOT RECOMMENDED.
   While these potentially obviate the need to transmit the TA
   certificate in the TLS server certificate message, client
   implementations may not be able to augment the server certificate
   chain with the data obtained from DNS, especially when the TLSA
   record supplies a bare key (selector SPKI(1)).  Since the server will
   need to transmit the TA certificate in any case, server operators
   SHOULD publish TLSA records with a matching type other than Full(0)
   and avoid potential DNS interoperability issues with large TLSA
   records containing full certificates or keys (see Section 10.1.1).









Dukhovni & Hardaker          Standards Track                   [Page 12]

RFC 7671                     DANE Operations                October 2015


   TLSA Publishers employing DANE-TA(2) records SHOULD publish records
   with a selector of Cert(0).  Such TLSA records are associated with
   the whole TA certificate, not just with the TA public key.  In
   particular, when authenticating the peer certificate chain via such a
   TLSA record, the client SHOULD apply any relevant constraints from
   the TA certificate, such as, for example, path length constraints.

   While a selector of SPKI(1) may also be employed, the resulting TLSA
   record will not specify the full TA certificate content, and elements
   of the TA certificate other than the public key become mutable.  This
   may, for example, enable a subsidiary CA to issue a chain that
   violates the TA's path length or name constraints.

5.2.2.  Trust Anchor Digests and Server Certificate Chain

   With DANE-TA(2), a complication arises when the TA certificate is
   omitted from the server's certificate chain, perhaps on the basis of
   Section 7.4.2 of [RFC5246]:

      The sender's certificate MUST come first in the list.  Each
      following certificate MUST directly certify the one preceding it.
      Because certificate validation requires that root keys be
      distributed independently, the self-signed certificate that
      specifies the root certificate authority MAY be omitted from the
      chain, under the assumption that the remote end must already
      possess it in order to validate it in any case.

   With TLSA certificate usage DANE-TA(2), there is no expectation that
   the client is preconfigured with the TA certificate.  In fact, client
   implementations are free to ignore all locally configured TAs when
   processing usage DANE-TA(2) TLSA records and may rely exclusively on
   the certificates provided in the server's certificate chain.  But,
   with a digest in the TLSA record, the TLSA record contains neither
   the full TA certificate nor the full public key.  If the TLS server's
   certificate chain does not contain the TA certificate, DANE clients
   will be unable to authenticate the server.

   TLSA Publishers that publish TLSA certificate usage DANE-TA(2)
   associations with a selector of SPKI(1) or with a digest-based
   matching type (not Full(0)) MUST ensure that the corresponding server
   is configured to also include the TA certificate in its TLS handshake
   certificate chain, even if that certificate is a self-signed root CA
   and would have been optional in the context of the existing public
   CA PKI.







Dukhovni & Hardaker          Standards Track                   [Page 13]

RFC 7671                     DANE Operations                October 2015


   Only when the server TLSA record includes a "DANE-TA(2) Cert(0)
   Full(0)" TLSA record containing a full TA certificate is the TA
   certificate optional in the server's TLS certificate message.  This
   is also the only type of DANE-TA(2) record for which the client MUST
   be able to verify the server's certificate chain even if the TA
   certificate appears only in DNS and is absent from the TLS handshake
   server certificate message.

5.2.3.  Trust Anchor Public Keys

   TLSA records with TLSA certificate usage DANE-TA(2), selector
   SPKI(1), and a matching type of Full(0) publish the full public key
   of a TA via DNS.  In Section 6.1.1 of [RFC5280], the definition of a
   TA consists of the following four parts:

   1.  the trusted issuer name,

   2.  the trusted public key algorithm,

   3.  the trusted public key, and

   4.  optionally, the trusted public key parameters associated with the
       public key.

   Items 2-4 are precisely the contents of the subjectPublicKeyInfo
   published in the TLSA record.  The issuer name is not included in the
   subjectPublicKeyInfo.

   With TLSA certificate usage DANE-TA(2), the client may not have the
   associated TA certificate and cannot generally verify whether or not
   a particular certificate chain is "issued by" the TA described in the
   TLSA record.

   When the server certificate chain includes a CA certificate whose
   public key matches the TLSA record, the client can match that CA as
   the intended issuer.  Otherwise, the client can only check that the
   topmost certificate in the server's chain is "signed by" the TA's
   public key in the TLSA record.  Such a check may be difficult to
   implement and cannot be expected to be supported by all clients.

   Thus, servers cannot rely on "DANE-TA(2) SPKI(1) Full(0)" TLSA
   records to be sufficient to authenticate chains issued by the
   associated public key in the absence of a corresponding certificate
   in the server's TLS certificate message.  Servers employing "2 1 0"
   TLSA records MUST include the corresponding TA certificate in their
   certificate chain.





Dukhovni & Hardaker          Standards Track                   [Page 14]

RFC 7671                     DANE Operations                October 2015


   If none of the server's certificate chain elements match a public key
   specified in a TLSA record, and at least one "DANE-TA(2) SPKI(1)
   Full(0)" TLSA record is available, it is RECOMMENDED that clients
   check to see whether or not the topmost certificate in the chain is
   signed by the provided public key and has not expired, and in that
   case consider the server authenticated, provided the rest of the
   chain passes validation, including leaf certificate name checks.

5.3.  Certificate Usage PKIX-EE(1)

   This certificate usage is similar to DANE-EE(3); but, in addition,
   PKIX verification is required.  Therefore, name checks, certificate
   expiration, CT, etc. apply as they would without DANE.

5.4.  Certificate Usage PKIX-TA(0)

   This section updates [RFC6698] by specifying new client
   implementation requirements.  Clients that trust intermediate
   certificates MUST be prepared to construct longer PKIX chains than
   would be required for PKIX alone.

   TLSA certificate usage PKIX-TA(0) allows a domain to publish
   constraints on the set of PKIX CAs trusted to issue certificates for
   its TLS servers.  A PKIX-TA(0) TLSA record matches PKIX-verified
   trust chains that contain an issuer certificate (root or
   intermediate) that matches its Certificate Association Data field
   (typically a certificate or digest).

   PKIX-TA(0) requires more complex coordination (than with DANE-TA(2)
   or DANE-EE(3)) between the Customer Domain and the Service Provider
   in hosting arrangements.  Thus, this certificate usage is
   NOT RECOMMENDED when the Service Provider is not also the TLSA
   Publisher (at the TLSA base domain obtained via CNAMEs, SRV records,
   or MX records).

   TLSA Publishers who publish TLSA records for a particular public root
   CA will expect that clients will only accept chains anchored at that
   root.  It is possible, however, that the client's trusted certificate
   store includes some intermediate CAs, either with or without the
   corresponding root CA.  When a client constructs a trust chain
   leading from a trusted intermediate CA to the server leaf
   certificate, such a "truncated" chain might not contain the trusted
   root published in the server's TLSA record.

   If the omitted root is also trusted, the client may erroneously
   reject the server chain if it fails to determine that the shorter
   chain it constructed extends to a longer trusted chain that matches
   the TLSA record.  Thus, when matching a usage PKIX-TA(0) TLSA record,



Dukhovni & Hardaker          Standards Track                   [Page 15]

RFC 7671                     DANE Operations                October 2015


   so long as no matching certificate has yet been found, a client MUST
   continue extending the chain even after any locally trusted
   certificate is found.  If no TLSA records have matched any of the
   elements of the chain and the trusted certificate found is not
   self-issued, the client MUST attempt to build a longer chain in case
   a certificate closer to the root matches the server's TLSA record.

6.  Service Provider and TLSA Publisher Synchronization

   Whenever possible, the TLSA Publisher and the Service Provider should
   be the same entity.  Otherwise, they need to coordinate changes to
   ensure that TLSA records published by the TLSA Publisher don't fall
   out of sync with the server certificate used by the Service Provider.
   Such coordination is difficult, and service outages will result when
   coordination fails.

   Publishing the TLSA record in the Service Provider's zone avoids the
   complexity of bilateral coordination of server certificate
   configuration and TLSA record management.  Even when the TLSA RRset
   has to be published in the Customer Domain's DNS zone (perhaps the
   client application does not "chase" CNAMEs to the TLSA base domain),
   it is possible to employ CNAME records to delegate the content of the
   TLSA RRset to a domain operated by the Service Provider.

   Only certificate usages DANE-EE(3) and DANE-TA(2) work well with TLSA
   CNAMEs across organizational boundaries.  With PKIX-TA(0) or
   PKIX-EE(1), the Service Provider would need to obtain certificates in
   the name of the Customer Domain from a suitable public CA (securely
   impersonate the customer), or the customer would need to provision
   the relevant private keys and certificates at the Service Provider's
   systems.

   Certificate Usage DANE-EE(3):  In this case, the Service Provider can
      publish a single TLSA RRset that matches the server certificate or
      public key digest.  The same RRset works for all Customer Domains
      because name checks do not apply with DANE-EE(3) TLSA records (see
      Section 5.1).  A Customer Domain can create a CNAME record
      pointing to the TLSA RRset published by the Service Provider.

   Certificate Usage DANE-TA(2):  When the Service Provider operates a
      private CA, the Service Provider is free to issue a certificate
      bearing any customer's domain name.  Without DANE, such a
      certificate would not pass trust verification, but with DANE, the
      customer's TLSA RRset that is aliased to the provider's TLSA RRset
      can delegate authority to the provider's CA for the corresponding
      service.  The Service Provider can generate appropriate





Dukhovni & Hardaker          Standards Track                   [Page 16]

RFC 7671                     DANE Operations                October 2015


      certificates for each customer and use the SNI information
      provided by clients to select the right certificate chain to
      present to each client.

   Below are example DNS records (assumed "secure" and shown without the
   associated DNSSEC information, such as record signatures) that
   illustrate both of the above models in the case of an HTTPS service
   whose clients all support DANE TLS.  These examples work even with
   clients that don't "chase" CNAMEs when constructing the TLSA base
   domain (see Section 7 below).

   ; The hosted web service is redirected via a CNAME alias.
   ; The associated TLSA RRset is also redirected via a CNAME alias.
   ;
   ; Certificate usage DANE-EE(3) makes it possible to deploy
   ; a single provider certificate for all Customer Domains.
   ;
   www1.example.com.            IN CNAME w1.example.net.
   _443._tcp.www1.example.com.  IN CNAME _443._tcp.w1.example.net.
   _443._tcp.w1.example.net.    IN TLSA 3 1 1 (
                                   8A9A70596E869BED72C69D97A8895DFA
                                   D86F300A343FECEFF19E89C27C896BC9 )

   ;
   ; A CA at the provider can also issue certificates for each Customer
   ; Domain and employ the DANE-TA(2) certificate usage to
   ; designate the provider's CA as a TA.
   ;
   www2.example.com.            IN CNAME w2.example.net.
   _443._tcp.www2.example.com.  IN CNAME _443._tcp.w2.example.net.
   _443._tcp.w2.example.net.    IN TLSA 2 0 1 (
                                   C164B2C3F36D068D42A6138E446152F5
                                   68615F28C69BD96A73E354CAC88ED00C )

   With protocols that support explicit transport redirection via DNS MX
   records, SRV records, or other similar records, the TLSA base domain
   is based on the redirected transport endpoint rather than the origin
   domain.  With SMTP, for example, when an email service is hosted by a
   Service Provider, the Customer Domain's MX hostnames will point at
   the Service Provider's SMTP hosts.  When the Customer Domain's DNS
   zone is signed, the MX hostnames can be securely used as the base










Dukhovni & Hardaker          Standards Track                   [Page 17]

RFC 7671                     DANE Operations                October 2015


   domains for TLSA records that are published and managed by the
   Service Provider.  For example (without the required DNSSEC
   information, such as record signatures):

   ; Hosted SMTP service.
   ;
   example.com.               IN MX 0 mx1.example.net.
   example.com.               IN MX 0 mx2.example.net.
   _25._tcp.mx1.example.net.  IN TLSA 3 1 1 (
                                 8A9A70596E869BED72C69D97A8895DFA
                                 D86F300A343FECEFF19E89C27C896BC9 )
   _25._tcp.mx2.example.net.  IN TLSA 3 1 1 (
                                 C164B2C3F36D068D42A6138E446152F5
                                 68615F28C69BD96A73E354CAC88ED00C )

   If redirection to the Service Provider's domain (via MX records, SRV
   records, or any similar mechanism) is not possible and aliasing of
   the TLSA record is not an option, then more complex coordination
   between the Customer Domain and Service Provider will be required.
   Either the Customer Domain periodically provides private keys and a
   corresponding certificate chain to the provider (after making
   appropriate changes in its TLSA records), or the Service Provider
   periodically generates the keys and certificates and needs to wait
   for matching TLSA records to be published by its Customer Domains
   before deploying newly generated keys and certificate chains.
   Section 7 below describes an approach that employs CNAME "chasing" to
   avoid the difficulties of coordinating key management across
   organizational boundaries.

   For further information about combining DANE and SRV, please see
   [RFC7673].

7.  TLSA Base Domain and CNAMEs

   When the application protocol does not support service location
   indirection via MX, SRV, or similar DNS records, the service may be
   redirected via a CNAME.  A CNAME is a more blunt instrument for this
   purpose because, unlike an MX or SRV record, it remaps the entire
   origin domain to the target domain for all protocols.

   The complexity of coordinating key management is largely eliminated
   when DANE TLSA records are found in the Service Provider's domain, as
   discussed in Section 6.  Therefore, DANE TLS clients connecting to a
   server whose domain name is a CNAME alias SHOULD follow the CNAME
   "hop by hop" to its ultimate target host (noting at each step whether
   or not the CNAME is DNSSEC validated).  If at each stage of CNAME
   expansion the DNSSEC validation status is "secure", the final target
   name SHOULD be the preferred base domain for TLSA lookups.



Dukhovni & Hardaker          Standards Track                   [Page 18]

RFC 7671                     DANE Operations                October 2015


   Implementations failing to find a TLSA record using a base name of
   the final target of a CNAME expansion SHOULD issue a TLSA query using
   the original destination name.  That is, the preferred TLSA base
   domain SHOULD be derived from the fully expanded name and, failing
   that, SHOULD be the initial domain name.

   When the TLSA base domain is the result of "secure" CNAME expansion,
   the resulting domain name MUST be used as the HostName in the
   client's SNI extension and MUST be the primary reference identifier
   for peer certificate matching with certificate usages other than
   DANE-EE(3).

   Protocol-specific TLSA specifications may provide additional guidance
   or restrictions when following CNAME expansions.

   Though CNAMEs are illegal on the right-hand side of most indirection
   records, such as MX and SRV records, they are supported by some
   implementations.  For example, if the MX or SRV host is a CNAME
   alias, some implementations may "chase" the CNAME.  If they do, they
   SHOULD use the target hostname as the preferred TLSA base domain as
   described above (and, if the TLSA records are found there, also use
   the CNAME-expanded domain in SNI and certificate name checks).

8.  TLSA Publisher Requirements

   This section updates [RFC6698] by specifying that the TLSA Publisher
   MUST ensure that each combination of certificate usage, selector, and
   matching type in the server's TLSA RRset includes at least one record
   that matches the server's current certificate chain.  TLSA records
   that match recently retired or yet-to-be-deployed certificate chains
   will be present during key rollover.  Such past or future records
   MUST NOT at any time be the only records published for any given
   combination of usage, selector, and matching type.  The TLSA record
   update process described below ensures that this requirement is met.

   While a server is to be considered authenticated when its certificate
   chain is matched by any of the published TLSA records, not all
   clients support all combinations of TLSA record parameters.  Some
   clients may not support some digest algorithms; others may either not
   support or exclusively support the PKIX certificate usages.  Some
   clients may prefer to negotiate [RFC7250] raw public keys, which are
   only compatible with TLSA records whose certificate usage is
   DANE-EE(3) with selector SPKI(1).  The only other TLSA record type
   that is potentially compatible with raw public keys is "DANE-EE(3)
   Cert(0) Full(0)", but support for raw public keys with that TLSA
   record type is not expected to be broadly implemented.





Dukhovni & Hardaker          Standards Track                   [Page 19]

RFC 7671                     DANE Operations                October 2015


   A consequence of the above uncertainty as to which TLSA parameters
   are supported by any given client is that servers need to ensure that
   each and every parameter combination that appears in the TLSA RRset
   is, on its own, sufficient to match the server's current certificate
   chain.  In particular, when deploying new keys or new parameter
   combinations, some care is required to not generate parameter
   combinations that only match past or future certificate chains (or
   raw public keys).  The rest of this section explains how to update
   the TLSA RRset in a manner that ensures that the above requirement
   is met.

8.1.  Key Rollover with Fixed TLSA Parameters

   The simplest case is key rollover while retaining the same set of
   published parameter combinations.  In this case, TLSA records
   matching the existing server certificate chain (or raw public keys)
   are first augmented with corresponding records matching the future
   keys, at least two Times to Live (TTLs) or longer before the new
   chain is deployed.  This allows the obsolete RRset to age out of
   client caches before the new chain is used in TLS handshakes.  Once
   sufficient time has elapsed and all clients performing DNS lookups
   are retrieving the updated TLSA records, the server administrator may
   deploy the new certificate chain, verify that it works, and then
   remove any obsolete records matching the chain that is no longer
   active:

   ; Initial TLSA RRset.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...

   ; Transitional TLSA RRset published at least two TTLs before
   ; the actual key change.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...
   _443._tcp.www.example.org. IN TLSA 3 1 1 7aa7a5359173d05b...

   ; Final TLSA RRset after the key change.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 7aa7a5359173d05b...












Dukhovni & Hardaker          Standards Track                   [Page 20]

RFC 7671                     DANE Operations                October 2015


   The next case to consider is adding or switching to a new combination
   of TLSA parameters.  In this case, publish the new parameter
   combinations for the server's existing certificate chain first, and
   only then deploy new keys if desired:

   ; Initial TLSA RRset.
   ;
   _443._tcp.www.example.org. IN TLSA 1 1 1 01d09d19c2139a46...

   ; New TLSA RRset, same key re-published as DANE-EE(3).
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...

8.2.  Switching to DANE-TA(2) from DANE-EE(3)

   This section explains how to migrate to a new certificate chain and
   TLSA record with usage DANE-TA(2) from a self-signed server
   certificate and a "DANE-EE(3) SPKI(1) SHA2-256(1)" TLSA record.  This
   example assumes that a new private key is generated in conjunction
   with transitioning to a new certificate issued by the desired TA.

   The original "3 1 1" TLSA record supports [RFC7250] raw public keys,
   and clients may choose to negotiate their use.  The use of raw public
   keys rules out the possibility of certificate chain verification.
   Therefore, the transitional TLSA record for the planned DANE-TA(2)
   certificate chain is a "3 1 1" record that works even when raw public
   keys are used.  The TLSA RRset is updated to use DANE-TA(2) only
   after the new chain is deployed and the "3 1 1" record matching the
   original key is dropped.

   This process follows the requirement that each combination of
   parameters present in the RRset is always sufficient to validate the
   server.  It avoids publishing a transitional TLSA RRset in which
   "3 1 1" matches only the current key and "2 0 1" matches only the
   future certificate chain, because these might not work reliably
   during the initial deployment of the new keys.















Dukhovni & Hardaker          Standards Track                   [Page 21]

RFC 7671                     DANE Operations                October 2015


   ; Initial TLSA RRset.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...

   ; Transitional TLSA RRset, published at least two TTLs before the
   ; actual key change.  The new keys are issued by a DANE-TA(2) CA
   ; but are initially specified via a DANE-EE(3) association.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...
   _443._tcp.www.example.org. IN TLSA 3 1 1 7aa7a5359173d05b...

   ; The final TLSA RRset after the key change.  Now that the old
   ; self-signed EE key is out of the picture, publish the issuing
   ; TA of the new chain.
   ;
   _443._tcp.www.example.org. IN TLSA 2 0 1 c57bce38455d9e3d...

8.3.  Switching to New TLSA Parameters

   When employing a new digest algorithm in the TLSA RRset, for
   compatibility with digest algorithm agility as specified in Section 9
   below, administrators SHOULD publish the new digest algorithm with
   each combination of certificate usage and selector for each
   associated key or chain used with any other digest algorithm.  When
   removing an algorithm, remove it entirely.  Each digest algorithm
   employed SHOULD match the same set of chains (or raw public keys).

   ; Initial TLSA RRset with "DANE-EE(3) SHA2-256(1)" associations
   ; for two keys.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...
   _443._tcp.www.example.org. IN TLSA 3 1 1 7aa7a5359173d05b...

   ; New TLSA RRset, also with SHA2-512(2) associations
   ; for each key.
   ;
   _443._tcp.www.example.org. IN TLSA 3 1 1 01d09d19c2139a46...
   _443._tcp.www.example.org. IN TLSA 3 1 2 d9947c35089310bc...
   _443._tcp.www.example.org. IN TLSA 3 1 1 7aa7a5359173d05b...
   _443._tcp.www.example.org. IN TLSA 3 1 2 89a7486a4b6ae714...











Dukhovni & Hardaker          Standards Track                   [Page 22]

RFC 7671                     DANE Operations                October 2015


8.4.  TLSA Publisher Requirements: Summary

   In summary, server operators updating TLSA records should make one
   change at a time.  The individual safe changes are as follows:

   o  Pre-publish new certificate associations that employ the same TLSA
      parameters (usage, selector, and matching type) as existing TLSA
      records, but match certificate chains that will be deployed in the
      near future.

   o  Wait for stale TLSA RRsets to expire from DNS caches before
      configuring servers to use the new certificate chain.

   o  Remove TLSA records matching any certificate chains that are no
      longer deployed.

   o  Publish TLSA RRsets in which all parameter combinations
      (certificate usage, selector, and matching type) present in the
      RRset match the same set of current and planned certificate
      chains.

   The above steps are intended to ensure that at all times, and for
   each combination of usage, selector, and matching type, at least one
   TLSA record corresponds to the server's current certificate chain.
   Each combination of certificate usage, selector, and matching type in
   a server's TLSA RRset SHOULD NOT at any time (including unexpired
   RRsets in client caches) match only some combination of future or
   past certificate chains.  As a result, no matter what combinations of
   usage, selector, and matching type may be supported by a given
   client, they will be sufficient to authenticate the server.

9.  Digest Algorithm Agility

   While [RFC6698] specifies multiple digest algorithms, it does not
   specify a protocol by which the client and TLSA record publisher can
   agree on the strongest shared algorithm.  Such a protocol would allow
   the client and server to avoid exposure to deprecated weaker
   algorithms that are published for compatibility with less capable
   clients but that SHOULD be avoided when possible.  Such a protocol is
   specified below.

   This section defines a protocol for avoiding deprecated digest
   algorithms when these are published in a peer's TLSA RRset alongside
   stronger digest algorithms.  Note that this protocol never avoids RRs
   with a DANE matching type of Full(0), as these do not employ a digest
   algorithm that might someday be weakened by cryptanalysis.





Dukhovni & Hardaker          Standards Track                   [Page 23]

RFC 7671                     DANE Operations                October 2015


   Client implementations SHOULD implement a default order of digest
   algorithms by strength.  This order SHOULD be configurable by the
   administrator or user of the client software.  If possible, a
   configurable mapping from numeric DANE TLSA matching types to
   underlying digest algorithms provided by the cryptographic library
   SHOULD be implemented to allow new matching types to be used with
   software that predates their introduction.  Configurable ordering of
   digest algorithms SHOULD be extensible to any new digest algorithms.

   To make digest algorithm agility possible, all published DANE TLSA
   RRsets MUST conform to the requirements of Section 8.  Clients SHOULD
   use digest algorithm agility when processing the peer's DANE TLSA
   records.  Algorithm agility is to be applied after first discarding
   any unusable or malformed records (unsupported digest algorithm, or
   incorrect digest length).  For each usage and selector, the client
   SHOULD process only any usable records with a matching type of
   Full(0) and the usable records whose digest algorithm is considered
   by the client to be the strongest among usable records with the given
   usage and selector.

   Example: a client implements digest algorithm agility and prefers
   SHA2-512(2) over SHA2-256(1), while the server publishes an RRset
   that employs both digest algorithms as well as a Full(0) record.

   _25._tcp.mail.example.com. IN TLSA 3 1 1 (
                                 3FE246A848798236DD2AB78D39F0651D
                                 6B6E7CA8E2984012EB0A2E1AC8A87B72 )
   _25._tcp.mail.example.com. IN TLSA 3 1 2 (
                                 D4F5AF015B46C5057B841C7E7BAB759C
                                 BF029526D29520C5BE6A32C67475439E
                                 54AB3A945D80C743347C9BD4DADC9D8D
                                 57FAB78EAA835362F3CA07CCC19A3214 )
   _25._tcp.mail.example.com. IN TLSA 3 1 0 (
                                 3059301306072A8648CE3D020106082A
                                 8648CE3D0301070342000471CB1F504F
                                 9E4B33971376C005445DACD33CD79A28
                                 81C3DED1981F18E7AAA76609DD0E4EF2
                                 8265C82703030AD60C5DBA6FB8A9397A
                                 C0FCF06D424C885D484887 )

   In this case, the client SHOULD accept a server public key that
   matches either the "3 1 0" record or the "3 1 2" record, but it
   SHOULD NOT accept keys that match only the weaker "3 1 1" record.








Dukhovni & Hardaker          Standards Track                   [Page 24]

RFC 7671                     DANE Operations                October 2015


10.  General DANE Guidelines

   These guidelines provide guidance for using or designing protocols
   for DANE.

10.1.  DANE DNS Record Size Guidelines

   Selecting a combination of TLSA parameters to use requires careful
   thought.  One important consideration to take into account is the
   size of the resulting TLSA record after its parameters are selected.

10.1.1.  UDP and TCP Considerations

   Deployments SHOULD avoid TLSA record sizes that cause UDP
   fragmentation.

   Although DNS over TCP would provide the ability to more easily
   transfer larger DNS records between clients and servers, it is not
   universally deployed and is still prohibited by some firewalls.
   Clients that request DNS records via UDP typically only use TCP upon
   receipt of a truncated response in the DNS response message sent over
   UDP.  Setting the Truncation (TC) bit (Section 4.1.1 of [RFC1035])
   alone will be insufficient if the response containing the TC bit is
   itself fragmented.

10.1.2.  Packet Size Considerations for TLSA Parameters

   Server operators SHOULD NOT publish TLSA records using both a TLSA
   selector of Cert(0) and a TLSA matching type of Full(0), as even a
   single certificate is generally too large to be reliably delivered
   via DNS over UDP.  Furthermore, two TLSA records containing full
   certificates will need to be published simultaneously during a
   certificate rollover, as discussed in Section 8.1.

   While TLSA records using a TLSA selector of SPKI(1) and a TLSA
   matching type of Full(0) (which publish the bare public keys, i.e.,
   without the overhead of encapsulating the keys in an X.509
   certificate) are generally more compact, these are also best avoided
   when significantly larger than their digests.  Rather, servers SHOULD
   publish digest-based TLSA matching types in their TLSA records, in
   which case the complete corresponding certificate MUST be transmitted
   to the client in-band during the TLS handshake.  The certificate (or
   raw public key) can be easily verified using the digest value.

   In summary, the use of a TLSA matching type of Full(0) is
   NOT RECOMMENDED, and a digest-based matching type, such as
   SHA2-256(1), SHOULD be used instead.




Dukhovni & Hardaker          Standards Track                   [Page 25]

RFC 7671                     DANE Operations                October 2015


10.2.  Certificate Name Check Conventions

   Certificates presented by a TLS server will generally contain a
   subjectAltName (SAN) extension or a Common Name (CN) element within
   the subject Distinguished Name (DN).  The TLS server's DNS domain
   name is normally published within these elements, ideally within the
   SAN extension.  (The use of the CN field for this purpose is
   deprecated.)

   When a server hosts multiple domains at the same transport endpoint,
   the server's ability to respond with the right certificate chain is
   predicated on correct SNI information from the client.  DANE clients
   MUST send the SNI extension with a HostName value of the base domain
   of the TLSA RRset.

   With the exception of TLSA certificate usage DANE-EE(3), where name
   checks are not applicable (see Section 5.1), DANE clients MUST verify
   that the client has reached the correct server by checking that the
   server name is listed in the server certificate's SAN or CN (when
   still supported).  The primary server name used for this comparison
   MUST be the TLSA base domain; however, additional acceptable names
   may be specified by protocol-specific DANE standards.  For example,
   with SMTP, both the destination domain name and the MX hostname are
   acceptable names to be found in the server certificate (see
   [RFC7672]).

   It is the responsibility of the service operator, in coordination
   with the TLSA Publisher, to ensure that at least one of the TLSA
   records published for the service will match the server's certificate
   chain (either the default chain or the certificate that was selected
   based on the SNI information provided by the client).

   Given the DNSSEC-validated DNS records below:

   example.com.               IN MX 0 mail.example.com.
   mail.example.com.          IN A 192.0.2.1
   _25._tcp.mail.example.com. IN TLSA 2 0 1 (
                                 E8B54E0B4BAA815B06D3462D65FBC7C0
                                 CF556ECCF9F5303EBFBB77D022F834C0 )

   The TLSA base domain is "mail.example.com" and is required to be the
   HostName in the client's SNI extension.  The server certificate chain
   is required to be signed by a TA with the above certificate SHA2-256
   digest.  Finally, one of the DNS names in the server certificate is
   required to be either "mail.example.com" or "example.com" (this
   additional name is a concession to compatibility with prior practice;
   see [RFC7672] for details).




Dukhovni & Hardaker          Standards Track                   [Page 26]

RFC 7671                     DANE Operations                October 2015


   [RFC6125] specifies the semantics of wildcards in server certificates
   for various application protocols.  DANE does not change how
   wildcards are treated by any given application.

10.3.  Design Considerations for Protocols Using DANE

   When a TLS client goes to the trouble of authenticating a certificate
   chain presented by a TLS server, it will typically not continue to
   use that server in the event of authentication failure, or else
   authentication serves no purpose.  Some clients may, at times,
   operate in an "audit" mode, where authentication failure is reported
   to the user or in logs as a potential problem, but the connection
   proceeds despite the failure.  Nevertheless, servers publishing TLSA
   records MUST be configured to allow correctly configured clients to
   successfully authenticate their TLS certificate chains.

   A service with DNSSEC-validated TLSA records implicitly promises TLS
   support.  When all the TLSA records for a service are found
   "unusable" due to unsupported parameter combinations or malformed
   certificate association data, DANE clients cannot authenticate the
   service certificate chain.  When authenticated TLS is mandatory, the
   client MUST NOT connect to the associated server.

   If, on the other hand, the use of TLS and DANE is "opportunistic"
   [RFC7435], then when all TLSA records are unusable, the client SHOULD
   connect to the server via an unauthenticated TLS connection, and if
   TLS encryption cannot be established, the client MUST NOT connect to
   the server.

   Standards for opportunistic DANE TLS specific to a particular
   application protocol may modify the above requirements.  The key
   consideration is whether or not mandating the use of
   (unauthenticated) TLS even with unusable TLSA records is asking for
   more security than one can realistically expect.  If expecting TLS
   support when unusable TLSA records are published is realistic for the
   application in question, then the application MUST avoid cleartext.
   If not realistic, then mandating TLS would cause clients (even in the
   absence of active attacks) to run into problems with various peers
   that do not interoperate "securely enough".  That would create strong
   incentives to just disable Opportunistic Security and stick with
   cleartext.










Dukhovni & Hardaker          Standards Track                   [Page 27]

RFC 7671                     DANE Operations                October 2015


11.  Note on DNSSEC Security

   Clearly, the security of the DANE TLSA PKI rests on the security of
   the underlying DNSSEC infrastructure.  While this document is not a
   guide to DNSSEC security, a few comments may be helpful to TLSA
   implementers.

   With the existing public CA Web PKI, name constraints are rarely
   used, and a public root CA can issue certificates for any domain of
   its choice.  With DNSSEC, under the Registry/Registrar/Registrant
   model, the situation is different: only the registrar of record can
   update a domain's DS record [RFC4034] in the registry parent zone (in
   some cases, however, the registry is the sole registrar).  With many
   Generic Top-Level Domains (gTLDs) for which multiple registrars
   compete to provide domains in a single registry, it is important to
   make sure that rogue registrars cannot easily initiate an
   unauthorized domain transfer and thus take over DNSSEC for the
   domain.  DNS operators are advised to set a registrar lock on their
   domains to offer some protection against this possibility.

   When the registrar is also the DNS operator for the domain, one needs
   to consider whether or not the registrar will allow orderly migration
   of the domain to another registrar or DNS operator in a way that will
   maintain DNSSEC integrity.  TLSA Publishers are advised to seek out a
   DNS hosting registrar that makes it possible to transfer domains to
   another hosting provider without disabling DNSSEC.

   DNSSEC-signed RRsets cannot be securely revoked before they expire.
   Operators need to plan accordingly and not generate signatures of
   excessively long duration.  For domains publishing high-value keys, a
   signature lifetime (length of the "signature validity period" as
   described in Section 8.1 of [RFC4033]) of a few days is reasonable,
   and the zone can be re-signed daily.  For domains with less critical
   data, a reasonable signature lifetime is a couple of weeks to a
   month, and the zone can be re-signed weekly.

   Short signature lifetimes require tighter synchronization of primary
   and secondary nameservers, to make sure that secondary servers never
   serve records with expired signatures.  They also limit the maximum
   time for which a primary server that signs the zone can be down.
   Therefore, short signature lifetimes are more appropriate for sites
   with dedicated operations staff, who can restore service quickly in
   case of a problem.

   Monitoring is important.  If a DNS zone is not re-signed in a timely
   manner, a major outage is likely, as the entire domain and all its
   sub-domains become "bogus".




Dukhovni & Hardaker          Standards Track                   [Page 28]

RFC 7671                     DANE Operations                October 2015


12.  Summary of Updates to RFC 6698

   o  Section 3 updates [RFC6698] to specify a requirement for clients
      to support at least TLS 1.0 and to support SNI.

   o  Section 4 explains that application support for all four
      certificate usages is NOT RECOMMENDED.  The recommended design is
      to support just DANE-EE(3) and DANE-TA(2).

   o  Section 5.1 updates [RFC6698] to specify that peer identity
      matching and validity period enforcement are based solely on the
      TLSA RRset properties.  It also specifies DANE authentication of
      raw public keys [RFC7250] via TLSA records with certificate usage
      DANE-EE(3) and selector SPKI(1).

   o  Section 5.2 updates [RFC6698] to require that servers publishing
      digest TLSA records with a usage of DANE-TA(2) MUST include the
      TA certificate in their TLS server certificate message.  This
      extends to the case of "2 1 0" TLSA records that publish a full
      public key.

   o  Section 5.4 observes that with usage PKIX-TA(0), clients may need
      to process extended trust chains beyond the first trusted issuer
      when that issuer is not self-signed.

   o  Section 7 recommends that DANE application protocols specify that,
      when possible, securely CNAME-expanded names be used to derive the
      TLSA base domain.

   o  Section 8 specifies a strategy for managing TLSA records that
      interoperates with DANE clients regardless of what subset of the
      possible TLSA record types (combinations of TLSA parameters) is
      supported by the client.

   o  Section 9 specifies a digest algorithm agility protocol.

   o  Section 10.1 recommends against the use of Full(0) TLSA records,
      as digest records are generally much more compact.

13.  Operational Considerations

   The DNS TTL of TLSA records needs to be chosen with care.  When an
   unplanned change in the server's certificate chain and TLSA RRset is
   required, such as when keys are compromised or lost, clients that
   cache stale TLSA records will fail to validate the certificate chain
   of the updated server.  Publish TLSA RRsets with TTLs that are short
   enough to limit unplanned service disruption to an acceptable
   duration.



Dukhovni & Hardaker          Standards Track                   [Page 29]

RFC 7671                     DANE Operations                October 2015


   The signature lifetime (length of the signature validity period) for
   TLSA records SHOULD NOT be too long.  Signed DNSSEC records can be
   replayed by an MITM attacker, provided the signatures have not yet
   expired.  Shorter signature validity periods allow for faster
   invalidation of compromised keys.  Zone refresh and expiration times
   for secondary nameservers often imply a lower bound on the signature
   validity period (Section 11).  See Section 4.4.1 of [RFC6781].

14.  Security Considerations

   Application protocols that cannot use the existing public CA Web PKI
   may choose to not implement certain TLSA record types defined in
   [RFC6698].  If such records are published despite not being supported
   by the application protocol, they are treated as "unusable".  When
   TLS is opportunistic, the client MAY proceed to use the server with
   mandatory unauthenticated TLS.  This is stronger than opportunistic
   TLS without DANE, since in that case the client may also proceed with
   a cleartext connection.  When TLS is not opportunistic, the client
   MUST NOT connect to the server.

   Thus, when TLSA records are used with opportunistic protocols where
   PKIX-TA(0) and PKIX-EE(1) do not apply, the recommended protocol
   design is for servers to not publish such TLSA records, and for
   opportunistic TLS clients to use them to only enforce the use of
   (albeit unauthenticated) TLS but otherwise treat them as unusable.
   Of course, when PKIX-TA(0) and PKIX-EE(1) are supported by the
   application protocol, clients MUST implement these certificate usages
   as described in [RFC6698] and this document.

15.  References

15.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <http://www.rfc-editor.org/info/rfc2119>.

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, DOI 10.17487/RFC4033, March 2005,
              <http://www.rfc-editor.org/info/rfc4033>.

   [RFC4034]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Resource Records for the DNS Security Extensions",
              RFC 4034, DOI 10.17487/RFC4034, March 2005,
              <http://www.rfc-editor.org/info/rfc4034>.




Dukhovni & Hardaker          Standards Track                   [Page 30]

RFC 7671                     DANE Operations                October 2015


   [RFC4035]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Protocol Modifications for the DNS Security
              Extensions", RFC 4035, DOI 10.17487/RFC4035, March 2005,
              <http://www.rfc-editor.org/info/rfc4035>.

   [RFC5246]  Dierks, T. and E. Rescorla, "The Transport Layer Security
              (TLS) Protocol Version 1.2", RFC 5246,
              DOI 10.17487/RFC5246, August 2008,
              <http://www.rfc-editor.org/info/rfc5246>.

   [RFC5280]  Cooper, D., Santesson, S., Farrell, S., Boeyen, S.,
              Housley, R., and W. Polk, "Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 5280, DOI 10.17487/RFC5280, May 2008,
              <http://www.rfc-editor.org/info/rfc5280>.

   [RFC6066]  Eastlake 3rd, D., "Transport Layer Security (TLS)
              Extensions: Extension Definitions", RFC 6066,
              DOI 10.17487/RFC6066, January 2011,
              <http://www.rfc-editor.org/info/rfc6066>.

   [RFC6125]  Saint-Andre, P. and J. Hodges, "Representation and
              Verification of Domain-Based Application Service Identity
              within Internet Public Key Infrastructure Using X.509
              (PKIX) Certificates in the Context of Transport Layer
              Security (TLS)", RFC 6125, DOI 10.17487/RFC6125,
              March 2011, <http://www.rfc-editor.org/info/rfc6125>.

   [RFC6347]  Rescorla, E. and N. Modadugu, "Datagram Transport Layer
              Security Version 1.2", RFC 6347, DOI 10.17487/RFC6347,
              January 2012, <http://www.rfc-editor.org/info/rfc6347>.

   [RFC6698]  Hoffman, P. and J. Schlyter, "The DNS-Based Authentication
              of Named Entities (DANE) Transport Layer Security (TLS)
              Protocol: TLSA", RFC 6698, DOI 10.17487/RFC6698,
              August 2012, <http://www.rfc-editor.org/info/rfc6698>.

   [RFC7218]  Gudmundsson, O., "Adding Acronyms to Simplify
              Conversations about DNS-Based Authentication of Named
              Entities (DANE)", RFC 7218, DOI 10.17487/RFC7218,
              April 2014, <http://www.rfc-editor.org/info/rfc7218>.

   [RFC7250]  Wouters, P., Ed., Tschofenig, H., Ed., Gilmore, J.,
              Weiler, S., and T. Kivinen, "Using Raw Public Keys in
              Transport Layer Security (TLS) and Datagram Transport
              Layer Security (DTLS)", RFC 7250, DOI 10.17487/RFC7250,
              June 2014, <http://www.rfc-editor.org/info/rfc7250>.




Dukhovni & Hardaker          Standards Track                   [Page 31]

RFC 7671                     DANE Operations                October 2015


15.2.  Informative References

   [RFC1035]  Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, DOI 10.17487/RFC1035,
              November 1987, <http://www.rfc-editor.org/info/rfc1035>.

   [RFC6781]  Kolkman, O., Mekking, W., and R. Gieben, "DNSSEC
              Operational Practices, Version 2", RFC 6781,
              DOI 10.17487/RFC6781, December 2012,
              <http://www.rfc-editor.org/info/rfc6781>.

   [RFC6962]  Laurie, B., Langley, A., and E. Kasper, "Certificate
              Transparency", RFC 6962, DOI 10.17487/RFC6962, June 2013,
              <http://www.rfc-editor.org/info/rfc6962>.

   [RFC7435]  Dukhovni, V., "Opportunistic Security: Some Protection
              Most of the Time", RFC 7435, DOI 10.17487/RFC7435,
              December 2014, <http://www.rfc-editor.org/info/rfc7435>.

   [RFC7672]  Dukhovni, V. and W. Hardaker, "SMTP Security via
              Opportunistic DNS-Based Authentication of Named Entities
              (DANE) Transport Layer Security (TLS)", RFC 7672,
              DOI 10.17487/RFC7672, October 2015,
              <http://www.rfc-editor.org/info/rfc7672>.

   [RFC7673]  Finch, T., Miller, M., and P. Saint-Andre, "Using
              DNS-Based Authentication of Named Entities (DANE) TLSA
              Records with SRV Records", RFC 7673, DOI 10.17487/RFC7673,
              October 2015, <http://www.rfc-editor.org/info/rfc7673>.






















Dukhovni & Hardaker          Standards Track                   [Page 32]

RFC 7671                     DANE Operations                October 2015


Acknowledgements

   The authors would like to thank Phil Pennock for his comments and
   advice on this document.

   Acknowledgements from Viktor: Thanks to Tony Finch, who finally
   prodded me into participating in DANE working group discussions.
   Thanks to Paul Hoffman, who motivated me to produce this document and
   provided feedback on early draft versions of it.  Thanks also to
   Samuel Dukhovni for editorial assistance.

Authors' Addresses

   Viktor Dukhovni
   Two Sigma

   Email: ietf-dane@dukhovni.org


   Wes Hardaker
   Parsons
   P.O. Box 382
   Davis, CA  95617
   United States

   Email: ietf@hardakers.net

























Dukhovni & Hardaker          Standards Track                   [Page 33]


```

---

# RFC 8461 — MTA-STS — SMTP MTA Strict Transport Security

```






Internet Engineering Task Force (IETF)                       D. Margolis
Request for Comments: 8461                                     M. Risher
Category: Standards Track                                   Google, Inc.
ISSN: 2070-1721                                          B. Ramakrishnan
                                                              Oath, Inc.
                                                              A. Brotman
                                                           Comcast, Inc.
                                                                J. Jones
                                                         Microsoft, Inc.
                                                          September 2018


              SMTP MTA Strict Transport Security (MTA-STS)

Abstract

   SMTP MTA Strict Transport Security (MTA-STS) is a mechanism enabling
   mail service providers (SPs) to declare their ability to receive
   Transport Layer Security (TLS) secure SMTP connections and to specify
   whether sending SMTP servers should refuse to deliver to MX hosts
   that do not offer TLS with a trusted server certificate.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 7841.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   https://www.rfc-editor.org/info/rfc8461.
















Margolis, et al.             Standards Track                    [Page 1]

RFC 8461                         MTA-STS                  September 2018


Copyright Notice

   Copyright (c) 2018 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.





































Margolis, et al.             Standards Track                    [Page 2]

RFC 8461                         MTA-STS                  September 2018


Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   4
     1.1.  Terminology . . . . . . . . . . . . . . . . . . . . . . .   4
   2.  Related Technologies  . . . . . . . . . . . . . . . . . . . .   5
   3.  Policy Discovery  . . . . . . . . . . . . . . . . . . . . . .   5
     3.1.  MTA-STS TXT Records . . . . . . . . . . . . . . . . . . .   6
     3.2.  MTA-STS Policies  . . . . . . . . . . . . . . . . . . . .   7
     3.3.  HTTPS Policy Fetching . . . . . . . . . . . . . . . . . .  10
     3.4.  Policy Selection for Smart Hosts and Subdomains . . . . .  11
   4.  Policy Validation . . . . . . . . . . . . . . . . . . . . . .  11
     4.1.  MX Host Validation  . . . . . . . . . . . . . . . . . . .  12
     4.2.  Recipient MTA Certificate Validation  . . . . . . . . . .  12
   5.  Policy Application  . . . . . . . . . . . . . . . . . . . . .  12
     5.1.  Policy Application Control Flow . . . . . . . . . . . . .  13
   6.  Reporting Failures  . . . . . . . . . . . . . . . . . . . . .  13
   7.  Interoperability Considerations . . . . . . . . . . . . . . .  14
     7.1.  SNI Support . . . . . . . . . . . . . . . . . . . . . . .  14
     7.2.  Minimum TLS Version Support . . . . . . . . . . . . . . .  14
   8.  Operational Considerations  . . . . . . . . . . . . . . . . .  15
     8.1.  Policy Updates  . . . . . . . . . . . . . . . . . . . . .  15
     8.2.  Policy Delegation . . . . . . . . . . . . . . . . . . . .  15
     8.3.  Removing MTA-STS  . . . . . . . . . . . . . . . . . . . .  16
     8.4.  Preserving MX Candidate Traversal . . . . . . . . . . . .  17
   9.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .  17
     9.1.  Well-Known URIs Registry  . . . . . . . . . . . . . . . .  17
     9.2.  MTA-STS TXT Record Fields . . . . . . . . . . . . . . . .  17
     9.3.  MTA-STS Policy Fields . . . . . . . . . . . . . . . . . .  18
   10. Security Considerations . . . . . . . . . . . . . . . . . . .  18
     10.1.  Obtaining a Signed Certificate . . . . . . . . . . . . .  18
     10.2.  Preventing Policy Discovery  . . . . . . . . . . . . . .  19
     10.3.  Denial of Service  . . . . . . . . . . . . . . . . . . .  19
     10.4.  Weak Policy Constraints  . . . . . . . . . . . . . . . .  20
     10.5.  Compromise of the Web PKI System . . . . . . . . . . . .  20
   11. References  . . . . . . . . . . . . . . . . . . . . . . . . .  21
     11.1.  Normative References . . . . . . . . . . . . . . . . . .  21
     11.2.  Informative References . . . . . . . . . . . . . . . . .  23
   Appendix A.  MTA-STS Example Record and Policy  . . . . . . . . .  25
   Appendix B.  Message Delivery Pseudocode  . . . . . . . . . . . .  25
   Contributors  . . . . . . . . . . . . . . . . . . . . . . . . . .  28
   Authors' Addresses  . . . . . . . . . . . . . . . . . . . . . . .  29










Margolis, et al.             Standards Track                    [Page 3]

RFC 8461                         MTA-STS                  September 2018


1.  Introduction

   The STARTTLS extension to SMTP [RFC3207] allows SMTP clients and
   hosts to negotiate the use of a TLS channel for encrypted mail
   transmission.

   While this opportunistic encryption protocol by itself provides a
   high barrier against passive man-in-the-middle traffic interception,
   any attacker who can delete parts of the SMTP session (such as the
   "250 STARTTLS" response) or who can redirect the entire SMTP session
   (perhaps by overwriting the resolved MX record of the delivery
   domain) can perform downgrade or interception attacks.

   This document defines a mechanism for recipient domains to publish
   policies, via a combination of DNS and HTTPS, specifying:

   o  whether MTAs sending mail to this domain can expect PKIX-
      authenticated TLS support

   o  what a conforming client should do with messages when TLS cannot
      be successfully negotiated

1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   We also define the following terms for further use in this document:

   o  MTA-STS Policy: A commitment by the Policy Domain to support TLS
      authenticated with PKIX [RFC5280] for the specified MX hosts.

   o  Policy Domain: The domain for which an MTA-STS Policy is defined.
      This is the next-hop domain; when sending mail to
      "alice@example.com", this would ordinarily be "example.com", but
      this may be overridden by explicit routing rules (as described in
      Section 3.4, "Policy Selection for Smart Hosts and Subdomains").

   o  Policy Host: The HTTPS host that serves the MTA-STS Policy for a
      Policy Domain.  Rules for constructing the hostname are described
      in Section 3.2, "MTA-STS Policies".

   o  Sender or Sending MTA: The SMTP MTA sending an email message.





Margolis, et al.             Standards Track                    [Page 4]

RFC 8461                         MTA-STS                  September 2018


   o  ABNF: Augmented Backus-Naur Form, a syntax for formally specifying
      syntax, defined in [RFC5234] and [RFC7405].

2.  Related Technologies

   The DNS-Based Authentication of a Named Entities (DANE) TLSA record
   [RFC7672] is similar, in that DANE is also designed to upgrade
   unauthenticated encryption or plaintext transmission into
   authenticated, downgrade-resistant encrypted transmission.  DANE
   requires DNSSEC [RFC4033] for authentication; the mechanism described
   here instead relies on certification authorities (CAs) and does not
   require DNSSEC, at a cost of risking malicious downgrades.  For a
   thorough discussion of this trade-off, see Section 10, "Security
   Considerations".

   In addition, MTA-STS provides an optional testing-only mode, enabling
   soft deployments to detect policy failures; partial deployments can
   be achieved in DANE by deploying TLSA records only for some of a
   domain's MXes, but such a mechanism is not possible for the per-
   domain policies used by MTA-STS.

   The primary motivation of MTA-STS is to provide a mechanism for
   domains to ensure transport security even when deploying DNSSEC is
   undesirable or impractical.  However, MTA-STS is designed not to
   interfere with DANE deployments when the two overlap; in particular,
   senders who implement MTA-STS validation MUST NOT allow MTA-STS
   Policy validation to override a failing DANE validation.

3.  Policy Discovery

   MTA-STS policies are distributed via HTTPS from a "well-known"
   [RFC5785] path served within the Policy Domain, and their presence
   and current version are indicated by a TXT record at the Policy
   Domain.  These TXT records additionally contain a policy "id" field,
   allowing Sending MTAs to check that a cached policy is still current
   without performing an HTTPS request.

   To discover if a recipient domain implements MTA-STS, a sender need
   only resolve a single TXT record.  To see if an updated policy is
   available for a domain for which the sender has a previously cached
   policy, the sender need only check the TXT record's version "id"
   against the cached value.









Margolis, et al.             Standards Track                    [Page 5]

RFC 8461                         MTA-STS                  September 2018


3.1.  MTA-STS TXT Records

   The MTA-STS TXT record is a TXT record with the name "_mta-sts" at
   the Policy Domain.  For the domain "example.com", this record would
   be "_mta-sts.example.com".  MTA-STS TXT records MUST be US-ASCII,
   semicolon-separated key/value pairs containing the following fields:

   o  "v" (plaintext, required): Currently, only "STSv1" is supported.

   o  "id" (plaintext, required): A short string used to track policy
      updates.  This string MUST uniquely identify a given instance of a
      policy, such that senders can determine when the policy has been
      updated by comparing to the "id" of a previously seen policy.
      There is no implied ordering of "id" fields between revisions.

   An example TXT record is as below:

   _mta-sts.example.com.  IN TXT "v=STSv1; id=20160831085700Z;"

   The formal definition of the "_mta-sts" TXT record, defined using
   ABNF [RFC7405], is as follows:

   sts-text-record = sts-version 1*(sts-field-delim sts-field)
                     [sts-field-delim]

   sts-field       = sts-id /                 ; Note that sts-id record
                     sts-extension            ; is required.

   sts-field-delim = *WSP ";" *WSP

   sts-version     = %s"v=STSv1"

   sts-id          = %s"id=" 1*32(ALPHA / DIGIT)     ; id=...

   sts-extension   = sts-ext-name "=" sts-ext-value  ; name=value

   sts-ext-name    = (ALPHA / DIGIT)
                     *31(ALPHA / DIGIT / "_" / "-" / ".")

   sts-ext-value   = 1*(%x21-3A / %x3C / %x3E-7E)
                     ; chars excluding "=", ";", SP, and CTLs

   The TXT record MUST begin with the sts-version field; the order of
   other fields is not significant.  If multiple TXT records for
   "_mta-sts" are returned by the resolver, records that do not begin
   with "v=STSv1;" are discarded.  If the number of resulting records is
   not one, or if the resulting record is syntactically invalid, senders
   MUST assume the recipient domain does not have an available MTA-STS



Margolis, et al.             Standards Track                    [Page 6]

RFC 8461                         MTA-STS                  September 2018


   Policy and skip the remaining steps of policy discovery.  (Note that
   the absence of a usable TXT record is not by itself sufficient to
   remove a sender's previously cached policy for the Policy Domain, as
   discussed in Section 5.1, "Policy Application Control Flow".)  If the
   resulting TXT record contains multiple strings, then the record MUST
   be treated as if those strings are concatenated without adding
   spaces.

   The "_mta-sts" record MAY return a CNAME that points (directly or via
   other CNAMEs) to a TXT record, in which case senders MUST follow the
   CNAME pointers.  This can be used for policy delegation, as described
   in Section 8.2.

3.2.  MTA-STS Policies

   The policy itself is a set of key/value pairs (similar to header
   fields in [RFC5322]) served via the HTTPS GET method from the fixed
   "well-known" [RFC5785] path of ".well-known/mta-sts.txt" served by
   the Policy Host.  The Policy Host DNS name is constructed by
   prepending "mta-sts" to the Policy Domain.

   Thus, for a Policy Domain of "example.com", the full URL is
   "https://mta-sts.example.com/.well-known/mta-sts.txt".

   When fetching a policy, senders SHOULD validate that the media type
   is "text/plain" to guard against cases where web servers allow
   untrusted users to host non-text content (typically, HTML or images)
   at a user-defined path.  All parameters other than charset=utf-8 or
   charset=us-ascii are ignored.  Additional "Content-Type" parameters
   are also ignored.

   This resource contains the following CRLF-separated key/value pairs:

   o  "version": Currently, only "STSv1" is supported.

   o  "mode": One of "enforce", "testing", or "none", indicating the
      expected behavior of a Sending MTA in the case of a policy
      validation failure.  See Section 5, "Policy Application", for more
      details about the three modes.

   o  "max_age": Max lifetime of the policy (plaintext non-negative
      integer seconds, maximum value of 31557600).  Well-behaved clients
      SHOULD cache a policy for up to this value from the last policy
      fetch time.  To mitigate the risks of attacks at policy refresh
      time, it is expected that this value typically be in the range of
      weeks or greater.





Margolis, et al.             Standards Track                    [Page 7]

RFC 8461                         MTA-STS                  September 2018


   o  "mx": Allowed MX patterns.  One or more patterns matching allowed
      MX hosts for the Policy Domain.  As an example,

                        mx: mail.example.com <CRLF>
                        mx: *.example.net

   indicates that mail for this domain might be handled by MX
   "mail.example.com" or any MX at "example.net".  Valid patterns can be
   either fully specified names ("example.com") or suffixes prefixed by
   a wildcard ("*.example.net").  If a policy specifies more than one
   MX, each MX MUST have its own "mx:" key, and each MX key/value pair
   MUST be on its own line in the policy file.  In the case of
   Internationalized Domain Names [RFC5891], the "mx" value MUST specify
   the Punycode-encoded A-label [RFC3492] to match against, and not the
   Unicode-encoded U-label.  The full semantics of certificate
   validation (including the use of wildcard patterns) are described in
   Section 4.1, "MX Host Validation".

   An example policy is as below:

                         version: STSv1
                         mode: enforce
                         mx: mail.example.com
                         mx: *.example.net
                         mx: backupmx.example.com
                         max_age: 604800

   The formal definition of the policy resource, defined using ABNF
   [RFC7405], is as follows:

sts-policy-record        = sts-policy-field *WSP
                           *(sts-policy-term sts-policy-field *WSP)
                           [sts-policy-term]

sts-policy-field         = sts-policy-version /      ; required once
                           sts-policy-mode    /      ; required once
                           sts-policy-max-age /      ; required once
                           sts-policy-mx /
                           ; required at least once, except when
                           ; mode is "none"
                           sts-policy-extension      ; other fields

sts-policy-field-delim   = ":" *WSP

sts-policy-version     = sts-policy-version-field sts-policy-field-delim
                         sts-policy-version-value

sts-policy-version-field = %s"version"



Margolis, et al.             Standards Track                    [Page 8]

RFC 8461                         MTA-STS                  September 2018


sts-policy-version-value = %s"STSv1"

sts-policy-mode          = sts-policy-mode-field sts-policy-field-delim
                           sts-policy-mode-value

sts-policy-mode-field    = %s"mode"

sts-policy-mode-value    =  %s"testing" / %s"enforce" / %s"none"

sts-policy-mx            = sts-policy-mx-field sts-policy-field-delim
                           sts-policy-mx-value

sts-policy-mx-field      = %s"mx"

sts-policy-mx-value      = ["*."] Domain

sts-policy-max-age     = sts-policy-max-age-field sts-policy-field-delim
                         sts-policy-max-age-value

sts-policy-max-age-field = %s"max_age"

sts-policy-max-age-value = 1*10(DIGIT)

sts-policy-extension     = sts-policy-ext-name    ; additional
                           sts-policy-field-delim ; extension
                           sts-policy-ext-value   ; fields

sts-policy-ext-name      = (sts-policy-alphanum)
                           *31(sta-policy-alphanum / "_" / "-" / ".")

sts-policy-term          = LF / CRLF

sts-policy-ext-value     = sts-policy-vchar
                           [*(%x20 / sts-policy-vchar)
                           sts-policy-vchar]
                           ; chars, including UTF-8 [RFC3629],
                           ; excluding CTLs and no
                           ; leading/trailing spaces

sts-policy-alphanum     = ALPHA / DIGIT

sts-policy-vchar        = %x21-7E / UTF8-2 / UTF8-3 / UTF8-4

UTF8-2          =   <Defined in Section 4 of [RFC3629]>

UTF8-3          =   <Defined in Section 4 of [RFC3629]>

UTF8-4          =   <Defined in Section 4 of [RFC3629]>



Margolis, et al.             Standards Track                    [Page 9]

RFC 8461                         MTA-STS                  September 2018


Domain          =   <Defined in Section 4.1.2 of [RFC5321]>

   Parsers MUST accept TXT records and policy files that are
   syntactically valid (i.e., valid key/value pairs separated by
   semicolons for TXT records), possibly containing additional key/value
   pairs not specified in this document, in which case unknown fields
   SHALL be ignored.  If any non-repeated field -- i.e., all fields
   excepting "mx" -- is duplicated, all entries except for the first
   SHALL be ignored.

3.3.  HTTPS Policy Fetching

   Policy bodies are, as described above, retrieved by Sending MTAs via
   HTTPS [RFC2818].  During the TLS handshake initiated to fetch a new
   or updated policy from the Policy Host, the Policy Host HTTPS server
   MUST present an X.509 certificate that is valid for the "mta-sts"
   DNS-ID [RFC6125] (e.g., "mta-sts.example.com") as described below,
   chain to a root CA that is trusted by the Sending MTA, and be non-
   expired.  It is expected that Sending MTAs use a set of trusted CAs
   similar to those in widely deployed web browsers and operating
   systems.  See [RFC5280] for more details about certificate
   verification.

   The certificate is valid for the Policy Host (i.e., "mta-sts"
   prepended to the Policy Domain) with respect to the rules described
   in [RFC6125], with the following application-specific considerations:

   o  Matching is performed only against the DNS-ID identifiers.

   o  DNS domain names in server certificates MAY contain the wildcard
      character '*' as the complete left-most label within the
      identifier.

   The certificate MAY be checked for revocation via the Online
   Certificate Status Protocol (OCSP) [RFC6960], certificate revocation
   lists (CRLs), or some other mechanism.

   Policies fetched via HTTPS are only valid if the HTTP response code
   is 200 (OK).  HTTP 3xx redirects MUST NOT be followed, and HTTP
   caching (as specified in [RFC7234]) MUST NOT be used.

   Senders may wish to rate-limit the frequency of attempts to fetch the
   HTTPS endpoint even if a valid TXT record for the recipient domain
   exists.  In the case where the HTTPS GET fails, implementers SHOULD
   limit further attempts to a period of five minutes or longer per
   version ID, to avoid overwhelming resource-constrained recipients
   with cascading failures.




Margolis, et al.             Standards Track                   [Page 10]

RFC 8461                         MTA-STS                  September 2018


   Senders MAY impose a timeout on the HTTPS GET and/or a limit on the
   maximum size of the response body to avoid long delays or resource
   exhaustion during attempted policy updates.  A suggested timeout is
   one minute, and a suggested maximum policy size is 64 kilobytes;
   Policy Hosts SHOULD respond to requests with a complete policy body
   within that timeout and size limit.

   If a valid TXT record is found but no policy can be fetched via HTTPS
   (for any reason), and there is no valid (non-expired) previously
   cached policy, senders MUST continue with delivery as though the
   domain has not implemented MTA-STS.

   Conversely, if no "live" policy can be discovered via DNS or fetched
   via HTTPS, but a valid (non-expired) policy exists in the sender's
   cache, the sender MUST apply that cached policy.

   Finally, to mitigate the risk of persistent interference with policy
   refresh, as discussed in-depth in Section 10, MTAs SHOULD proactively
   refresh cached policies before they expire; a suggested refresh
   frequency is once per day.  To enable administrators to discover
   problems with policy refresh, MTAs SHOULD alert administrators
   (through the use of logs or similar) when such attempts fail, unless
   the cached policy mode is "none".

3.4.  Policy Selection for Smart Hosts and Subdomains

   When sending mail via a "smart host" -- an administratively
   configured intermediate SMTP relay, which is different from the
   message recipient's server as determined from DNS -- compliant
   senders MUST treat the smart host domain as the Policy Domain for the
   purposes of policy discovery and application.  This specification
   does not provide a means of associating policies with email addresses
   that employ Address Literals [RFC5321].

   When sending mail to a mailbox at a subdomain, compliant senders MUST
   NOT attempt to fetch a policy from the parent zone.  Thus, for mail
   sent to "user@mail.example.com", the policy can be fetched only from
   "mail.example.com", not "example.com".

4.  Policy Validation

   When sending to an MX at a domain for which the sender has a valid
   and non-expired MTA-STS Policy, a Sending MTA honoring MTA-STS MUST
   check whether:

   1.  At least one of the policy's "mx" patterns matches the selected
       MX host, as described in Section 4.1, "MX Host Validation".




Margolis, et al.             Standards Track                   [Page 11]

RFC 8461                         MTA-STS                  September 2018


   2.  The recipient mail server supports STARTTLS and offers a PKIX-
       based TLS certificate, during TLS handshake, which is valid for
       that host, as described in Section 4.2, "Recipient MTA
       Certificate Validation".

   When these conditions are not met, a policy is said to fail to
   validate.  This section does not dictate the behavior of Sending MTAs
   when the above conditions are not met; see Section 5, "Policy
   Application", for a description of Sending MTA behavior when policy
   validation fails.

4.1.  MX Host Validation

   A receiving candidate MX host is valid according to an applied MTA-
   STS Policy if the MX record name matches one or more of the "mx"
   fields in the applied policy.  Matching is identical to the rules
   given in [RFC6125], with the restriction that the wildcard character
   '*' may only be used to match the entire left-most label in the
   presented identifier.  Thus, the mx pattern "*.example.com" matches
   "mail.example.com" but not "example.com" or "foo.bar.example.com".

4.2.  Recipient MTA Certificate Validation

   The certificate presented by the receiving MTA MUST not be expired
   and MUST chain to a root CA that is trusted by the Sending MTA.  The
   certificate MUST have a subject alternative name (SAN) [RFC5280] with
   a DNS-ID [RFC6125] matching the hostname, per the rules given in
   [RFC6125].  The MX's certificate MAY also be checked for revocation
   via OCSP [RFC6960], CRLs [RFC6818], or some other mechanism.

5.  Policy Application

   When sending to an MX at a domain for which the sender has a valid,
   non-expired MTA-STS Policy, a Sending MTA honoring MTA-STS applies
   the result of a policy validation failure in one of two ways,
   depending on the value of the policy "mode" field:

   1.  "enforce": In this mode, Sending MTAs MUST NOT deliver the
       message to hosts that fail MX matching or certificate validation
       or that do not support STARTTLS.

   2.  "testing": In this mode, Sending MTAs that also implement the
       TLSRPT (TLS Reporting) specification [RFC8460] send a report
       indicating policy application failures (as long as TLSRPT is also
       implemented by the recipient domain); in any case, messages may
       be delivered as though there were no MTA-STS validation failure.





Margolis, et al.             Standards Track                   [Page 12]

RFC 8461                         MTA-STS                  September 2018


   3.  "none": In this mode, Sending MTAs should treat the Policy Domain
       as though it does not have any active policy; see Section 8.3,
       "Removing MTA-STS", for use of this mode value.

   When a message fails to deliver due to an "enforce" policy, a
   compliant MTA MUST NOT permanently fail to deliver messages before
   checking, via DNS, for the presence of an updated policy at the
   Policy Domain.  (In all cases, MTAs SHOULD treat such failures as
   transient errors and retry delivery later.)  This allows implementing
   domains to update long-lived policies on the fly.

5.1.  Policy Application Control Flow

   An example control flow for a compliant sender consists of the
   following steps:

   1.  Check for a cached policy whose time-since-fetch has not exceeded
       its "max_age".  If none exists, attempt to fetch a new policy
       (perhaps asynchronously, so as not to block message delivery).
       Optionally, Sending MTAs may unconditionally check for a new
       policy at this step.

   2.  For each candidate MX, in order of MX priority, attempt to
       deliver the message.  If a policy is present with an "enforce"
       mode, when attempting to deliver to each candidate MX, ensure
       STARTTLS support and host identity validity as described in
       Section 4, "Policy Validation".  If a candidate fails validation,
       continue to the next candidate (if there is one).

   3.  A message delivery attempt MUST NOT be permanently failed until
       the sender has first checked for the presence of a new policy (as
       indicated by the "id" field in the "_mta-sts" TXT record).  If a
       new policy is not found, existing rules for the case of temporary
       message delivery failures apply (as discussed in [RFC5321],
       Section 4.5.4.1).

6.  Reporting Failures

   MTA-STS is intended to be used along with TLSRPT [RFC8460] in order
   to ensure that implementing domains can detect cases of both benign
   and malicious failures and to ensure that failures that indicate an
   active attack are discoverable.  As such, senders that also implement
   TLSRPT SHOULD treat the following events as reportable failures:

   o  HTTPS policy fetch failures when a valid TXT record is present.

   o  Policy fetch failures of any kind when a valid policy exists in
      the policy cache, except if that policy's mode is "none".



Margolis, et al.             Standards Track                   [Page 13]

RFC 8461                         MTA-STS                  September 2018


   o  Delivery attempts in which a contacted MX does not support
      STARTTLS or does not present a certificate that validates
      according to the applied policy, except if that policy's mode is
      "none".

7.  Interoperability Considerations

7.1.  SNI Support

   To ensure that the server sends the right certificate chain, the SMTP
   client MUST have support for the TLS Server Name Indication (SNI)
   extension [RFC6066].  When connecting to an HTTP server to retrieve
   the MTA-STS Policy, the SNI extension MUST contain the name of the
   Policy Host (e.g., "mta-sts.example.com").  When connecting to an
   SMTP server, the SNI extension MUST contain the MX hostname.

   HTTP servers used to deliver MTA-STS policies MAY rely on SNI to
   determine which certificate chain to present to the client.  HTTP
   servers MUST respond with a certificate chain that matches the policy
   hostname or abort the TLS handshake if unable to do so.  Clients that
   do not send SNI information may not see the expected certificate
   chain.

   SMTP servers MAY rely on SNI to determine which certificate chain to
   present to the client.  However, servers that have one identity and a
   single matching certificate do not require SNI support.  Servers MUST
   NOT enforce the use of SNI by clients, as the client may be using
   unauthenticated opportunistic TLS and may not expect any particular
   certificate from the server.  If the client sends no SNI extension or
   sends an SNI extension for an unsupported server name, the server
   MUST simply send a fallback certificate chain of its choice.  The
   reason for not enforcing strict matching of the requested SNI
   hostname is that MTA-STS TLS clients may be typically willing to
   accept multiple server names but can only send one name in the SNI
   extension.  The server's fallback certificate may match a different
   name that is acceptable to the client, e.g., the original next-hop
   domain.

7.2.  Minimum TLS Version Support

   MTAs supporting MTA-STS MUST have support for TLS 1.2 [RFC5246] or
   TLS 1.3 [RFC8446] or higher.  The general TLS usage guidance in
   [RFC7525] SHOULD be followed.








Margolis, et al.             Standards Track                   [Page 14]

RFC 8461                         MTA-STS                  September 2018


8.  Operational Considerations

8.1.  Policy Updates

   Updating the policy requires that the owner make changes in two
   places: the "_mta-sts" TXT record in the Policy Domain's DNS zone and
   at the corresponding HTTPS endpoint.  As a result, recipients should
   expect that a policy will continue to be used by senders until both
   the HTTPS and TXT endpoints are updated and the TXT record's TTL has
   passed.

   In other words, a sender who is unable to successfully deliver a
   message while applying a cache of the recipient's now-outdated policy
   may be unable to discover that a new policy exists until the DNS TTL
   has passed.  Recipients SHOULD therefore ensure that old policies
   continue to work for message delivery during this period of time, or
   risk message delays.

   Recipients SHOULD also update the HTTPS policy body before updating
   the TXT record; this ordering avoids the risk that senders, seeing a
   new TXT record, mistakenly cache the old policy from HTTPS.

8.2.  Policy Delegation

   Domain owners commonly delegate SMTP hosting to a different
   organization, such as an ISP or a web host.  In such a case, they may
   wish to also delegate the MTA-STS Policy to the same organization,
   which can be accomplished with two changes.

   First, the Policy Domain must point the "_mta-sts" record, via CNAME,
   to the "_mta-sts" record maintained by the provider.  This allows the
   provider to control update signaling.

   Second, the Policy Domain must point the "well-known" policy location
   to the provider.  This can be done either by setting the "mta-sts"
   record to an IP address or CNAME specified by the provider and by
   giving the provider a TLS certificate that is valid for that host or
   by setting up a "reverse proxy" (also known as a "gateway") server
   for the Policy Domain's Policy Host, configured to serve proxied
   responses from the Policy Host of the provider.

   For example, given a user domain "user.example" hosted by a mail
   provider "provider.example", the following configuration would allow
   policy delegation:

   DNS:

        _mta-sts.user.example.  IN CNAME _mta-sts.provider.example.



Margolis, et al.             Standards Track                   [Page 15]

RFC 8461                         MTA-STS                  September 2018


   Policy:

         > GET /.well-known/mta-sts.txt Host: mta-sts.user.example
         < HTTP/1.1 200 OK  # Response proxies content from
                            # https://mta-sts.provider.example

   Note that in all such cases, the policy endpoint
   ("https://mta-sts.user.example/.well-known/mta-sts.txt" in this
   example) must still present a certificate valid for the Policy Host
   ("mta-sts.user.example"), and not for that host at the provider's
   domain ("mta-sts.provider.example").

   Note that while Sending MTAs MUST NOT use HTTP caching when fetching
   policies via HTTPS, such caching may nonetheless be useful to a
   reverse proxy configured as described in this section.  An HTTPS
   policy endpoint expecting to be proxied for multiple hosted domains
   -- as with a large mail hosting provider or similar -- may wish to
   indicate an HTTP Cache-Control "max-age" response directive (as
   specified in [RFC7234]) of 60 seconds as a reasonable value to save
   reverse proxies an unnecessarily high-rate of proxied policy
   fetching.

8.3.  Removing MTA-STS

   In order to facilitate clean opt-out of MTA-STS by implementing
   Policy Domains, and to distinguish clearly between failures that
   indicate attacks and those that indicate such opt-outs, MTA-STS
   implements the "none" mode, which allows validated policies to
   indicate authoritatively that the Policy Domain wishes to no longer
   implement MTA-STS and may, in the future, remove the MTA-STS TXT and
   policy endpoints entirely.

   A suggested workflow to implement such an opt out is as follows:

   1.  Publish a new policy with "mode" equal to "none" and a small
       "max_age" (e.g., one day).

   2.  Publish a new TXT record to trigger fetching of the new policy.

   3.  When all previously served policies have expired -- normally this
       is the time the previously published policy was last served plus
       that policy's "max_age", but note that policies older than the
       previously published policy may have been served with a greater
       "max_age" than the previously published policy, allowing
       overlapping policy caches -- safely remove the TXT record and
       HTTPS endpoint.





Margolis, et al.             Standards Track                   [Page 16]

RFC 8461                         MTA-STS                  September 2018


8.4.  Preserving MX Candidate Traversal

   Implementers of send-time MTA-STS validation in mail transfer agents
   should take note of the risks of modifying the logic of traversing MX
   candidate lists.  Because an MTA-STS Policy can be used to prefilter
   invalid MX candidates from the MX candidate list, it is tempting to
   implement a "two-pass" model, where MX candidates are first filtered
   for possible validity according to the MTA-STS Policy, and then the
   remaining candidates are attempted in order as without an MTA-STS
   Policy.  This may lead to incorrect implementations, such as message
   loops; instead, it is recommended that implementers traverse the MX
   candidate list as usual, and treat invalid candidates as though they
   were unreachable (i.e., as though there were some transient error
   when trying to deliver to that candidate).

   One consequence of validating MX hosts in order of ordinary candidate
   traversal is that in the event a higher-priority MX is MTA-STS valid
   and a lower-priority MX is not, senders may never encounter the
   lower-priority MX, leading to a risk that policy misconfigurations
   that apply only to "backup" MXes may only be discovered in the case
   of primary MX failure.

9.  IANA Considerations

9.1.  Well-Known URIs Registry

   A new "well-known" URI as described in Section 3 has been registered
   in the "Well-Known URIs" registry as described below:

   URI Suffix: mta-sts.txt

   Change Controller: IETF

9.2.  MTA-STS TXT Record Fields

   IANA has created a new registry titled "MTA-STS TXT Record Fields".
   The initial entries in the registry are:

       +------------+--------------------+-------------------------+
       | Field Name | Description        | Reference               |
       +------------+--------------------+-------------------------+
       | v          | Record version     | Section 3.1 of RFC 8461 |
       | id         | Policy instance ID | Section 3.1 of RFC 8461 |
       +------------+--------------------+-------------------------+

   New fields are added to this registry using IANA's "Expert Review"
   policy [RFC8126].




Margolis, et al.             Standards Track                   [Page 17]

RFC 8461                         MTA-STS                  September 2018


9.3.  MTA-STS Policy Fields

   IANA has created a new registry titled "MTA-STS Policy Fields".  The
   initial entries in the registry are:

      +------------+----------------------+-------------------------+
      | Field Name | Description          | Reference               |
      +------------+----------------------+-------------------------+
      | version    | Policy version       | Section 3.2 of RFC 8461 |
      | mode       | Enforcement behavior | Section 3.2 of RFC 8461 |
      | max_age    | Policy lifetime      | Section 3.2 of RFC 8461 |
      | mx         | MX identities        | Section 3.2 of RFC 8461 |
      +------------+----------------------+-------------------------+

   New fields are added to this registry using IANA's "Expert Review"
   policy.

10.  Security Considerations

   SMTP MTA-STS attempts to protect against an active attacker trying to
   intercept or tamper with mail between hosts that support STARTTLS.
   There are two classes of attacks considered:

   o  Foiling TLS negotiation (for example, by deleting the "250
      STARTTLS" response from a server or altering TLS session
      negotiation).  This would result in the SMTP session occurring
      over plaintext, despite both parties supporting TLS.

   o  Impersonating the destination mail server, whereby the sender
      might deliver the message to an impostor, who could then monitor
      and/or modify messages despite opportunistic TLS.  This
      impersonation could be accomplished by spoofing the DNS MX record
      for the recipient domain or by redirecting client connections
      intended for the legitimate recipient server (for example, by
      altering BGP routing tables).

   MTA-STS can thwart such attacks only if the sender is able to
   previously obtain and cache a policy for the recipient domain, and
   only if the attacker is unable to obtain a valid certificate that
   complies with that policy.  Below, we consider specific attacks on
   this model.

10.1.  Obtaining a Signed Certificate

   SMTP MTA-STS relies on certificate validation via PKIX-based TLS
   identity checking [RFC6125].  Attackers who are able to obtain a
   valid certificate for the targeted recipient mail service (e.g., by
   compromising a CA) are thus able to circumvent STS authentication.



Margolis, et al.             Standards Track                   [Page 18]

RFC 8461                         MTA-STS                  September 2018


10.2.  Preventing Policy Discovery

   Since MTA-STS uses DNS TXT records for policy discovery, an attacker
   who is able to block DNS responses can suppress the discovery of an
   MTA-STS Policy, making the Policy Domain appear not to have an MTA-
   STS Policy.  The sender policy cache is designed to resist this
   attack by decreasing the frequency of policy discovery and thus
   reducing the window of vulnerability; it is nonetheless a risk that
   attackers who can predict or induce policy discovery -- for example,
   by inducing a sending domain to send mail to a never-before-contacted
   recipient while carrying out a man-in-the-middle attack -- may be
   able to foil policy discovery and effectively downgrade the security
   of the message delivery.

   Since this attack depends upon intercepting initial policy discovery,
   implementers SHOULD prefer policy "max_age" values to be as long as
   is practical.

   Because this attack is also possible upon refresh of a cached policy,
   implementers SHOULD NOT wait until a cached policy has expired before
   checking for an update; if senders attempt to refresh the cache
   regularly (for example, by fetching the current live policy in a
   background task that runs daily or weekly, regardless of the state of
   the "_mta-sts" TXT record, and updating their cache's "max age"
   accordingly), an attacker would have to foil policy discovery
   consistently over the lifetime of a cached policy to prevent a
   successful refresh.

   Additionally, MTAs SHOULD alert administrators to repeated policy
   refresh failures long before cached policies expire (through warning
   logs or similar applicable mechanisms), allowing administrators to
   detect such a persistent attack on policy refresh.  (However, they
   should not implement such alerts if the cached policy has a "none"
   mode, to allow clean MTA-STS removal, as described in Section 8.3.)

   Resistance to downgrade attacks of this nature -- due to the ability
   to authoritatively determine "lack of a record" even for non-
   participating recipients -- is a feature of DANE, due to its use of
   DNSSEC for policy discovery.

10.3.  Denial of Service

   We additionally consider the Denial-of-Service risk posed by an
   attacker who can modify the DNS records for a recipient domain.
   Absent MTA-STS, such an attacker can cause a Sending MTA to cache
   invalid MX records, but only for however long the sending resolver
   caches those records.  With MTA-STS, the attacker can additionally
   advertise a new, long "max_age" MTA-STS Policy with "mx" constraints



Margolis, et al.             Standards Track                   [Page 19]

RFC 8461                         MTA-STS                  September 2018


   that validate the malicious MX record, causing senders to cache the
   policy and refuse to deliver messages once the victim has resecured
   the MX records.

   This attack is mitigated in part by the ability of a victim domain to
   (at any time) publish a new policy updating the cached, malicious
   policy, though this does require the victim domain to both obtain a
   valid CA-signed certificate and to understand and properly configure
   MTA-STS.

   Similarly, we consider the possibility of domains that deliberately
   allow untrusted users to serve untrusted content on user-specified
   subdomains.  In some cases (e.g., the service "tumblr.com"), this
   takes the form of providing HTTPS hosting of user-registered
   subdomains; in other cases (e.g. dynamic DNS providers), this takes
   the form of allowing untrusted users to register custom DNS records
   at the provider's domain.

   In these cases, there is a risk that untrusted users would be able to
   serve custom content at the "mta-sts" host, including serving an
   illegitimate MTA-STS Policy.  We believe this attack is rendered more
   difficult by the need for the attacker to also serve the "_mta-sts"
   TXT record on the same domain -- something not, to our knowledge,
   widely provided to untrusted users.  This attack is additionally
   mitigated by the aforementioned ability for a victim domain to update
   an invalid policy at any future date.

10.4.  Weak Policy Constraints

   Even if an attacker cannot modify a served policy, the potential
   exists for configurations that allow attackers on the same domain to
   receive mail for that domain.  For example, an easy configuration
   option when authoring an MTA-STS Policy for "example.com" is to set
   the "mx" equal to "*.example.com"; in this case, recipient domains
   must consider the risk that any user possessing a valid hostname and
   CA-signed certificate (for example, "dhcp-123.example.com") will,
   from the perspective of MTA-STS Policy validation, be a valid MX host
   for that domain.

10.5.  Compromise of the Web PKI System

   A number of risks apply to the PKI system that is used for
   certificate authentication, both of the "mta-sts" HTTPS host's
   certificate and the SMTP servers' certificates.  These risks are
   broadly applicable within the Web PKI ecosystem and are not specific
   to MTA-STS; nonetheless, they deserve some consideration in this
   context.




Margolis, et al.             Standards Track                   [Page 20]

RFC 8461                         MTA-STS                  September 2018


   Broadly speaking, attackers may compromise the system by obtaining
   certificates under fraudulent circumstances (i.e., by impersonating
   the legitimate owner of the victim domain), by compromising a CA or
   Delegate Authority's private keys, by obtaining a legitimate
   certificate issued to the victim domain, and similar.

   One approach commonly employed by web browsers to help mitigate
   against some of these attacks is to allow for revocation of
   compromised or fraudulent certificates via OCSP [RFC6960] or CRLs
   [RFC6818].  Such mechanisms themselves represent trade-offs and are
   not universally implemented; we nonetheless recommend implementers of
   MTA-STS to implement revocation mechanisms that are most applicable
   to their implementations.

11.  References

11.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC2818]  Rescorla, E., "HTTP Over TLS", RFC 2818,
              DOI 10.17487/RFC2818, May 2000,
              <https://www.rfc-editor.org/info/rfc2818>.

   [RFC3207]  Hoffman, P., "SMTP Service Extension for Secure SMTP over
              Transport Layer Security", RFC 3207, DOI 10.17487/RFC3207,
              February 2002, <https://www.rfc-editor.org/info/rfc3207>.

   [RFC3492]  Costello, A., "Punycode: A Bootstring encoding of Unicode
              for Internationalized Domain Names in Applications
              (IDNA)", RFC 3492, DOI 10.17487/RFC3492, March 2003,
              <https://www.rfc-editor.org/info/rfc3492>.

   [RFC3629]  Yergeau, F., "UTF-8, a transformation format of ISO
              10646", STD 63, RFC 3629, DOI 10.17487/RFC3629, November
              2003, <https://www.rfc-editor.org/info/rfc3629>.

   [RFC5234]  Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234,
              DOI 10.17487/RFC5234, January 2008,
              <https://www.rfc-editor.org/info/rfc5234>.







Margolis, et al.             Standards Track                   [Page 21]

RFC 8461                         MTA-STS                  September 2018


   [RFC5246]  Dierks, T. and E. Rescorla, "The Transport Layer Security
              (TLS) Protocol Version 1.2", RFC 5246,
              DOI 10.17487/RFC5246, August 2008,
              <https://www.rfc-editor.org/info/rfc5246>.

   [RFC5280]  Cooper, D., Santesson, S., Farrell, S., Boeyen, S.,
              Housley, R., and W. Polk, "Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 5280, DOI 10.17487/RFC5280, May 2008,
              <https://www.rfc-editor.org/info/rfc5280>.

   [RFC5321]  Klensin, J., "Simple Mail Transfer Protocol", RFC 5321,
              DOI 10.17487/RFC5321, October 2008,
              <https://www.rfc-editor.org/info/rfc5321>.

   [RFC5785]  Nottingham, M. and E. Hammer-Lahav, "Defining Well-Known
              Uniform Resource Identifiers (URIs)", RFC 5785,
              DOI 10.17487/RFC5785, April 2010,
              <https://www.rfc-editor.org/info/rfc5785>.

   [RFC6066]  Eastlake 3rd, D., "Transport Layer Security (TLS)
              Extensions: Extension Definitions", RFC 6066,
              DOI 10.17487/RFC6066, January 2011,
              <https://www.rfc-editor.org/info/rfc6066>.

   [RFC6125]  Saint-Andre, P. and J. Hodges, "Representation and
              Verification of Domain-Based Application Service Identity
              within Internet Public Key Infrastructure Using X.509
              (PKIX) Certificates in the Context of Transport Layer
              Security (TLS)", RFC 6125, DOI 10.17487/RFC6125, March
              2011, <https://www.rfc-editor.org/info/rfc6125>.

   [RFC7405]  Kyzivat, P., "Case-Sensitive String Support in ABNF",
              RFC 7405, DOI 10.17487/RFC7405, December 2014,
              <https://www.rfc-editor.org/info/rfc7405>.

   [RFC7525]  Sheffer, Y., Holz, R., and P. Saint-Andre,
              "Recommendations for Secure Use of Transport Layer
              Security (TLS) and Datagram Transport Layer Security
              (DTLS)", BCP 195, RFC 7525, DOI 10.17487/RFC7525, May
              2015, <https://www.rfc-editor.org/info/rfc7525>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.






Margolis, et al.             Standards Track                   [Page 22]

RFC 8461                         MTA-STS                  September 2018


   [RFC8446]  Rescorla, E., "The Transport Layer Security (TLS) Protocol
              Version 1.3", RFC 8446, DOI 10.17487/RFC8446, August 2018,
              <https://www.rfc-editor.org/info/rfc8446>.

   [RFC8460]  Margolis, D., Brotman, A., Ramakrishnan, B., Jones, J.,
              and M. Risher, "SMTP TLS Reporting", RFC 8460,
              DOI 10.17487/RFC8460, September 2018,
              <https://www.rfc-editor.org/info/rfc8460>.

11.2.  Informative References

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, DOI 10.17487/RFC4033, March 2005,
              <https://www.rfc-editor.org/info/rfc4033>.

   [RFC5322]  Resnick, P., Ed., "Internet Message Format", RFC 5322,
              DOI 10.17487/RFC5322, October 2008,
              <https://www.rfc-editor.org/info/rfc5322>.

   [RFC5891]  Klensin, J., "Internationalized Domain Names in
              Applications (IDNA): Protocol", RFC 5891,
              DOI 10.17487/RFC5891, August 2010,
              <https://www.rfc-editor.org/info/rfc5891>.

   [RFC6818]  Yee, P., "Updates to the Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 6818, DOI 10.17487/RFC6818, January
              2013, <https://www.rfc-editor.org/info/rfc6818>.

   [RFC6960]  Santesson, S., Myers, M., Ankney, R., Malpani, A.,
              Galperin, S., and C. Adams, "X.509 Internet Public Key
              Infrastructure Online Certificate Status Protocol - OCSP",
              RFC 6960, DOI 10.17487/RFC6960, June 2013,
              <https://www.rfc-editor.org/info/rfc6960>.

   [RFC7234]  Fielding, R., Ed., Nottingham, M., Ed., and J. Reschke,
              Ed., "Hypertext Transfer Protocol (HTTP/1.1): Caching",
              RFC 7234, DOI 10.17487/RFC7234, June 2014,
              <https://www.rfc-editor.org/info/rfc7234>.

   [RFC7672]  Dukhovni, V. and W. Hardaker, "SMTP Security via
              Opportunistic DNS-Based Authentication of Named Entities
              (DANE) Transport Layer Security (TLS)", RFC 7672,
              DOI 10.17487/RFC7672, October 2015,
              <https://www.rfc-editor.org/info/rfc7672>.





Margolis, et al.             Standards Track                   [Page 23]

RFC 8461                         MTA-STS                  September 2018


   [RFC8126]  Cotton, M., Leiba, B., and T. Narten, "Guidelines for
              Writing an IANA Considerations Section in RFCs", BCP 26,
              RFC 8126, DOI 10.17487/RFC8126, June 2017,
              <https://www.rfc-editor.org/info/rfc8126>.















































Margolis, et al.             Standards Track                   [Page 24]

RFC 8461                         MTA-STS                  September 2018


Appendix A.  MTA-STS Example Record and Policy

   The owner of "example.com" wishes to begin using MTA-STS with a
   policy that will solicit reports from senders without affecting how
   the messages are processed, in order to verify the identity of MXes
   that handle mail for "example.com", confirm that TLS is correctly
   used, and ensure that certificates presented by the recipient MX
   validate.

   MTA-STS Policy indicator TXT RR:

       _mta-sts.example.com.  IN TXT "v=STSv1; id=20160831085700Z;"

   MTA-STS Policy file served as the response body at
   "https://mta-sts.example.com/.well-known/mta-sts.txt":

                         version: STSv1
                         mode: testing
                         mx: mx1.example.com
                         mx: mx2.example.com
                         mx: mx.backup-example.com
                         max_age: 1296000

Appendix B.  Message Delivery Pseudocode

   Below is pseudocode demonstrating the logic of a compliant Sending
   MTA.

   While this pseudocode implementation suggests synchronous policy
   retrieval in the delivery path, that may be undesirable in a working
   implementation, and we expect some implementers to instead prefer a
   background fetch that does not block delivery when no cached policy
   is present.


   func isEnforce(policy) {
     // Return true if the policy mode is "enforce".
   }

   func isNonExpired(policy) {
     // Return true if the policy is not expired.
   }

   func tryStartTls(connection) {
     // Attempt to open an SMTP STARTTLS connection with the MX.
   }

   func certMatches(connection, host) {



Margolis, et al.             Standards Track                   [Page 25]

RFC 8461                         MTA-STS                  September 2018


     // Assume a handy function to return if the server
     // certificate presented in "connection" is valid for "host".
   }

   func policyMatches(candidate, policy) {
     for mx in policy.mx {
       // Literal match.
       if mx == candidate {
         return true
       }
       // Wildcard matches only the leftmost label.
       // Wildcards must always be followed by a '.'.
       if mx[0] == '*' {
         parts = SplitN(candidate, '.', 2)  // Split on the first '.'.
         if len(parts) > 1 && parts[1] == mx[2:] {
           return true
         }
       }
     }
     return false
   }

   func tryDeliverMail(connection, message) {
     // Attempt to deliver "message" via "connection".
   }

   func tryGetNewPolicy(domain) {
     // Check for an MTA-STS TXT record for "domain" in DNS, and return
     // the indicated policy.
   }

   func cachePolicy(domain, policy) {
     // Store "policy" as the cached policy for "domain".
   }

   func tryGetCachedPolicy(domain) {
     // Return a cached policy for "domain".
   }

   func reportError(error) {
     // Report an error via TLSRPT.
   }

   func tryMxAccordingTo(message, mx, policy) {
     connection := connect(mx)
     if !connection {
       return false  // Can't connect to the MX, so it's not an MTA-STS
                     // error.



Margolis, et al.             Standards Track                   [Page 26]

RFC 8461                         MTA-STS                  September 2018


     }
     secure := true
     if !policyMatches(mx, policy) {
       secure = false
       reportError(E_HOST_MISMATCH)
     } else if !tryStartTls(connection) {
       secure = false
       reportError(E_NO_VALID_TLS)
     } else if !certMatches(connection, policy) {
       secure = false
       reportError(E_CERT_MISMATCH)
     }
     if secure || !isEnforce(policy) {
       return tryDeliverMail(connection, message)
     }
     return false
   }

   func tryWithPolicy(message, domain, policy) {
     mxes := getMxForDomain(domain)
     for mx in mxes {
       if tryMxAccordingTo(message, mx, policy) {
         return true
       }
     }
     return false
   }

   func handleMessage(message) {
     domain := ... // domain part after '@' from recipient
     policy := tryGetNewPolicy(domain)
     if policy {
       cachePolicy(domain, policy)
     } else {
       policy = tryGetCachedPolicy(domain)
     }
     if policy {
       return tryWithPolicy(message, domain, policy)
     }
     // Try to deliver the message normally (i.e., without MTA-STS).
   }










Margolis, et al.             Standards Track                   [Page 27]

RFC 8461                         MTA-STS                  September 2018


Contributors

   Wei Chuang
   Google, Inc.
   weihaw@google.com

   Viktor Dukhovni
   ietf-dane@dukhovni.de

   Markus Laber
   1&1 Mail & Media Development & Technology GmbH
   markus.laber@1und1.de

   Nicolas Lidzborski
   Google, Inc.
   nlidz@google.com

   Brandon Long
   Google, Inc.
   blong@google.com

   Franck Martin
   LinkedIn, Inc.
   fmartin@linkedin.com

   Klaus Umbach
   1&1 Mail & Media Development & Technology GmbH
   klaus.umbach@1und1.de























Margolis, et al.             Standards Track                   [Page 28]

RFC 8461                         MTA-STS                  September 2018


Authors' Addresses

   Daniel Margolis
   Google, Inc.

   Email: dmargolis@google.com


   Mark Risher
   Google, Inc.

   Email: risher@google.com


   Binu Ramakrishnan
   Oath, Inc.

   Email: prbinu@yahoo.com


   Alexander Brotman
   Comcast, Inc.

   Email: alex_brotman@comcast.com


   Janet Jones
   Microsoft, Inc.

   Email: janet.jones@microsoft.com





















Margolis, et al.             Standards Track                   [Page 29]


```

---

# RFC 8460 — TLS-RPT — SMTP TLS Reporting

```






Internet Engineering Task Force (IETF)                       D. Margolis
Request for Comments: 8460                                  Google, Inc.
Category: Standards Track                                     A. Brotman
ISSN: 2070-1721                                            Comcast, Inc.
                                                         B. Ramakrishnan
                                                              Oath, Inc.
                                                                J. Jones
                                                         Microsoft, Inc.
                                                               M. Risher
                                                            Google, Inc.
                                                          September 2018


                           SMTP TLS Reporting

Abstract

   A number of protocols exist for establishing encrypted channels
   between SMTP Mail Transfer Agents (MTAs), including STARTTLS, DNS-
   Based Authentication of Named Entities (DANE) TLSA, and MTA Strict
   Transport Security (MTA-STS).  These protocols can fail due to
   misconfiguration or active attack, leading to undelivered messages or
   delivery over unencrypted or unauthenticated channels.  This document
   describes a reporting mechanism and format by which sending systems
   can share statistics and specific information about potential
   failures with recipient domains.  Recipient domains can then use this
   information to both detect potential attacks and diagnose
   unintentional misconfigurations.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 7841.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   https://www.rfc-editor.org/info/rfc8460.









Margolis, et al.             Standards Track                    [Page 1]

RFC 8460                   SMTP TLS Reporting             September 2018


Copyright Notice

   Copyright (c) 2018 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.





































Margolis, et al.             Standards Track                    [Page 2]

RFC 8460                   SMTP TLS Reporting             September 2018


Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   4
     1.1.  Terminology . . . . . . . . . . . . . . . . . . . . . . .   4
   2.  Related Technologies  . . . . . . . . . . . . . . . . . . . .   5
   3.  Reporting Policy  . . . . . . . . . . . . . . . . . . . . . .   6
     3.1.  Example Reporting Policy  . . . . . . . . . . . . . . . .   8
       3.1.1.  Report Using MAILTO . . . . . . . . . . . . . . . . .   8
       3.1.2.  Report Using HTTPS  . . . . . . . . . . . . . . . . .   8
   4.  Reporting Schema  . . . . . . . . . . . . . . . . . . . . . .   8
     4.1.  Report Time Frame . . . . . . . . . . . . . . . . . . . .   9
     4.2.  Delivery Summary  . . . . . . . . . . . . . . . . . . . .  10
       4.2.1.  Success Count . . . . . . . . . . . . . . . . . . . .  10
       4.2.2.  Failure Count . . . . . . . . . . . . . . . . . . . .  10
     4.3.  Result Types  . . . . . . . . . . . . . . . . . . . . . .  10
       4.3.1.  Negotiation Failures  . . . . . . . . . . . . . . . .  10
       4.3.2.  Policy Failures . . . . . . . . . . . . . . . . . . .  11
       4.3.3.  General Failures  . . . . . . . . . . . . . . . . . .  11
       4.3.4.  Transient Failures  . . . . . . . . . . . . . . . . .  12
     4.4.  JSON Report Schema  . . . . . . . . . . . . . . . . . . .  12
     4.5.  Policy Samples  . . . . . . . . . . . . . . . . . . . . .  15
   5.  Report Delivery . . . . . . . . . . . . . . . . . . . . . . .  15
     5.1.  Report Filename . . . . . . . . . . . . . . . . . . . . .  16
     5.2.  Compression . . . . . . . . . . . . . . . . . . . . . . .  17
     5.3.  Email Transport . . . . . . . . . . . . . . . . . . . . .  17
       5.3.1.  Example Report  . . . . . . . . . . . . . . . . . . .  19
     5.4.  HTTPS Transport . . . . . . . . . . . . . . . . . . . . .  19
     5.5.  Delivery Retry  . . . . . . . . . . . . . . . . . . . . .  20
     5.6.  Metadata Variances  . . . . . . . . . . . . . . . . . . .  20
   6.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .  20
     6.1.  Message Headers . . . . . . . . . . . . . . . . . . . . .  20
     6.2.  Report Type . . . . . . . . . . . . . . . . . . . . . . .  21
     6.3.  +gzip Media Type Suffix . . . . . . . . . . . . . . . . .  22
     6.4.  application/tlsrpt+json Media Type  . . . . . . . . . . .  23
     6.5.  application/tlsrpt+gzip Media Type  . . . . . . . . . . .  24
     6.6.  STARTTLS Validation Result Types  . . . . . . . . . . . .  25
   7.  Security Considerations . . . . . . . . . . . . . . . . . . .  26
   8.  Privacy Considerations  . . . . . . . . . . . . . . . . . . .  27
   9.  References  . . . . . . . . . . . . . . . . . . . . . . . . .  28
     9.1.  Normative References  . . . . . . . . . . . . . . . . . .  28
     9.2.  Informative References  . . . . . . . . . . . . . . . . .  30
   Appendix A.  Example Reporting Policy . . . . . . . . . . . . . .  32
     A.1.  Report Using MAILTO . . . . . . . . . . . . . . . . . . .  32
     A.2.  Report Using HTTPS  . . . . . . . . . . . . . . . . . . .  32
   Appendix B.  Example JSON Report  . . . . . . . . . . . . . . . .  32
   Contributors  . . . . . . . . . . . . . . . . . . . . . . . . . .  34
   Authors' Addresses  . . . . . . . . . . . . . . . . . . . . . . .  34




Margolis, et al.             Standards Track                    [Page 3]

RFC 8460                   SMTP TLS Reporting             September 2018


1.  Introduction

   The STARTTLS extension to SMTP [RFC3207] allows SMTP clients and
   hosts to establish secure SMTP sessions over TLS.  The protocol
   design uses an approach that has come to be known as "Opportunistic
   Security" (OS) [RFC7435].  This method maintains interoperability
   with clients that do not support STARTTLS, but it means that any
   attacker could potentially eavesdrop on a session.  An attacker could
   perform a downgrade or interception attack by deleting parts of the
   SMTP session (such as the "250 STARTTLS" response) or redirect the
   entire SMTP session (perhaps by overwriting the resolved MX record of
   the delivery domain).

   Because such "downgrade attacks" are not necessarily apparent to the
   receiving MTA, this document defines a mechanism for sending domains
   to report on failures at multiple stages of the MTA-to-MTA
   conversation.

   Recipient domains may also use the mechanisms defined by MTA-STS
   [RFC8461] or DANE [RFC6698] to publish additional encryption and
   authentication requirements; this document defines a mechanism for
   sending domains that are compatible with MTA-STS or DANE to share
   success and failure statistics with recipient domains.

   Specifically, this document defines a reporting schema that covers
   failures in routing, DNS resolution, and STARTTLS negotiation; policy
   validation errors for both DANE [RFC6698] and MTA-STS [RFC8461]; and
   a standard TXT record that recipient domains can use to indicate
   where reports in this format should be sent.  The report can also
   serve as a heartbeat to indicate that systems are successfully
   negotiating TLS during sessions as expected.

   This document is intended as a companion to the specification for
   SMTP MTA-STS [RFC8461] and adds reporting abilities for those
   implementing DANE [RFC7672].

1.1.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.








Margolis, et al.             Standards Track                    [Page 4]

RFC 8460                   SMTP TLS Reporting             September 2018


   We also define the following terms for further use in this document:

   o  MTA-STS Policy: A mechanism by which administrators can specify
      the expected TLS availability, presented identity, and desired
      actions for a given email recipient domain.  MTA-STS is defined in
      [RFC8461].

   o  DANE Policy: A mechanism by which administrators can use DNSSEC to
      commit an MTA to support STARTTLS and to publish criteria to be
      used to validate its presented certificates.  DANE for SMTP is
      defined in [RFC7672], with the base specification defined in
      [RFC6698] (and updated by [RFC7671]).

   o  TLSRPT (TLS Reporting) Policy: A policy specifying the endpoint to
      which Sending MTAs should deliver reports.

   o  Policy Domain: The domain against which a TLSRPT, an MTA-STS, or a
      DANE policy is defined.  For TLSRPT and MTA-STS, this is typically
      the same as the envelope recipient domain [RFC5321], but when mail
      is routed to a "smarthost" gateway by local policy, the
      "smarthost" domain name is used instead.  For DANE, the Policy
      Domain is the "TLSA base domain" of the receiving SMTP server as
      described in Section 2.2.3 of RFC 7672 and Section 3 of RFC 6698.

   o  Sending MTA: The MTA initiating the relay of an email message.

   o  Aggregate Report URI (rua): A comma-separated list of locations
      where the report is to be submitted.

   o  ABNF: Augmented Backus-Naur Form, a syntax for formally specifying
      syntax, defined in [RFC5234] and [RFC7405].

2.  Related Technologies

   o  This document is intended as a companion to the specification for
      SMTP MTA-STS [RFC8461].

   o  SMTP TLSRPT defines a mechanism for sending domains that are
      compatible with MTA-STS or DANE to share success and failure
      statistics with recipient domains.  DANE is defined in [RFC6698],
      and MTA-STS is defined in [RFC8461].










Margolis, et al.             Standards Track                    [Page 5]

RFC 8460                   SMTP TLS Reporting             September 2018


3.  Reporting Policy

   A domain publishes a record to its DNS indicating that it wishes to
   receive reports.  These SMTP TLSRPT policies are distributed via DNS
   from the Policy Domain's zone as TXT records (similar to Domain-based
   Message Authentication, Reporting, and Conformance (DMARC) policies)
   under the name "_smtp._tls".  For example, for the Policy Domain
   "example.com", the recipient's TLSRPT policy can be retrieved from
   "_smtp._tls.example.com".

   Policies consist of the following directives:

   o  "v": This document defines version 1 of TLSRPT, for which this
      value MUST be equal to "TLSRPTv1".  Other versions may be defined
      in later documents.

   o  "rua": A URI specifying the endpoint to which aggregate
      information about policy validation results should be sent (see
      Section 4, "Reporting Schema", for more information).  Two URI
      schemes are supported: "mailto" and "https".  As with DMARC
      [RFC7489], the Policy Domain can specify a comma-separated list of
      URIs.

   o  In the case of "https", reports should be submitted via POST
      [RFC7231] to the specified URI.  Report submitters MAY ignore
      certificate validation errors when submitting reports via HTTPS
      POST.

   o  In the case of "mailto", reports should be submitted to the
      specified email address [RFC6068].  When sending failure reports
      via SMTP, Sending MTAs MUST deliver reports despite any TLS-
      related failures and SHOULD NOT include this SMTP session in the
      next report.  This may mean that the reports are delivered
      unencrypted.  Reports sent via SMTP MUST contain a valid
      DomainKeys Identified Mail (DKIM) [RFC6376] signature by the
      reporting domain.  Reports lacking such a signature MUST be
      ignored by the recipient.  DKIM signatures MUST NOT use the "l="
      attribute to limit the body length used in the signature.  This
      ensures attackers cannot append extraneous or misleading data to a
      report without breaking the signature.  The DKIM TXT record SHOULD
      contain the appropriate service type declaration, "s=tlsrpt".  If
      not present, the receiving system MAY ignore reports lacking that
      service type.

   Sample DKIM record:

      dkim_selector._domainkey.example.com TXT
            "v=DKIM1;k=rsa;s=tlsrpt;p=Mlf4qwSZfase4fa=="



Margolis, et al.             Standards Track                    [Page 6]

RFC 8460                   SMTP TLS Reporting             September 2018


   The formal definition of the "_smtp._tls" TXT record, defined using
   [RFC5234] and [RFC7405], is as follows:

        tlsrpt-record     = tlsrpt-version 1*(field-delim tlsrpt-field)
                            [field-delim]

        field-delim       = *WSP ";" *WSP

        tlsrpt-field      = tlsrpt-rua /        ; Note that the
                            tlsrpt-extension    ; tlsrpt-rua record is
                                                ; required.

        tlsrpt-version    = %s"v=TLSRPTv1"

        tlsrpt-rua        = %s"rua="
                            tlsrpt-uri *(*WSP "," *WSP tlsrpt-uri)

        tlsrpt-uri        = URI
                            ; "URI" is imported from [RFC3986];
                            ; commas (ASCII 0x2C), exclamation
                            ; points (ASCII 0x21), and semicolons
                            ; (ASCII 0x3B) MUST be encoded

        tlsrpt-extension  = tlsrpt-ext-name "=" tlsrpt-ext-value

        tlsrpt-ext-name   = (ALPHA / DIGIT) *31(ALPHA /
                            DIGIT / "_" / "-" / ".")

        tlsrpt-ext-value  = 1*(%x21-3A / %x3C / %x3E-7E)
                            ; chars excluding "=", ";", SP, and control
                            ; chars

   If multiple TXT records for "_smtp._tls" are returned by the
   resolver, records that do not begin with "v=TLSRPTv1;" are discarded.
   If the number of resulting records is not one, senders MUST assume
   the recipient domain does not implement TLSRPT.  If the resulting TXT
   record contains multiple strings (as described in Section 3.3 of
   [RFC7208]), then the record MUST be treated as if those strings are
   concatenated without adding spaces.

   The record supports the ability to declare more than one rua, and if
   there exists more than one, the reporter MAY attempt to deliver to
   each of the supported rua destinations.  A receiver MAY opt to only
   attempt delivery to one of the endpoints; however, the report SHOULD
   NOT be considered successfully delivered until one of the endpoints
   accepts delivery of the report.





Margolis, et al.             Standards Track                    [Page 7]

RFC 8460                   SMTP TLS Reporting             September 2018


   Parsers MUST accept TXT records that are syntactically valid (i.e.,
   valid key/value pairs separated by semicolons) and implement a
   superset of this specification, in which case unknown fields SHALL be
   ignored.

3.1.  Example Reporting Policy

3.1.1.  Report Using MAILTO

            _smtp._tls.example.com. IN TXT \
                    "v=TLSRPTv1;rua=mailto:reports@example.com"

3.1.2.  Report Using HTTPS

           _smtp._tls.example.com. IN TXT \
                   "v=TLSRPTv1; \
                   rua=https://reporting.example.com/v1/tlsrpt"

4.  Reporting Schema

   The report is composed as a plaintext file encoded in the Internet
   JSON (I-JSON) format [RFC7493].

   Aggregate reports contain the following fields:

   o  Report metadata:

      *  The organization responsible for the report

      *  Contact information for one or more responsible parties for the
         contents of the report

      *  A unique identifier for the report

      *  The reporting date range for the report

   o  Policy, consisting of:

      *  One of the following policy types: (1) the MTA-STS Policy
         applied (as a string), (2) the DANE TLSA record applied (as a
         string, with each RR entry of the RRset listed and separated by
         a semicolon), and (3) the literal string "no-policy-found", if
         neither a DANE nor MTA-STS Policy could be found.

      *  The domain for which the policy is applied

      *  The MX host




Margolis, et al.             Standards Track                    [Page 8]

RFC 8460                   SMTP TLS Reporting             September 2018


   o  Aggregate counts, comprising result type, Sending MTA IP,
      receiving MTA hostname, session count, and an optional additional
      information field containing a URI for recipients to review
      further information on a failure type.

   Note that the failure types are non-exclusive; an aggregate report
   may contain overlapping "counts" of failure types when a single send
   attempt encountered multiple errors.  Reporters may report multiple
   applied policies (for example, an MTA-STS Policy and a DANE TLSA
   record for the same domain and MX).  Because of this, even in the
   case where only a single policy was applied, the "policies" field of
   the report body MUST be an array and not a singular value.

   In the case of multiple failure types, the "failure-details" array
   would contain multiple entries.  Each entry would have its own set of
   information pertaining to that failure type.

4.1.  Report Time Frame

   The report SHOULD cover a full day, from 00:00-24:00 UTC.  This
   should allow for easier correlation of failure events.  To avoid
   unintentionally overloading the system processing the reports, the
   reports should be delivered after some delay, perhaps several hours.

   As an example, a sending site might want to introduce a random delay
   of up to four hours:

          func generate_sleep_delay() {
            min_delay = 1
            max_delay = 14400
            rand = random(min_delay, max_delay)
            return rand
          }

          func generate_report(policy_domain) {
            do_rpt_work(policy_domain)
            send_rpt(policy_domain)
          }

          func generate_tlsrpt() {
            sleep(generate_sleep_delay())
            for policy_domain in list_of_tlsrpt_enabled_domains {
              generate_report(policy_domain)
            }
          }






Margolis, et al.             Standards Track                    [Page 9]

RFC 8460                   SMTP TLS Reporting             September 2018


4.2.  Delivery Summary

4.2.1.  Success Count

   o  "total-successful-session-count": This indicates that the Sending
      MTA was able to successfully negotiate a policy-compliant TLS
      connection and serves to provide a "heartbeat" to receiving
      domains that signifies reporting is functional and tabulating
      correctly.  This field contains an aggregate count of successful
      connections for the reporting system.

4.2.2.  Failure Count

   o  "total-failure-session-count": This indicates that the Sending MTA
      was unable to successfully establish a connection with the
      receiving platform.  Section 4.3, "Result Types", will elaborate
      on the failed negotiation attempts.  This field contains an
      aggregate count of failed connections.

4.3.  Result Types

   The list of result types will start with the minimal set below and is
   expected to grow over time based on real-world experience.  The
   initial set is outlined in Sections 4.3.1 to 4.3.4:

4.3.1.  Negotiation Failures

   o  "starttls-not-supported": This indicates that the recipient MX did
      not support STARTTLS.

   o  "certificate-host-mismatch": This indicates that the certificate
      presented did not adhere to the constraints specified in the MTA-
      STS or DANE policy, e.g., if the MX hostname does not match any
      identities listed in the subject alternative name (SAN) [RFC5280].

   o  "certificate-expired": This indicates that the certificate has
      expired.

   o  "certificate-not-trusted": This is a label that covers multiple
      certificate-related failures that include, but are not limited to,
      errors such as untrusted/unknown certification authorities (CAs),
      certificate name constraints, certificate chain errors, etc.  When
      using this declaration, the reporting MTA SHOULD utilize the
      "failure-reason-code" to provide more information to the receiving
      entity.






Margolis, et al.             Standards Track                   [Page 10]

RFC 8460                   SMTP TLS Reporting             September 2018


   o  "validation-failure": This indicates a general failure for a
      reason not matching a category above.  When using this
      declaration, the reporting MTA SHOULD utilize the "failure-reason-
      code" to provide more information to the receiving entity.

4.3.2.  Policy Failures

4.3.2.1.  DANE-Specific Policy Failures

   o  "tlsa-invalid": This indicates a validation error in the TLSA
      record associated with a DANE policy.  None of the records in the
      RRset were found to be valid.

   o  "dnssec-invalid": This indicates that no valid records were
      returned from the recursive resolver.

   o  "dane-required": This indicates that the sending system is
      configured to require DANE TLSA records for all the MX hosts of
      the destination domain, but no DNSSEC-validated TLSA records were
      present for the MX host that is the subject of the report.
      Mandatory DANE for SMTP is described in Section 6 of [RFC7672].
      Such policies may be created by mutual agreement between two
      organizations that frequently exchange sensitive content via
      email.

4.3.2.2.  MTA-STS-specific Policy Failures

   o  "sts-policy-fetch-error": This indicates a failure to retrieve an
      MTA-STS policy, for example, because the policy host is
      unreachable.

   o  "sts-policy-invalid": This indicates a validation error for the
      overall MTA-STS Policy.

   o  "sts-webpki-invalid": This indicates that the MTA-STS Policy could
      not be authenticated using PKIX validation.

4.3.3.  General Failures

   When a negotiation failure cannot be categorized into one of the
   "Negotiation Failures" stated above, the reporter SHOULD use the
   "validation-failure" category.  As TLS grows and becomes more
   complex, new mechanisms may not be easily categorized.  This allows
   for a generic feedback category.  When this category is used, the
   reporter SHOULD also use "failure-reason-code" to give some feedback
   to the receiving entity.  This is intended to be a short text field,
   and the contents of the field should be an error code or error text,
   such as "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION".



Margolis, et al.             Standards Track                   [Page 11]

RFC 8460                   SMTP TLS Reporting             September 2018


4.3.4.  Transient Failures

   Transient errors due to too-busy networks, TCP timeouts, etc., are
   not required to be reported.

4.4.  JSON Report Schema

   The JSON schema is derived from the HTTP Public Key Pinning (HPKP)
   JSON schema; see Section 3 of [RFC7469].

 {
   "organization-name": organization-name,
   "date-range": {
     "start-datetime": date-time,
     "end-datetime": date-time
   },
   "contact-info": email-address,
   "report-id": report-id,
   "policies": [{
     "policy": {
       "policy-type": policy-type,
       "policy-string": policy-string,
       "policy-domain": domain,
       "mx-host": mx-host-pattern
     },
     "summary": {
       "total-successful-session-count": total-successful-session-count,
       "total-failure-session-count": total-failure-session-count
     },
     "failure-details": [
       {
         "result-type": result-type,
         "sending-mta-ip": ip-address,
         "receiving-mx-hostname": receiving-mx-hostname,
         "receiving-mx-helo": receiving-mx-helo,
         "receiving-ip": receiving-ip,
         "failed-session-count": failed-session-count,
         "additional-information": additional-info-uri,
         "failure-reason-code": failure-reason-code
         }
       ]
     }
   ]
 }


                            JSON Report Format




Margolis, et al.             Standards Track                   [Page 12]

RFC 8460                   SMTP TLS Reporting             September 2018


   o  "organization-name": The name of the organization responsible for
      the report.  It is provided as a string.

   o  "date-time": The date-time indicates the start and end times for
      the report range.  It is provided as a string formatted according
      to "Internet Date/Time Format", Section 5.6 of [RFC3339].  The
      report should be for a full UTC day, 00:00-24:00.

   o  "email-address": The contact information for the party responsible
      for the report.  It is provided as a string formatted according to
      "Addr-Spec Specification", Section 3.4.1 of [RFC5322].

   o  "report-id": A unique identifier for the report.  Report authors
      may use whatever scheme they prefer to generate a unique
      identifier.  It is provided as a string.

   o  "policy-type": The type of policy that was applied by the sending
      domain.  Presently, the only three valid choices are "tlsa",
      "sts", and the literal string "no-policy-found".  It is provided
      as a string.

   o  "policy-string": An encoding of the applied policy as a JSON array
      of strings, whether it's a TLSA record ([RFC6698], Section 2.3) or
      an MTA-STS Policy.  Examples follow in the next section.

   o  "domain": The Policy Domain against which the MTA-STS or DANE
      policy is defined.  In the case of Internationalized Domain Names
      [RFC5891], the domain MUST consist of the Punycode-encoded
      A-labels [RFC3492] and not the U-labels.

   o  "mx-host-pattern": In the case where "policy-type" is "sts", it's
      the pattern of MX hostnames from the applied policy.  It is
      provided as a JSON array of strings and is interpreted in the same
      manner as the rules in "MX Host Validation"; see Section 4.1 of
      [RFC8461].  In the case of Internationalized Domain Names
      [RFC5891], the domain MUST consist of the Punycode-encoded
      A-labels [RFC3492] and not the U-labels.

   o  "result-type": A value from Section 4.3, "Result Types", above.

   o  "ip-address": The IP address of the Sending MTA that attempted the
      STARTTLS connection.  It is provided as a string representation of
      an IPv4 (see below) or IPv6 [RFC5952] address in dot-decimal or
      colon-hexadecimal notation.

   o  "receiving-mx-hostname": The hostname of the receiving MTA MX
      record with which the Sending MTA attempted to negotiate a
      STARTTLS connection.



Margolis, et al.             Standards Track                   [Page 13]

RFC 8460                   SMTP TLS Reporting             September 2018


   o  "receiving-mx-helo" (optional): The HELLO (HELO) or Extended HELLO
      (EHLO) string from the banner announced during the reported
      session.

   o  "receiving-ip": The destination IP address that was used when
      creating the outbound session.  It is provided as a string
      representation of an IPv4 (see below) or IPv6 [RFC5952] address in
      dot-decimal or colon-hexadecimal notation.

   o  "total-successful-session-count": The aggregate count (an integer,
      encoded as a JSON number) of successfully negotiated TLS-enabled
      connections to the receiving site.

   o  "total-failure-session-count": The aggregate count (an integer,
      encoded as a JSON number) of failures to negotiate a TLS-enabled
      connection to the receiving site.

   o  "failed-session-count": The number of (attempted) sessions that
      match the relevant "result-type" for this section (an integer,
      encoded as a JSON number).

   o  "additional-info-uri" (optional): A URI [RFC3986] that points to
      additional information around the relevant "result-type".  For
      example, this URI might host the complete certificate chain
      presented during an attempted STARTTLS session.

   o  "failure-reason-code": A text field to include a TLS-related error
      code or error message.

   For report purposes, an IPv4 address is defined via the following
   ABNF:

     IPv4address = dec-octet "." dec-octet "." dec-octet "." dec-octet
     dec-octet     = DIGIT                 ; 0-9
                   / %x31-39 DIGIT         ; 10-99
                   / "1" 2DIGIT            ; 100-199
                   / "2" %x30-34 DIGIT     ; 200-249
                   / "25" %x30-35          ; 250-255

   And an IPv6 address is defined via the following ABNF:


     IPv6address = <as defined in [RFC5954]>








Margolis, et al.             Standards Track                   [Page 14]

RFC 8460                   SMTP TLS Reporting             September 2018


4.5.  Policy Samples

   Part of the report body includes the policy that is applied when
   attempting relay to the destination.

   For DANE TLSA policies, this is a JSON array of strings each
   representing the RDATA of a single TLSA resource record as a space-
   separated list of its four TLSA fields; the fields are in
   presentation format (defined in [RFC6698], Section 2.2) with no
   internal spaces or grouping parentheses:

       [
       "3 0 1 1F850A337E6DB9C609C522D136A475638CC43E1ED424F8EEC8513
              D747D1D085D",
       "3 0 1 12350A337E6DB9C6123522D136A475638CC43E1ED424F8EEC8513
              D747D1D1234"
       ]

   For MTA-STS policies, this is an array of JSON strings that
   represents the policy that is declared by the receiving site,
   including any errors that may be present.  Note that where there are
   multiple "mx" values, they must be listed as separate "mx" elements
   in the policy array rather than as a single nested "mx" sub-array.

                       [
                       "version: STSv1",
                       "mode: testing",
                       "mx: mx1.example.com",
                       "mx: mx2.example.com",
                       "mx: mx.backup-example.com",
                       "max_age: 604800"
                       ]

5.  Report Delivery

   Reports can be delivered either via SMTP (as an email message) or via
   HTTP POST.














Margolis, et al.             Standards Track                   [Page 15]

RFC 8460                   SMTP TLS Reporting             September 2018


5.1.  Report Filename

   The filename is RECOMMENDED to be constructed using the following
   ABNF:

    filename        = sender "!" policy-domain "!" begin-timestamp
                      "!" end-timestamp [ "!" unique-id ] "." extension

    unique-id       = 1*(ALPHA / DIGIT)

    sender          = domain ; from [RFC5321] -- this is used
                      ; as the domain for the `contact-info`
                      ; address in the report body.
                      ; In the case of Internationalized Domain
                      ; Names [RFC5891], the domain MUST consist of
                      ; the Punycode-encoded A-labels [RFC3492] and
                      ; not the U-labels.

    policy-domain   = domain
                      ; In the case of Internationalized Domain
                      ; Names [RFC5891], the domain MUST consist of
                      ; the Punycode-encoded A-labels [RFC3492] and
                      ; not the U-labels.

    begin-timestamp = 1*DIGIT
                      ; seconds since 00:00:00 UTC January 1, 1970
                      ; indicating start of the time range contained
                      ; in the report

    end-timestamp   = 1*DIGIT
                      ; seconds since 00:00:00 UTC January 1, 1970
                      ; indicating end of the time range contained
                      ; in the report

    extension       = "json" / "json.gz"


   The extension MUST be "json" for a plain JSON file or "json.gz" for a
   JSON file compressed using gzip.

   "unique-id" allows an optional unique ID generated by the Sending MTA
   to distinguish among multiple reports generated simultaneously by
   different sources for the same Policy Domain.  For example, this is a
   possible filename for a compressed report to the Policy Domain
   "example.net" from the Sending MTA "mail.sndr.example.com":

   "mail.sndr.example.com!example.net!1470013207!1470186007!001.json.gz"




Margolis, et al.             Standards Track                   [Page 16]

RFC 8460                   SMTP TLS Reporting             September 2018


5.2.  Compression

   The report SHOULD be subjected to gzip [RFC1952] compression for both
   email and HTTPS transport.  Declining to apply compression can cause
   the report to be too large for a receiver to process (a commonly
   observed receiver limit is ten megabytes); compressing the file
   increases the chances of acceptance of the report at some
   computational cost.

5.3.  Email Transport

   The report MAY be delivered by email.  To make the reports machine-
   parsable for the receivers, we define a top-level media type
   "multipart/report" with a new parameter "report-type="tlsrpt"".
   Inside it, there are two parts: The first part is human readable,
   typically "text/plain", and the second part is machine readable with
   a new media type defined called "application/tlsrpt+json".  If
   compressed, the report should use the media type "application/
   tlsrpt+gzip".

   In addition, the following two new top-level message header fields
   are defined:

   "TLS-Report-Domain: Receiver-Domain"

   "TLS-Report-Submitter: Sender-Domain"

   The "TLS-Report-Submitter" value MUST match the value found in the
   domain [RFC5321] of the "contact-info" from the report body.  These
   message header fields MUST be included and should allow for easy
   searching for all reports submitted by a reporting domain or a
   particular submitter, for example, in IMAP [RFC3501]:

   "s SEARCH HEADER "TLS-Report-Domain" "example.com""

   It is presumed that the aggregate reporting address will be equipped
   to process new message header fields and extract MIME parts with the
   prescribed media type and filename, and ignore the rest.  These
   additional headers SHOULD be included in the DKIM [RFC6376] signature
   for the message.











Margolis, et al.             Standards Track                   [Page 17]

RFC 8460                   SMTP TLS Reporting             September 2018


   The RFC5322.Subject field for report submissions SHOULD conform to
   the following ABNF:

       tlsrpt-subject = %s"Report" FWS               ; "Report"
                        %s"Domain:" FWS              ; "Domain:"
                        domain-name FWS              ; per [RFC6376]
                        %s"Submitter:" FWS           ; "Submitter:"
                        domain-name FWS              ; per [RFC6376]
                        %s"Report-ID:" FWS           ; "Report-ID:
                        "<" id-left "@" id-right ">" ; per [RFC5322]
                        [CFWS]                       ; per [RFC5322]
                                                     ; (as with FWS)

   The first domain-name indicates the DNS domain name about which the
   report was generated.  The second domain-name indicates the DNS
   domain name representing the Sending MTA generating the report.  The
   purpose of the "Report-ID:" portion of the field is to enable the
   Policy Domain to identify and ignore duplicate reports that might be
   sent by a Sending MTA.

   For instance, this is a possible Subject field for a report to the
   Policy Domain "example.net" from the Sending MTA
   "mail.sender.example.com".  It is line-wrapped as allowed by
   [RFC5322]:

              Subject: Report Domain: example.net
                  Submitter: mail.sender.example.com
                  Report-ID: <735ff.e317+bf22029@mailexample.net>























Margolis, et al.             Standards Track                   [Page 18]

RFC 8460                   SMTP TLS Reporting             September 2018


5.3.1.  Example Report

      From: tlsrpt@mail.sender.example.com
          Date: Fri, May 09 2017 16:54:30 -0800
          To: mts-sts-tlsrpt@example.net
          Subject: Report Domain: example.net
              Submitter: mail.sender.example.com
              Report-ID: <735ff.e317+bf22029@example.net>
          TLS-Report-Domain: example.net
          TLS-Report-Submitter: mail.sender.example.com
          MIME-Version: 1.0
          Content-Type: multipart/report; report-type="tlsrpt";
              boundary="----=_NextPart_000_024E_01CC9B0A.AFE54C00"
          Content-Language: en-us

          This is a multipart message in MIME format.

          ------=_NextPart_000_024E_01CC9B0A.AFE54C00
          Content-Type: text/plain; charset="us-ascii"
          Content-Transfer-Encoding: 7bit

          This is an aggregate TLS report from mail.sender.example.com

          ------=_NextPart_000_024E_01CC9B0A.AFE54C00
          Content-Type: application/tlsrpt+gzip
          Content-Transfer-Encoding: base64
          Content-Disposition: attachment;
              filename="mail.sender.example!example.com!
                        1013662812!1013749130.json.gz"

          <gzipped content of report>

     ------=_NextPart_000_024E_01CC9B0A.AFE54C00--
     ...

   Note that, when sending failure reports via SMTP, Sending MTAs MUST
   NOT honor MTA-STS or DANE TLSA failures.

5.4.  HTTPS Transport

   The report MAY be delivered by POST to HTTPS.  If compressed, the
   report SHOULD use the media type "application/tlsrpt+gzip"; otherwise
   it SHOULD use the media type "application/tlsrpt+json" (see
   Section 6, "IANA Considerations").

   The receiving system MUST return a "successful" response from its
   HTTPS server, typically a 200 or 201 HTTP code [RFC7231].  Other
   codes could indicate a delivery failure and may be retried as per



Margolis, et al.             Standards Track                   [Page 19]

RFC 8460                   SMTP TLS Reporting             September 2018


   local sender policy.  The receiving system is not expected to process
   reports at receipt time and MAY store them for processing at a later
   time.

5.5.  Delivery Retry

   In the event of a delivery failure, regardless of the delivery
   method, a sender SHOULD attempt redelivery for up to 24 hours after
   the initial attempt.  As previously stated, the reports are optional,
   so while it is ideal to attempt redelivery, it is not required.  If
   multiple retries are attempted, ideally they SHOULD be done with
   exponential backoff.

5.6.  Metadata Variances

   As stated above, there are a variable number of ways to declare
   information about the data therein.  If any of the items declared via
   subject or filename disagree with the report, the report MUST be
   considered the authoritative source.

6.  IANA Considerations

   The following are the IANA considerations discussed in this document.

6.1.  Message Headers

   Below is the Internet Assigned Numbers Authority (IANA) Permanent
   Message Header Field registration information per [RFC3864].

             Header field name:           TLS-Report-Domain
             Applicable protocol:         mail
             Status:                      standard
             Author/Change controller:    IETF
             Specification document(s):   RFC 8460


             Header field name:           TLS-Report-Submitter
             Applicable protocol:         mail
             Status:                      standard
             Author/Change controller:    IETF
             Specification document(s):   RFC 8460










Margolis, et al.             Standards Track                   [Page 20]

RFC 8460                   SMTP TLS Reporting             September 2018


6.2.  Report Type

   This document creates a new registry for the "report-type" parameter
   to the Content-Type header field for the "multipart/report" top-level
   media type defined in [RFC6522].

   The registry name is "Report Type Registry", and the procedure for
   updating the registry will be "Specification Required" [RFC8126].

   An entry in this registry should contain:

   o  the report-type being registered

   o  one or more registered media types that can be used with this
      report-type

   o  the document containing the registration action

   o  an optional comment

   The initial entries are:

   Report-Type: tlsrpt
   Media Type: application/tlsrpt+gzip, application/tlsrpt+json
   Registered By: [RFC8460]
   Comment: Media types suitable for use with this report-type are
   defined in Sections 6.4 and 6.5 of [RFC8460]

   Report-Type: disposition-notification
   Media Type: message/disposition-notification
   Registered By: [RFC8098], Section 10

   Report-Type: disposition-notification
   Media Type: message/global-disposition-notification
   Registered By: [RFC6533], Section 6

   Report-Type: delivery-status
   Media Type: message/delivery-status
   Registered By: [RFC3464], Section 6.2

   Report-Type: delivery-status
   Media Type: message/global-delivery-status
   Registered By: [RFC6533], Section 6








Margolis, et al.             Standards Track                   [Page 21]

RFC 8460                   SMTP TLS Reporting             September 2018


6.3.  +gzip Media Type Suffix

   This document registers a new media type suffix "+gzip".  The gzip
   format is a public domain, cross-platform, interoperable file storage
   and transfer format, specified in [RFC1952]; it supports compression
   and is used as the underlying representation by a variety of file
   formats.  The media type "application/gzip" has been registered for
   such files.  The suffix "+gzip" MAY be used with any media type whose
   representation follows that established for "application/gzip".  The
   registration form for the structured syntax suffix for use with media
   types is as follows:

   Type name: gzip file storage and transfer format.

   +suffix: +gzip

   References: [RFC1952] [RFC6713]

   Encoding considerations: gzip is a binary encoding.

   Fragment identifier considerations: The syntax and semantics of
   fragment identifiers specified for +gzip SHOULD be as specified for
   "application/gzip".  (At publication of this document, there is no
   fragment identification syntax defined for "application/gzip".)  The
   syntax and semantics for fragment identifiers for a specific "xxx/
   yyy+gzip" SHOULD be processed as follows:

       For cases defined in +gzip, where the fragment identifier
       resolves per the +gzip rules, process as specified in
       +gzip.

       For cases defined in +gzip, where the fragment identifier does
       not resolve per the +gzip rules, process as specified in
       "xxx/yyy+gzip".

       For cases not defined in +gzip, process as specified in
       "xxx/yyy+gzip".

   Interoperability considerations: N/A

   Security considerations: gzip format doesn't provide confidentiality
   protection.  Integrity protection is provided by an Adler-32
   checksum, which is not cryptographically strong.  See also the
   security considerations of [RFC6713].  Each individual media type
   registered with a +gzip suffix can have additional security
   considerations.  Additionally, gzip objects can contain multiple





Margolis, et al.             Standards Track                   [Page 22]

RFC 8460                   SMTP TLS Reporting             September 2018


   files and associated paths.  File paths must be validated when the
   files are extracted; a malicious file path could otherwise cause the
   extractor to overwrite application or system files.

   Contact: art@ietf.org

   Author/Change controller: Internet Engineering Task Force
   (iesg@ietf.org).

6.4.  application/tlsrpt+json Media Type

   This document registers multiple media types, beginning with Table 1
   below.

    +-------------+----------------+-------------+-------------------+
    | Type        | Subtype        | File Ext    | Specification     |
    +-------------+----------------+-------------+-------------------+
    | application | tlsrpt+json    |  .json      | Section 5.3       |
    +-------------+----------------+-------------+-------------------+

                    Table 1: SMTP TLS Reporting Media Type

   Type name: application

   Subtype name: tlsrpt+json

   Required parameters: N/A

   Optional parameters: N/A

   Encoding considerations: Encoding considerations are identical to
   those specified for the "application/json" media type.  See
   [RFC7493].

   Security considerations: Security considerations relating to SMTP TLS
   Reporting are discussed in Section 7.

   Interoperability considerations: This document specifies the format
   of conforming messages and the interpretation thereof.

   Published specification: Section 5.3 of RFC 8460.

   Applications that use this media type: Mail User Agents (MUAs) and
   Mail Transfer Agents.







Margolis, et al.             Standards Track                   [Page 23]

RFC 8460                   SMTP TLS Reporting             September 2018


   Additional information:

      Deprecated alias names for this type: N/A

      Magic number(s): N/A

      File extension(s): ".json"

      Macintosh file type code(s): N/A

   Person & email address to contact for further information:
   See the Authors' Addresses section.

   Intended usage: COMMON

   Restrictions on usage: N/A

   Author: See the Authors' Addresses section.

   Change controller: Internet Engineering Task Force (iesg@ietf.org).

6.5.  application/tlsrpt+gzip Media Type

    +-------------+----------------+-------------+-------------------+
    | Type        | Subtype        | File Ext    | Specification     |
    +-------------+----------------+-------------+-------------------+
    | application | tlsrpt+gzip    |  .gz        | Section 5.3       |
    +-------------+----------------+-------------+-------------------+

                    Table 2: SMTP TLS Reporting Media Type

   Type name: application

   Subtype name: tlsrpt+gzip

   Required parameters: N/A

   Optional parameters: N/A

   Encoding considerations: Binary

   Security considerations: Security considerations relating to SMTP TLS
   Reporting are discussed in Section 7.  Security considerations
   related to gzip compression are discussed in RFC 6713.

   Interoperability considerations: This document specifies the format
   of conforming messages and the interpretation thereof.




Margolis, et al.             Standards Track                   [Page 24]

RFC 8460                   SMTP TLS Reporting             September 2018


   Published specification: Section 5.3 of RFC 8460.

   Applications that use this media type: Mail User Agents (MUAs) and
   Mail Transfer Agents.

   Additional information:

      Deprecated alias names for this type: N/A

      Magic number(s): The first two bytes are 0x1f, 0x8b.

      File extension(s): ".gz"

      Macintosh file type code(s): N/A

   Person & email address to contact for further information:
   See the Authors' Addresses section.

   Intended usage: COMMON

   Restrictions on usage: N/A

   Author: See the Authors' Addresses section.

   Change controller: Internet Engineering Task Force (iesg@ietf.org).

6.6.  STARTTLS Validation Result Types

   This document creates a new registry, "STARTTLS Validation Result
   Types".  The initial entries in the registry are:

              +-----------------------------+--------------+
              | Result Type                 |  Description |
              +-----------------------------+--------------+
              | starttls-not-supported      |  Section 4.3 |
              | certificate-host-mismatch   |  Section 4.3 |
              | certificate-expired         |  Section 4.3 |
              | tlsa-invalid                |  Section 4.3 |
              | dnssec-invalid              |  Section 4.3 |
              | dane-required               |  Section 4.3 |
              | certificate-not-trusted     |  Section 4.3 |
              | sts-policy-invalid          |  Section 4.3 |
              | sts-webpki-invalid          |  Section 4.3 |
              | validation-failure          |  Section 4.3 |
              | sts-policy-fetch-error      |  Section 4.3 |
              +-----------------------------+--------------+





Margolis, et al.             Standards Track                   [Page 25]

RFC 8460                   SMTP TLS Reporting             September 2018


   The above entries are described in Section 4.3, "Result Types".  New
   result types can be added to this registry using the "Expert Review"
   IANA registration policy.

7.  Security Considerations

   SMTP TLS Reporting provides visibility into misconfigurations or
   attempts to intercept or tamper with mail between hosts who support
   STARTTLS.  There are several security risks presented by the
   existence of this reporting channel:

   o  Flooding of the Aggregate Report URI (rua) endpoint: An attacker
      could flood the endpoint with excessive reporting traffic and
      prevent the receiving domain from accepting additional reports.
      This type of Denial-of-Service attack would limit visibility into
      STARTTLS failures, leaving the receiving domain blind to an
      ongoing attack.

   o  Untrusted content: An attacker could inject malicious code into
      the report, exploiting any vulnerabilities in the report-handling
      systems of the receiving domain.  Implementers are advised to take
      precautions against evaluating the contents of the report.

   o  Report snooping: An attacker could create a bogus TLSRPT record to
      receive statistics about a domain the attacker does not own.
      Since an attacker that is able to poison DNS is already able to
      receive counts of SMTP connections (and, absent DANE or MTA-STS
      policies, actual SMTP message payloads), this does not present a
      significant new vulnerability.

   o  Ignoring HTTPS validation when submitting reports: When reporting
      benign misconfigurations, it is likely that a misconfigured SMTP
      server may also mean a misconfigured HTTPS server; as a result,
      reporters who require HTTPS validity on the reporting endpoint may
      fail to alert administrators about such misconfigurations.
      Conversely, in the event of an actual attack, an attacker who
      wishes to create a gap in reporting and could intercept HTTPS
      reports could, just as easily, simply thwart the resolution of the
      TLSRPT TXT record or establishment of the TCP session to the HTTPS
      endpoint.  Furthermore, such a man-in-the-middle attacker could
      discover most or all of the metadata exposed in a report merely
      through passive observation.  As a result, we consider the risks
      of failure to deliver reports on misconfigurations to outweigh
      those of attackers intercepting reports.







Margolis, et al.             Standards Track                   [Page 26]

RFC 8460                   SMTP TLS Reporting             September 2018


   o  Reports as DDoS: TLSRPT allows specifying destinations for the
      reports that are outside the authority of the Policy Domain, which
      allows domains to delegate processing of reports to a partner
      organization.  However, an attacker who controls the Policy Domain
      DNS could also use this mechanism to direct the reports to an
      unwitting victim, flooding that victim with excessive reports.
      DMARC [RFC7489] defines a solution for verifying delegation to
      avoid such attacks; the need for this is greater with DMARC,
      however, because DMARC allows an attacker to trigger reports to a
      target from an innocent third party by sending mail to that third
      party (which triggers a report from the third party to the
      target).  In the case of TLSRPT, the attacker would have to induce
      the third party to send mail to the attacker in order to trigger
      reports from the third party to the victim; this reduces the risk
      of such an attack and the need for a verification mechanism.

   Finally, because TLSRPT is intended to help administrators discover
   man-in-the-middle attacks against transport-layer encryption,
   including attacks designed to thwart negotiation of encrypted
   connections (by downgrading opportunistic encryption or, in the case
   of MTA-STS, preventing discovery of a new MTA-STS Policy), we must
   also consider the risk that an adversary who can induce such a
   downgrade attack can also prevent discovery of the TLSRPT TXT record
   (and thus prevent discovery of the successful downgrade attack).
   Administrators are thus encouraged to deploy TLSRPT TXT records with
   a large TTL (reducing the window for successful application of
   transient attacks against DNS resolution of the record) or to deploy
   DNSSEC on the deploying zone.

8.  Privacy Considerations

   MTAs are generally considered public knowledge; however, the
   internals of how those MTAs are configured and the users of those
   MTAs may not be as public.  It should be noted that providing a
   receiving site with information about TLS failures may reveal
   information about the sender's configuration or even information
   about the senders themselves.  For example, sending a report may
   disclose what TLS implementation the sender uses, as the inability to
   negotiate a session may be a known incompatibility between two
   implementations.  This may, indirectly, leak information on the
   reporter's operating system or even region, if, for example, a rare
   TLS implementation is popular among certain users or in certain
   locations.








Margolis, et al.             Standards Track                   [Page 27]

RFC 8460                   SMTP TLS Reporting             September 2018


9.  References

9.1.  Normative References

   [RFC1952]  Deutsch, P., "GZIP file format specification version 4.3",
              RFC 1952, DOI 10.17487/RFC1952, May 1996,
              <https://www.rfc-editor.org/info/rfc1952>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC3339]  Klyne, G. and C. Newman, "Date and Time on the Internet:
              Timestamps", RFC 3339, DOI 10.17487/RFC3339, July 2002,
              <https://www.rfc-editor.org/info/rfc3339>.

   [RFC3492]  Costello, A., "Punycode: A Bootstring encoding of Unicode
              for Internationalized Domain Names in Applications
              (IDNA)", RFC 3492, DOI 10.17487/RFC3492, March 2003,
              <https://www.rfc-editor.org/info/rfc3492>.

   [RFC3986]  Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
              Resource Identifier (URI): Generic Syntax", STD 66,
              RFC 3986, DOI 10.17487/RFC3986, January 2005,
              <https://www.rfc-editor.org/info/rfc3986>.

   [RFC5234]  Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234,
              DOI 10.17487/RFC5234, January 2008,
              <https://www.rfc-editor.org/info/rfc5234>.

   [RFC5280]  Cooper, D., Santesson, S., Farrell, S., Boeyen, S.,
              Housley, R., and W. Polk, "Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 5280, DOI 10.17487/RFC5280, May 2008,
              <https://www.rfc-editor.org/info/rfc5280>.

   [RFC5321]  Klensin, J., "Simple Mail Transfer Protocol", RFC 5321,
              DOI 10.17487/RFC5321, October 2008,
              <https://www.rfc-editor.org/info/rfc5321>.

   [RFC5322]  Resnick, P., Ed., "Internet Message Format", RFC 5322,
              DOI 10.17487/RFC5322, October 2008,
              <https://www.rfc-editor.org/info/rfc5322>.






Margolis, et al.             Standards Track                   [Page 28]

RFC 8460                   SMTP TLS Reporting             September 2018


   [RFC5891]  Klensin, J., "Internationalized Domain Names in
              Applications (IDNA): Protocol", RFC 5891,
              DOI 10.17487/RFC5891, August 2010,
              <https://www.rfc-editor.org/info/rfc5891>.

   [RFC5952]  Kawamura, S. and M. Kawashima, "A Recommendation for IPv6
              Address Text Representation", RFC 5952,
              DOI 10.17487/RFC5952, August 2010,
              <https://www.rfc-editor.org/info/rfc5952>.

   [RFC6068]  Duerst, M., Masinter, L., and J. Zawinski, "The 'mailto'
              URI Scheme", RFC 6068, DOI 10.17487/RFC6068, October 2010,
              <https://www.rfc-editor.org/info/rfc6068>.

   [RFC6376]  Crocker, D., Ed., Hansen, T., Ed., and M. Kucherawy, Ed.,
              "DomainKeys Identified Mail (DKIM) Signatures", STD 76,
              RFC 6376, DOI 10.17487/RFC6376, September 2011,
              <https://www.rfc-editor.org/info/rfc6376>.

   [RFC6522]  Kucherawy, M., Ed., "The Multipart/Report Media Type for
              the Reporting of Mail System Administrative Messages",
              STD 73, RFC 6522, DOI 10.17487/RFC6522, January 2012,
              <https://www.rfc-editor.org/info/rfc6522>.

   [RFC6698]  Hoffman, P. and J. Schlyter, "The DNS-Based Authentication
              of Named Entities (DANE) Transport Layer Security (TLS)
              Protocol: TLSA", RFC 6698, DOI 10.17487/RFC6698, August
              2012, <https://www.rfc-editor.org/info/rfc6698>.

   [RFC6713]  Levine, J., "The 'application/zlib' and 'application/gzip'
              Media Types", RFC 6713, DOI 10.17487/RFC6713, August 2012,
              <https://www.rfc-editor.org/info/rfc6713>.

   [RFC7208]  Kitterman, S., "Sender Policy Framework (SPF) for
              Authorizing Use of Domains in Email, Version 1", RFC 7208,
              DOI 10.17487/RFC7208, April 2014,
              <https://www.rfc-editor.org/info/rfc7208>.

   [RFC7231]  Fielding, R., Ed. and J. Reschke, Ed., "Hypertext Transfer
              Protocol (HTTP/1.1): Semantics and Content", RFC 7231,
              DOI 10.17487/RFC7231, June 2014,
              <https://www.rfc-editor.org/info/rfc7231>.

   [RFC7405]  Kyzivat, P., "Case-Sensitive String Support in ABNF",
              RFC 7405, DOI 10.17487/RFC7405, December 2014,
              <https://www.rfc-editor.org/info/rfc7405>.





Margolis, et al.             Standards Track                   [Page 29]

RFC 8460                   SMTP TLS Reporting             September 2018


   [RFC7493]  Bray, T., Ed., "The I-JSON Message Format", RFC 7493,
              DOI 10.17487/RFC7493, March 2015,
              <https://www.rfc-editor.org/info/rfc7493>.

   [RFC7671]  Dukhovni, V. and W. Hardaker, "The DNS-Based
              Authentication of Named Entities (DANE) Protocol: Updates
              and Operational Guidance", RFC 7671, DOI 10.17487/RFC7671,
              October 2015, <https://www.rfc-editor.org/info/rfc7671>.

   [RFC7672]  Dukhovni, V. and W. Hardaker, "SMTP Security via
              Opportunistic DNS-Based Authentication of Named Entities
              (DANE) Transport Layer Security (TLS)", RFC 7672,
              DOI 10.17487/RFC7672, October 2015,
              <https://www.rfc-editor.org/info/rfc7672>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8461]  Margolis, D., Risher, M., Ramakrishnan, B., Brotman, A.,
              and J. Jones, "SMTP MTA Strict Transport Security (MTA-
              STS)", RFC 8461, DOI 10.17487/RFC8461, September 2018,
              <https://www.rfc-editor.org/info/rfc8461>.

9.2.  Informative References

   [RFC3207]  Hoffman, P., "SMTP Service Extension for Secure SMTP over
              Transport Layer Security", RFC 3207, DOI 10.17487/RFC3207,
              February 2002, <https://www.rfc-editor.org/info/rfc3207>.

   [RFC3464]  Moore, K. and G. Vaudreuil, "An Extensible Message Format
              for Delivery Status Notifications", RFC 3464,
              DOI 10.17487/RFC3464, January 2003,
              <https://www.rfc-editor.org/info/rfc3464>.

   [RFC3501]  Crispin, M., "INTERNET MESSAGE ACCESS PROTOCOL - VERSION
              4rev1", RFC 3501, DOI 10.17487/RFC3501, March 2003,
              <https://www.rfc-editor.org/info/rfc3501>.

   [RFC3864]  Klyne, G., Nottingham, M., and J. Mogul, "Registration
              Procedures for Message Header Fields", BCP 90, RFC 3864,
              DOI 10.17487/RFC3864, September 2004,
              <https://www.rfc-editor.org/info/rfc3864>.

   [RFC6533]  Hansen, T., Ed., Newman, C., and A. Melnikov,
              "Internationalized Delivery Status and Disposition
              Notifications", RFC 6533, DOI 10.17487/RFC6533, February
              2012, <https://www.rfc-editor.org/info/rfc6533>.



Margolis, et al.             Standards Track                   [Page 30]

RFC 8460                   SMTP TLS Reporting             September 2018


   [RFC7435]  Dukhovni, V., "Opportunistic Security: Some Protection
              Most of the Time", RFC 7435, DOI 10.17487/RFC7435,
              December 2014, <https://www.rfc-editor.org/info/rfc7435>.

   [RFC7469]  Evans, C., Palmer, C., and R. Sleevi, "Public Key Pinning
              Extension for HTTP", RFC 7469, DOI 10.17487/RFC7469, April
              2015, <https://www.rfc-editor.org/info/rfc7469>.

   [RFC7489]  Kucherawy, M., Ed. and E. Zwicky, Ed., "Domain-based
              Message Authentication, Reporting, and Conformance
              (DMARC)", RFC 7489, DOI 10.17487/RFC7489, March 2015,
              <https://www.rfc-editor.org/info/rfc7489>.

   [RFC8098]  Hansen, T., Ed. and A. Melnikov, Ed., "Message Disposition
              Notification", STD 85, RFC 8098, DOI 10.17487/RFC8098,
              February 2017, <https://www.rfc-editor.org/info/rfc8098>.

   [RFC8126]  Cotton, M., Leiba, B., and T. Narten, "Guidelines for
              Writing an IANA Considerations Section in RFCs", BCP 26,
              RFC 8126, DOI 10.17487/RFC8126, June 2017,
              <https://www.rfc-editor.org/info/rfc8126>.






























Margolis, et al.             Standards Track                   [Page 31]

RFC 8460                   SMTP TLS Reporting             September 2018


Appendix A.  Example Reporting Policy

A.1.  Report Using MAILTO

            _smtp._tls.mail.example.com. IN TXT \
                    "v=TLSRPTv1;rua=mailto:reports@example.com"

A.2.  Report Using HTTPS

           _smtp._tls.mail.example.com. IN TXT \
                   "v=TLSRPTv1; \
                   rua=https://reporting.example.com/v1/tlsrpt"

Appendix B.  Example JSON Report

   Below is an example JSON report for messages from Company-X to
   Company-Y, where 100 sessions were attempted to Company-Y servers
   with an expired certificate, and 200 sessions were attempted to
   Company-Y servers that did not successfully respond to the "STARTTLS"
   command.  Additionally, 3 sessions failed due to
   "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED".

   {
     "organization-name": "Company-X",
     "date-range": {
       "start-datetime": "2016-04-01T00:00:00Z",
       "end-datetime": "2016-04-01T23:59:59Z"
     },
     "contact-info": "sts-reporting@company-x.example",
     "report-id": "5065427c-23d3-47ca-b6e0-946ea0e8c4be",
     "policies": [{
       "policy": {
         "policy-type": "sts",
         "policy-string": ["version: STSv1","mode: testing",
               "mx: *.mail.company-y.example","max_age: 86400"],
         "policy-domain": "company-y.example",
         "mx-host": "*.mail.company-y.example"
       },
       "summary": {
         "total-successful-session-count": 5326,
         "total-failure-session-count": 303
       },
       "failure-details": [{
         "result-type": "certificate-expired",
         "sending-mta-ip": "2001:db8:abcd:0012::1",
         "receiving-mx-hostname": "mx1.mail.company-y.example",
         "failed-session-count": 100
       }, {



Margolis, et al.             Standards Track                   [Page 32]

RFC 8460                   SMTP TLS Reporting             September 2018


         "result-type": "starttls-not-supported",
         "sending-mta-ip": "2001:db8:abcd:0013::1",
         "receiving-mx-hostname": "mx2.mail.company-y.example",
         "receiving-ip": "203.0.113.56",
         "failed-session-count": 200,
         "additional-information": "https://reports.company-x.example/
           report_info ? id = 5065427 c - 23 d3# StarttlsNotSupported "
       }, {
         "result-type": "validation-failure",
         "sending-mta-ip": "198.51.100.62",
         "receiving-ip": "203.0.113.58",
         "receiving-mx-hostname": "mx-backup.mail.company-y.example",
         "failed-session-count": 3,
         "failure-reason-code": "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED"
       }]
     }]
   }


































Margolis, et al.             Standards Track                   [Page 33]

RFC 8460                   SMTP TLS Reporting             September 2018


Contributors

   Laetitia Baudoin
   Google, Inc.
   lbaudoin@google.com

Authors' Addresses

   Daniel Margolis
   Google, Inc.

   Email: dmargolis@google.com


   Alexander Brotman
   Comcast, Inc.

   Email: alex_brotman@comcast.com


   Binu Ramakrishnan
   Oath, Inc.

   Email: prbinu@yahoo.com


   Janet Jones
   Microsoft, Inc.

   Email: janet.jones@microsoft.com


   Mark Risher
   Google, Inc.

   Email: risher@google.com















Margolis, et al.             Standards Track                   [Page 34]


```

---

# RFC 6844 — CAA — Certification Authority Authorization (base)

```






Internet Engineering Task Force (IETF)                   P. Hallam-Baker
Request for Comments: 6844                            Comodo Group, Inc.
Category: Standards Track                                   R. Stradling
ISSN: 2070-1721                                          Comodo CA, Ltd.
                                                            January 2013


    DNS Certification Authority Authorization (CAA) Resource Record

Abstract

   The Certification Authority Authorization (CAA) DNS Resource Record
   allows a DNS domain name holder to specify one or more Certification
   Authorities (CAs) authorized to issue certificates for that domain.
   CAA Resource Records allow a public Certification Authority to
   implement additional controls to reduce the risk of unintended
   certificate mis-issue.  This document defines the syntax of the CAA
   record and rules for processing CAA records by certificate issuers.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 5741.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc6844.

Copyright Notice

   Copyright (c) 2013 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.




Hallam-Baker & Stradling     Standards Track                    [Page 1]

RFC 6844          Certification Authority Authorization     January 2013


Table of Contents

   1. Introduction ....................................................2
   2. Definitions .....................................................3
      2.1. Requirements Language ......................................3
      2.2. Defined Terms ..............................................3
   3. The CAA RR Type .................................................5
   4. Certification Authority Processing ..............................7
      4.1. Use of DNS Security ........................................8
   5. Mechanism .......................................................8
      5.1. Syntax .....................................................8
           5.1.1. Canonical Presentation Format ......................10
      5.2. CAA issue Property ........................................10
      5.3. CAA issuewild Property ....................................12
      5.4. CAA iodef Property ........................................12
   6. Security Considerations ........................................13
      6.1. Non-Compliance by Certification Authority .................13
      6.2. Mis-Issue by Authorized Certification Authority ...........13
      6.3. Suppression or Spoofing of CAA Records ....................13
      6.4. Denial of Service .........................................14
      6.5. Abuse of the Critical Flag ................................14
   7. IANA Considerations ............................................14
      7.1. Registration of the CAA Resource Record Type ..............14
      7.2. Certification Authority Restriction Properties ............15
      7.3. Certification Authority Restriction Flags .................15
   8. Acknowledgements ...............................................16
   9. References .....................................................16
      9.1. Normative References ......................................16
      9.2. Informative References ....................................17

1.  Introduction

   The Certification Authority Authorization (CAA) DNS Resource Record
   allows a DNS domain name holder to specify the Certification
   Authorities (CAs) authorized to issue certificates for that domain.
   Publication of CAA Resource Records allows a public Certification
   Authority to implement additional controls to reduce the risk of
   unintended certificate mis-issue.

   Like the TLSA record defined in DNS-Based Authentication of Named
   Entities (DANE) [RFC6698], CAA records are used as a part of a
   mechanism for checking PKIX certificate data.  The distinction
   between the two specifications is that CAA records specify an
   authorization control to be performed by a certificate issuer before
   issue of a certificate and TLSA records specify a verification
   control to be performed by a relying party after the certificate is
   issued.




Hallam-Baker & Stradling     Standards Track                    [Page 2]

RFC 6844          Certification Authority Authorization     January 2013


   Conformance with a published CAA record is a necessary but not
   sufficient condition for issuance of a certificate.  Before issuing a
   certificate, a PKIX CA is required to validate the request according
   to the policies set out in its Certificate Policy.  In the case of a
   public CA that validates certificate requests as a third party, the
   certificate will typically be issued under a public trust anchor
   certificate embedded in one or more relevant Relying Applications.

   Criteria for inclusion of embedded trust anchor certificates in
   applications are outside the scope of this document.  Typically, such
   criteria require the CA to publish a Certificate Practices Statement
   (CPS) that specifies how the requirements of the Certificate Policy
   (CP) are achieved.  It is also common for a CA to engage an
   independent third-party auditor to prepare an annual audit statement
   of its performance against its CPS.

   A set of CAA records describes only current grants of authority to
   issue certificates for the corresponding DNS domain.  Since a
   certificate is typically valid for at least a year, it is possible
   that a certificate that is not conformant with the CAA records
   currently published was conformant with the CAA records published at
   the time that the certificate was issued.  Relying Applications MUST
   NOT use CAA records as part of certificate validation.

   CAA records MAY be used by Certificate Evaluators as a possible
   indicator of a security policy violation.  Such use SHOULD take
   account of the possibility that published CAA records changed between
   the time a certificate was issued and the time at which the
   certificate was observed by the Certificate Evaluator.

2.  Definitions

2.1.  Requirements Language

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
   document are to be interpreted as described in [RFC2119].

2.2.  Defined Terms

   The following terms are used in this document:

   Authorization Entry:  An authorization assertion that grants or
      denies a specific set of permissions to a specific group of
      entities.

   Certificate:  An X.509 Certificate, as specified in [RFC5280].




Hallam-Baker & Stradling     Standards Track                    [Page 3]

RFC 6844          Certification Authority Authorization     January 2013


   Certificate Evaluator:  A party other than a relying party that
      evaluates the trustworthiness of certificates issued by
      Certification Authorities.

   Certification Authority (CA):  An issuer that issues certificates in
      accordance with a specified Certificate Policy.

   Certificate Policy (CP):  Specifies the criteria that a Certification
      Authority undertakes to meet in its issue of certificates.  See
      [RFC3647].

   Certification Practices Statement (CPS):  Specifies the means by
      which the criteria of the Certificate Policy are met.  In most
      cases, this will be the document against which the operations of
      the Certification Authority are audited.  See [RFC3647].

   Domain:  A DNS Domain Name.

   Domain Name:  A DNS Domain Name as specified in [STD13].

   Domain Name System (DNS):  The Internet naming system specified in
      [STD13].

   DNS Security (DNSSEC):  Extensions to the DNS that provide
      authentication services as specified in [RFC4033], [RFC4034],
      [RFC4035], [RFC5155], and revisions.

   Issuer:  An entity that issues certificates.  See [RFC5280].

   Property:  The tag-value portion of a CAA Resource Record.

   Property Tag:  The tag portion of a CAA Resource Record.

   Property Value:  The value portion of a CAA Resource Record.

   Public Key Infrastructure X.509 (PKIX):  Standards and specifications
      issued by the IETF that apply the [X.509] certificate standards
      specified by the ITU to Internet applications as specified in
      [RFC5280] and related documents.

   Resource Record (RR):  A particular entry in the DNS including the
      owner name, class, type, time to live, and data, as defined in
      [STD13] and [RFC2181].

   Resource Record Set (RRSet):  A set of Resource Records or a
      particular owner name, class, and type.  The time to live on all
      RRs with an RRSet is always the same, but the data may be
      different among RRs in the RRSet.



Hallam-Baker & Stradling     Standards Track                    [Page 4]

RFC 6844          Certification Authority Authorization     January 2013


   Relying Party:  A party that makes use of an application whose
      operation depends on use of a certificate for making a security
      decision.  See [RFC5280].

   Relying Application:  An application whose operation depends on use
      of a certificate for making a security decision.

3.  The CAA RR Type

   A CAA RR consists of a flags byte and a tag-value pair referred to as
   a property.  Multiple properties MAY be associated with the same
   domain name by publishing multiple CAA RRs at that domain name.  The
   following flag is defined:

   Issuer Critical:  If set to '1', indicates that the corresponding
      property tag MUST be understood if the semantics of the CAA record
      are to be correctly interpreted by an issuer.

      Issuers MUST NOT issue certificates for a domain if the relevant
      CAA Resource Record set contains unknown property tags that have
      the Critical bit set.

   The following property tags are defined:

   issue <Issuer Domain Name> [; <name>=<value> ]* :  The issue property
      entry authorizes the holder of the domain name <Issuer Domain
      Name> or a party acting under the explicit authority of the holder
      of that domain name to issue certificates for the domain in which
      the property is published.

   issuewild <Issuer Domain Name> [; <name>=<value> ]* :  The issuewild
      property entry authorizes the holder of the domain name <Issuer
      Domain Name> or a party acting under the explicit authority of the
      holder of that domain name to issue wildcard certificates for the
      domain in which the property is published.

   iodef <URL> :  Specifies a URL to which an issuer MAY report
      certificate issue requests that are inconsistent with the issuer's
      Certification Practices or Certificate Policy, or that a
      Certificate Evaluator may use to report observation of a possible
      policy violation.  The Incident Object Description Exchange Format
      (IODEF) format is used [RFC5070].

   The following example is a DNS zone file (see [RFC1035]) that informs
   CAs that certificates are not to be issued except by the holder of
   the domain name 'ca.example.net' or an authorized agent thereof.
   This policy applies to all subordinate domains under example.com.




Hallam-Baker & Stradling     Standards Track                    [Page 5]

RFC 6844          Certification Authority Authorization     January 2013


   $ORIGIN example.com
   .       CAA 0 issue "ca.example.net"

   If the domain name holder specifies one or more iodef properties, a
   certificate issuer MAY report invalid certificate requests to that
   address.  In the following example, the domain name holder specifies
   that reports may be made by means of email with the IODEF data as an
   attachment, a Web service [RFC6546], or both:

   $ORIGIN example.com
   .       CAA 0 issue "ca.example.net"
   .       CAA 0 iodef "mailto:security@example.com"
   .       CAA 0 iodef "http://iodef.example.com/"

   A certificate issuer MAY specify additional parameters that allow
   customers to specify additional parameters governing certificate
   issuance.  This might be the Certificate Policy under which the
   certificate is to be issued, the authentication process to be used
   might be specified, or an account number specified by the CA to
   enable these parameters to be retrieved.

   For example, the CA 'ca.example.net' has requested its customer
   'example.com' to specify the CA's account number '230123' in each of
   the customer's CAA records.

   $ORIGIN example.com
   .       CAA 0 issue "ca.example.net; account=230123"

   The syntax of additional parameters is a sequence of name-value pairs
   as defined in Section 5.2.  The semantics of such parameters is left
   to site policy and is outside the scope of this document.

   The critical flag is intended to permit future versions CAA to
   introduce new semantics that MUST be understood for correct
   processing of the record, preventing conforming CAs that do not
   recognize the new semantics from issuing certificates for the
   indicated domains.

   In the following example, the property 'tbs' is flagged as critical.
   Neither the example.net CA nor any other issuer is authorized to
   issue under either policy unless the processing rules for the 'tbs'
   property tag are understood.

   $ORIGIN example.com
   .       CAA 0 issue "ca.example.net; policy=ev"
   .       CAA 128 tbs "Unknown"





Hallam-Baker & Stradling     Standards Track                    [Page 6]

RFC 6844          Certification Authority Authorization     January 2013


   Note that the above restrictions only apply at certificate issue.
   Since the validity of an end entity certificate is typically a year
   or more, it is quite possible that the CAA records published at a
   domain will change between the time a certificate was issued and
   validation by a relying party.

4.  Certification Authority Processing

   Before issuing a certificate, a compliant CA MUST check for
   publication of a relevant CAA Resource Record set.  If such a record
   set exists, a CA MUST NOT issue a certificate unless the CA
   determines that either (1) the certificate request is consistent with
   the applicable CAA Resource Record set or (2) an exception specified
   in the relevant Certificate Policy or Certification Practices
   Statement applies.

   A certificate request MAY specify more than one domain name and MAY
   specify wildcard domains.  Issuers MUST verify authorization for all
   the domains and wildcard domains specified in the request.

   The search for a CAA record climbs the DNS name tree from the
   specified label up to but not including the DNS root '.'.

   Given a request for a specific domain X, or a request for a wildcard
   domain *.X, the relevant record set R(X) is determined as follows:

   Let CAA(X) be the record set returned in response to performing a CAA
   record query on the label X, P(X) be the DNS label immediately above
   X in the DNS hierarchy, and A(X) be the target of a CNAME or DNAME
   alias record specified at the label X.

   o  If CAA(X) is not empty, R(X) = CAA (X), otherwise

   o  If A(X) is not null, and R(A(X)) is not empty, then R(X) =
      R(A(X)), otherwise

   o  If X is not a top-level domain, then R(X) = R(P(X)), otherwise

   o  R(X) is empty.

   For example, if a certificate is requested for X.Y.Z the issuer will
   search for the relevant CAA record set in the following order:

      X.Y.Z

      Alias (X.Y.Z)

      Y.Z



Hallam-Baker & Stradling     Standards Track                    [Page 7]

RFC 6844          Certification Authority Authorization     January 2013


      Alias (Y.Z)

      Z

      Alias (Z)

      Return Empty

4.1.  Use of DNS Security

   Use of DNSSEC to authenticate CAA RRs is strongly RECOMMENDED but not
   required.  An issuer MUST NOT issue certificates if doing so would
   conflict with the relevant CAA Resource Record set, irrespective of
   whether the corresponding DNS records are signed.

   DNSSEC provides a proof of non-existence for both DNS domains and RR
   set within domains.  DNSSEC verification thus enables an issuer to
   determine if the answer to a CAA record query is empty because the RR
   set is empty or if it is non-empty but the response has been
   suppressed.

   Use of DNSSEC allows an issuer to acquire and archive a proof that
   they were authorized to issue certificates for the domain.
   Verification of such archives MAY be an audit requirement to verify
   CAA record processing compliance.  Publication of such archives MAY
   be a transparency requirement to verify CAA record processing
   compliance.

5.  Mechanism

5.1.  Syntax

   A CAA RR contains a single property entry consisting of a tag-value
   pair.  Each tag represents a property of the CAA record.  The value
   of a CAA property is that specified in the corresponding value field.

   A domain name MAY have multiple CAA RRs associated with it and a
   given property MAY be specified more than once.

   The CAA data field contains one property entry.  A property entry
   consists of the following data fields:










Hallam-Baker & Stradling     Standards Track                    [Page 8]

RFC 6844          Certification Authority Authorization     January 2013


   +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
   | Flags          | Tag Length = n |
   +----------------+----------------+...+---------------+
   | Tag char 0     | Tag char 1     |...| Tag char n-1  |
   +----------------+----------------+...+---------------+
   +----------------+----------------+.....+----------------+
   | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
   +----------------+----------------+.....+----------------+

   Where n is the length specified in the Tag length field and m is the
   remaining octets in the Value field (m = d - n - 2) where d is the
   length of the RDATA section.

   The data fields are defined as follows:

   Flags:  One octet containing the following fields:

      Bit 0, Issuer Critical Flag:  If the value is set to '1', the
         critical flag is asserted and the property MUST be understood
         if the CAA record is to be correctly processed by a certificate
         issuer.

         A Certification Authority MUST NOT issue certificates for any
         Domain that contains a CAA critical property for an unknown or
         unsupported property tag that for which the issuer critical
         flag is set.

      Note that according to the conventions set out in [RFC1035], bit 0
      is the Most Significant Bit and bit 7 is the Least Significant
      Bit. Thus, the Flags value 1 means that bit 7 is set while a value
      of 128 means that bit 0 is set according to this convention.

      All other bit positions are reserved for future use.

      To ensure compatibility with future extensions to CAA, DNS records
      compliant with this version of the CAA specification MUST clear
      (set to "0") all reserved flags bits.  Applications that interpret
      CAA records MUST ignore the value of all reserved flag bits.

   Tag Length:  A single octet containing an unsigned integer specifying
      the tag length in octets.  The tag length MUST be at least 1 and
      SHOULD be no more than 15.









Hallam-Baker & Stradling     Standards Track                    [Page 9]

RFC 6844          Certification Authority Authorization     January 2013


   Tag:  The property identifier, a sequence of US-ASCII characters.

      Tag values MAY contain US-ASCII characters 'a' through 'z', 'A'
      through 'Z', and the numbers 0 through 9.  Tag values SHOULD NOT
      contain any other characters.  Matching of tag values is case
      insensitive.

      Tag values submitted for registration by IANA MUST NOT contain any
      characters other than the (lowercase) US-ASCII characters 'a'
      through 'z' and the numbers 0 through 9.

   Value:  A sequence of octets representing the property value.
      Property values are encoded as binary values and MAY employ sub-
      formats.

      The length of the value field is specified implicitly as the
      remaining length of the enclosing Resource Record data field.

5.1.1.  Canonical Presentation Format

   The canonical presentation format of the CAA record is:

   CAA <flags> <tag> <value>

   Where:

   Flags:  Is an unsigned integer between 0 and 255.

   Tag:  Is a non-zero sequence of US-ASCII letters and numbers in lower
      case.

   Value:  Is the <character-string> encoding of the value field as
      specified in [RFC1035], Section 5.1.

5.2.  CAA issue Property

   The issue property tag is used to request that certificate issuers
   perform CAA issue restriction processing for the domain and to grant
   authorization to specific certificate issuers.

   The CAA issue property value has the following sub-syntax (specified
   in ABNF as per [RFC5234]).









Hallam-Baker & Stradling     Standards Track                   [Page 10]

RFC 6844          Certification Authority Authorization     January 2013


   issuevalue  = space [domain] space [";" *(space parameter) space]

   domain = label *("." label)
   label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))

   space = *(SP / HTAB)

   parameter =  tag "=" value

   tag = 1*(ALPHA / DIGIT)

   value = *VCHAR

   For consistency with other aspects of DNS administration, domain name
   values are specified in letter-digit-hyphen Label (LDH-Label) form.

   A CAA record with an issue parameter tag that does not specify a
   domain name is a request that certificate issuers perform CAA issue
   restriction processing for the corresponding domain without granting
   authorization to any certificate issuer.

   This form of issue restriction would be appropriate to specify that
   no certificates are to be issued for the domain in question.

   For example, the following CAA record set requests that no
   certificates be issued for the domain 'nocerts.example.com' by any
   certificate issuer.

   nocerts.example.com       CAA 0 issue ";"

   A CAA record with an issue parameter tag that specifies a domain name
   is a request that certificate issuers perform CAA issue restriction
   processing for the corresponding domain and grants authorization to
   the certificate issuer specified by the domain name.

   For example, the following CAA record set requests that no
   certificates be issued for the domain 'certs.example.com' by any
   certificate issuer other than the example.net certificate issuer.

   certs.example.com       CAA 0 issue "example.net"

   CAA authorizations are additive; thus, the result of specifying both
   the empty issuer and a specified issuer is the same as specifying
   just the specified issuer alone.







Hallam-Baker & Stradling     Standards Track                   [Page 11]

RFC 6844          Certification Authority Authorization     January 2013


   An issuer MAY choose to specify issuer-parameters that further
   constrain the issue of certificates by that issuer, for example,
   specifying that certificates are to be subject to specific validation
   polices, billed to certain accounts, or issued under specific trust
   anchors.

   The semantics of issuer-parameters are determined by the issuer
   alone.

5.3.  CAA issuewild Property

   The issuewild property has the same syntax and semantics as the issue
   property except that issuewild properties only grant authorization to
   issue certificates that specify a wildcard domain and issuewild
   properties take precedence over issue properties when specified.
   Specifically:

      issuewild properties MUST be ignored when processing a request for
      a domain that is not a wildcard domain.

      If at least one issuewild property is specified in the relevant
      CAA record set, all issue properties MUST be ignored when
      processing a request for a domain that is a wildcard domain.

5.4.  CAA iodef Property

   The iodef property specifies a means of reporting certificate issue
   requests or cases of certificate issue for the corresponding domain
   that violate the security policy of the issuer or the domain name
   holder.

   The Incident Object Description Exchange Format (IODEF) [RFC5070] is
   used to present the incident report in machine-readable form.

   The iodef property takes a URL as its parameter.  The URL scheme type
   determines the method used for reporting:

   mailto:  The IODEF incident report is reported as a MIME email
      attachment to an SMTP email that is submitted to the mail address
      specified.  The mail message sent SHOULD contain a brief text
      message to alert the recipient to the nature of the attachment.

   http or https:  The IODEF report is submitted as a Web service
      request to the HTTP address specified using the protocol specified
      in [RFC6546].






Hallam-Baker & Stradling     Standards Track                   [Page 12]

RFC 6844          Certification Authority Authorization     January 2013


6.  Security Considerations

   CAA records assert a security policy that the holder of a domain name
   wishes to be observed by certificate issuers.  The effectiveness of
   CAA records as an access control mechanism is thus dependent on
   observance of CAA constraints by issuers.

   The objective of the CAA record properties described in this document
   is to reduce the risk of certificate mis-issue rather than avoid
   reliance on a certificate that has been mis-issued.  DANE [RFC6698]
   describes a mechanism for avoiding reliance on mis-issued
   certificates.

6.1.  Non-Compliance by Certification Authority

   CAA records offer CAs a cost-effective means of mitigating the risk
   of certificate mis-issue: the cost of implementing CAA checks is very
   small and the potential costs of a mis-issue event include the
   removal of an embedded trust anchor.

6.2.  Mis-Issue by Authorized Certification Authority

   Use of CAA records does not prevent mis-issue by an authorized
   Certification Authority, i.e., a CA that is authorized to issue
   certificates for the domain in question by CAA records.

   Domain name holders SHOULD verify that the CAs they authorize to
   issue certificates for their domains employ appropriate controls to
   ensure that certificates are issued only to authorized parties within
   their organization.

   Such controls are most appropriately determined by the domain name
   holder and the authorized CA(s) directly and are thus out of scope of
   this document.

6.3.  Suppression or Spoofing of CAA Records

   Suppression of the CAA record or insertion of a bogus CAA record
   could enable an attacker to obtain a certificate from an issuer that
   was not authorized to issue for that domain name.

   Where possible, issuers SHOULD perform DNSSEC validation to detect
   missing or modified CAA record sets.

   In cases where DNSSEC is not deployed in a corresponding domain, an
   issuer SHOULD attempt to mitigate this risk by employing appropriate
   DNS security controls.  For example, all portions of the DNS lookup




Hallam-Baker & Stradling     Standards Track                   [Page 13]

RFC 6844          Certification Authority Authorization     January 2013


   process SHOULD be performed against the authoritative name server.
   Data cached by third parties MUST NOT be relied on but MAY be used to
   support additional anti-spoofing or anti-suppression controls.

6.4.  Denial of Service

   Introduction of a malformed or malicious CAA RR could in theory
   enable a Denial-of-Service (DoS) attack.

   This specific threat is not considered to add significantly to the
   risk of running an insecure DNS service.

   An attacker could, in principle, perform a DoS attack against an
   issuer by requesting a certificate with a maliciously long DNS name.
   In practice, the DNS protocol imposes a maximum name length and CAA
   processing does not exacerbate the existing need to mitigate DoS
   attacks to any meaningful degree.

6.5.  Abuse of the Critical Flag

   A Certification Authority could make use of the critical flag to
   trick customers into publishing records that prevent competing
   Certification Authorities from issuing certificates even though the
   customer intends to authorize multiple providers.

   In practice, such an attack would be of minimal effect since any
   competent competitor that found itself unable to issue certificates
   due to lack of support for a property marked critical SHOULD
   investigate the cause and report the reason to the customer.  The
   customer will thus discover that they had been deceived.

7.  IANA Considerations

7.1.  Registration of the CAA Resource Record Type

   IANA has assigned Resource Record Type 257 for the CAA Resource
   Record Type and added the line depicted below to the registry named
   "Resource Record (RR) TYPEs" and QTYPEs as defined in BCP 42
   [RFC6195] and located at
   http://www.iana.org/assignments/dns-parameters.

 RR Name      Value and meaning                                Reference
 -----------  ---------------------------------------------    ---------
 CAA          257 Certification Authority Restriction          [RFC6844]







Hallam-Baker & Stradling     Standards Track                   [Page 14]

RFC 6844          Certification Authority Authorization     January 2013


7.2.  Certification Authority Restriction Properties

   IANA has created the "Certification Authority Restriction Properties"
   registry with the following initial values:


   Tag          Meaning                                Reference
   -----------  -------------------------------------- ---------
   issue        Authorization Entry by Domain          [RFC6844]
   issuewild    Authorization Entry by Wildcard Domain [RFC6844]
   iodef        Report incident by IODEF report        [RFC6844]
   auth         Reserved                               [HB2011]
   path         Reserved                               [HB2011]
   policy       Reserved                               [HB2011]


   Although [HB2011] has expired, deployed clients implement the CAA
   properties specified in the document and reuse of these property tags
   for a different purpose could cause unexpected behavior.

   Addition of tag identifiers requires a public specification and
   Expert Review as set out in [RFC6195], Section 3.1.1.

   The tag space is designed to be sufficiently large that exhausting
   the possible tag space need not be a concern.  The scope of Expert
   Review SHOULD be limited to the question of whether the specification
   provided is sufficiently clear to permit implementation and to avoid
   unnecessary duplication of functionality.

7.3.  Certification Authority Restriction Flags

   IANA has created the "Certification Authority Restriction Flags"
   registry with the following initial values:


             Flag         Meaning                            Reference
   -----------  ---------------------------------- ---------
   0            Issuer Critical Flag               [RFC6844]
   1-7          Reserved>                          [RFC6844]

   Assignment of new flags follows the RFC Required policy set out in
   [RFC5226], Section 4.1.









Hallam-Baker & Stradling     Standards Track                   [Page 15]

RFC 6844          Certification Authority Authorization     January 2013


8.  Acknowledgements

   The authors would like to thank the following people who contributed
   to the design and documentation of this work item: Chris Evans,
   Stephen Farrell, Jeff Hodges, Paul Hoffman, Stephen Kent, Adam
   Langley, Ben Laurie, James Manager, Chris Palmer, Scott Schmit, Sean
   Turner, and Ben Wilson.

9.  References

9.1.  Normative References

   [RFC1035]  Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, November 1987.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119, March 1997.

   [RFC2181]  Elz, R. and R. Bush, "Clarifications to the DNS
              Specification", RFC 2181, July 1997.

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, March 2005.

   [RFC4034]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Resource Records for the DNS Security Extensions",
              RFC 4034, March 2005.

   [RFC4035]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Protocol Modifications for the DNS Security
              Extensions", RFC 4035, March 2005.

   [RFC5070]  Danyliw, R., Meijer, J., and Y. Demchenko, "The Incident
              Object Description Exchange Format", RFC 5070,
              December 2007.

   [RFC5155]  Laurie, B., Sisson, G., Arends, R., and D. Blacka, "DNS
              Security (DNSSEC) Hashed Authenticated Denial of
              Existence", RFC 5155, March 2008.

   [RFC5226]  Narten, T. and H. Alvestrand, "Guidelines for Writing an
              IANA Considerations Section in RFCs", BCP 26, RFC 5226,
              May 2008.

   [RFC5234]  Crocker, D. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234, January 2008.




Hallam-Baker & Stradling     Standards Track                   [Page 16]

RFC 6844          Certification Authority Authorization     January 2013


   [RFC5280]  Cooper, D., Santesson, S., Farrell, S., Boeyen, S.,
              Housley, R., and W. Polk, "Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 5280, May 2008.

   [RFC6195]  Eastlake, D., "Domain Name System (DNS) IANA
              Considerations", BCP 42, RFC 6195, March 2011.

   [RFC6546]  Trammell, B., "Transport of Real-time Inter-network
              Defense (RID) Messages over HTTP/TLS", RFC 6546,
              April 2012.

   [RFC6698]  Hoffman, P. and J. Schlyter, "The DNS-Based Authentication
              of Named Entities (DANE) Transport Layer Security (TLS)
              Protocol: TLSA", RFC 6698, August 2012.

   [STD13]    Mockapetris, P., "Domain names - concepts and facilities",
              STD 13, RFC 1034, November 1987.

              Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, November 1987.

   [X.509]    International Telecommunication Union, "ITU-T
              Recommendation X.509 (11/2008): Information technology -
              Open systems interconnection - The Directory: Public-key
              and attribute certificate frameworks", ITU-T
              Recommendation X.509, November 2008.

9.2.  Informative References

   [HB2011]   Hallam-Baker, P., Stradling, R., and B. Laurie, "DNS
              Certification Authority Authorization (CAA) Resource
              Record", Work in Progress, May 2011.

   [RFC3647]  Chokhani, S., Ford, W., Sabett, R., Merrill, C., and S.
              Wu, "Internet X.509 Public Key Infrastructure Certificate
              Policy and Certification Practices Framework", RFC 3647,
              November 2003.













Hallam-Baker & Stradling     Standards Track                   [Page 17]

RFC 6844          Certification Authority Authorization     January 2013


Authors' Addresses

   Phillip Hallam-Baker
   Comodo Group, Inc.

   EMail: philliph@comodo.com


   Rob Stradling
   Comodo CA, Ltd.

   EMail: rob.stradling@comodo.com







































Hallam-Baker & Stradling     Standards Track                   [Page 18]


```

---

# RFC 8659 — CAA — Certification Authority Authorization (révision)

```
﻿



Internet Engineering Task Force (IETF)                   P. Hallam-Baker
Request for Comments: 8659                          Venture Cryptography
Obsoletes: 6844                                             R. Stradling
Category: Standards Track                                        Sectigo
ISSN: 2070-1721                                       J. Hoffman-Andrews
                                                           Let's Encrypt
                                                           November 2019


    DNS Certification Authority Authorization (CAA) Resource Record

Abstract

   The Certification Authority Authorization (CAA) DNS Resource Record
   allows a DNS domain name holder to specify one or more Certification
   Authorities (CAs) authorized to issue certificates for that domain
   name.  CAA Resource Records allow a public CA to implement additional
   controls to reduce the risk of unintended certificate mis-issue.
   This document defines the syntax of the CAA record and rules for
   processing CAA records by CAs.

   This document obsoletes RFC 6844.

Status of This Memo

   This is an Internet Standards Track document.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Further information on
   Internet Standards is available in Section 2 of RFC 7841.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   https://www.rfc-editor.org/info/rfc8659.

Copyright Notice

   Copyright (c) 2019 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.

Table of Contents

   1.  Introduction
   2.  Definitions
     2.1.  Requirements Language
     2.2.  Defined Terms
   3.  Relevant Resource Record Set
   4.  Mechanism
     4.1.  Syntax
       4.1.1.  Canonical Presentation Format
     4.2.  CAA issue Property
     4.3.  CAA issuewild Property
     4.4.  CAA iodef Property
     4.5.  Critical Flag
   5.  Security Considerations
     5.1.  Use of DNS Security
     5.2.  Non-compliance by Certification Authority
     5.3.  Mis-Issue by Authorized Certification Authority
     5.4.  Suppression or Spoofing of CAA Records
     5.5.  Denial of Service
     5.6.  Abuse of the Critical Flag
   6.  Deployment Considerations
     6.1.  Blocked Queries or Responses
     6.2.  Rejected Queries and Malformed Responses
     6.3.  Delegation to Private Nameservers
     6.4.  Bogus DNSSEC Responses
   7.  Differences from RFC 6844
   8.  IANA Considerations
   9.  References
     9.1.  Normative References
     9.2.  Informative References
   Acknowledgements
   Authors' Addresses

1.  Introduction

   The Certification Authority Authorization (CAA) DNS Resource Record
   allows a DNS domain name holder to specify the Certification
   Authorities (CAs) authorized to issue certificates for that domain
   name.  Publication of CAA Resource Records allows a public CA to
   implement additional controls to reduce the risk of unintended
   certificate mis-issue.

   Like the TLSA record defined in DNS-Based Authentication of Named
   Entities (DANE) [RFC6698], CAA records are used as a part of a
   mechanism for checking PKIX [RFC6698] certificate data.  The
   distinction between CAA and TLSA is that CAA records specify an
   authorization control to be performed by a CA before issuing a
   certificate and TLSA records specify a verification control to be
   performed by a Relying Party after the certificate is issued.

   Conformance with a published CAA record is a necessary, but not
   sufficient, condition for the issuance of a certificate.

   Criteria for the inclusion of embedded trust anchor certificates in
   applications are outside the scope of this document.  Typically, such
   criteria require the CA to publish a Certification Practices
   Statement (CPS) that specifies how the requirements of the
   Certificate Policy (CP) are achieved.  It is also common for a CA to
   engage an independent third-party auditor to prepare an annual audit
   statement of its performance against its CPS.

   A set of CAA records describes only current grants of authority to
   issue certificates for the corresponding DNS domain name.  Since
   certificates are valid for a period of time, it is possible that a
   certificate that is not conformant with the CAA records currently
   published was conformant with the CAA records published at the time
   that the certificate was issued.  Relying Parties MUST NOT use CAA
   records as part of certificate validation.

   CAA records MAY be used by Certificate Evaluators as a possible
   indicator of a security policy violation.  Such use SHOULD take into
   account the possibility that published CAA records changed between
   the time a certificate was issued and the time at which the
   certificate was observed by the Certificate Evaluator.

2.  Definitions

2.1.  Requirements Language

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in
   BCP 14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

2.2.  Defined Terms

   The following terms are used in this document:

   Certificate:  An X.509 Certificate, as specified in [RFC5280].

   Certificate Evaluator:  A party other than a Relying Party that
      evaluates the trustworthiness of certificates issued by
      Certification Authorities.

   Certification Authority (CA):  An Issuer that issues certificates in
      accordance with a specified Certificate Policy.

   Certificate Policy (CP):  Specifies the criteria that a CA undertakes
      to meet in its issue of certificates.  See [RFC3647].

   Certification Practices Statement (CPS):  Specifies the means by
      which the criteria of the CP are met.  In most cases, this will be
      the document against which the operations of the CA are audited.
      See [RFC3647].

   Domain Name:  The label assigned to a node in the Domain Name System.

   Domain Name System (DNS):  The Internet naming system specified in
      [RFC1034] and [RFC1035].

   DNS Security (DNSSEC):  Extensions to the DNS that provide
      authentication services as specified in [RFC4033], [RFC4034],
      [RFC4035], [RFC5155], and any revisions to these specifications.

   Fully Qualified Domain Name (FQDN):  A domain name that includes the
      labels of all superior nodes in the DNS.

   Issuer:  An entity that issues certificates.  See [RFC5280].

   Property:  The tag-value portion of a CAA Resource Record.

   Property Tag:  The tag portion of a CAA Resource Record.

   Property Value:  The value portion of a CAA Resource Record.

   Relevant Resource Record Set (Relevant RRset):  A set of CAA Resource
      Records resulting from applying the algorithm in Section 3 to a
      specific FQDN or Wildcard Domain Name.

   Relying Party:  A party that makes use of an application whose
      operation depends on the use of a certificate for making a
      security decision.  See [RFC5280].

   Resource Record (RR):  A particular entry in the DNS, including the
      owner name, class, type, time to live, and data, as defined in
      [RFC1034] and [RFC2181].

   Resource Record Set (RRset):  A set of RRs of a particular owner
      name, class, and type.  The time to live on all RRs within an
      RRset is always the same, but the data may be different among RRs
      in the RRset.

   Wildcard Domain Name:  A domain name consisting of a single asterisk
      character followed by a single "full stop" character ("*.")
      followed by an FQDN.

3.  Relevant Resource Record Set

   Before issuing a certificate, a compliant CA MUST check for
   publication of a Relevant RRset.  If such an RRset exists, a CA
   MUST NOT issue a certificate unless the CA determines that either
   (1) the certificate request is consistent with the applicable CAA
   RRset or (2) an exception specified in the relevant CP or CPS
   applies.  If the Relevant RRset for an FQDN or Wildcard Domain Name
   contains no Property Tags that restrict issuance (for instance, if it
   contains only iodef Property Tags or only Property Tags unrecognized
   by the CA), CAA does not restrict issuance.

   A certificate request MAY specify more than one FQDN and MAY specify
   Wildcard Domain Names.  Issuers MUST verify authorization for all the
   FQDNs and Wildcard Domain Names specified in the request.

   The search for a CAA RRset climbs the DNS name tree from the
   specified label up to, but not including, the DNS root "." until a
   CAA RRset is found.

   Given a request for a specific FQDN X or a request for a Wildcard
   Domain Name *.X, the Relevant RRset RelevantCAASet(X) is determined
   as follows (in pseudocode):

      Let CAA(X) be the RRset returned by performing a CAA record query
      for the FQDN X, according to the lookup algorithm specified in
      Section 4.3.2 of [RFC1034] (in particular, chasing aliases).  Let
      Parent(X) be the FQDN produced by removing the leftmost label of
      X.

      RelevantCAASet(domain):
        while domain is not ".":
          if CAA(domain) is not Empty:
            return CAA(domain)
          domain = Parent(domain)
        return Empty

      For example, processing CAA for the FQDN "X.Y.Z" where there are
      no CAA records at any level in the tree RelevantCAASet would have
      the following steps:

      CAA("X.Y.Z.") = Empty; domain = Parent("X.Y.Z.") = "Y.Z."
      CAA("Y.Z.")   = Empty; domain = Parent("Y.Z.")   = "Z."
      CAA("Z.")     = Empty; domain = Parent("Z.")     = "."
      return Empty

      Processing CAA for the FQDN "A.B.C" where there is a CAA record
      "issue example.com" at "B.C" would terminate early upon finding
      the CAA record:

      CAA("A.B.C.") = Empty; domain = Parent("A.B.C.") = "B.C."
      CAA("B.C.")   = "issue example.com"
      return "issue example.com"

4.  Mechanism

4.1.  Syntax

   A CAA RR contains a single Property consisting of a tag-value pair.
   An FQDN MAY have multiple CAA RRs associated with it, and a given
   Property Tag MAY be specified more than once across those RRs.

   The RDATA section for a CAA RR contains one Property.  A Property
   consists of the following:

   +0-1-2-3-4-5-6-7-|0-1-2-3-4-5-6-7-|
   | Flags          | Tag Length = n |
   +----------------|----------------+...+---------------+
   | Tag char 0     | Tag char 1     |...| Tag char n-1  |
   +----------------|----------------+...+---------------+
   +----------------|----------------+.....+----------------+
   | Value byte 0   | Value byte 1   |.....| Value byte m-1 |
   +----------------|----------------+.....+----------------+

   Where n is the length specified in the Tag Length field and m is the
   number of remaining octets in the Value field.  They are related by
   (m = d - n - 2) where d is the length of the RDATA section.

   The fields are defined as follows:

   Flags:  One octet containing the following field:

      Bit 0, Issuer Critical Flag:  If the value is set to "1", the
         Property is critical.  A CA MUST NOT issue certificates for any
         FQDN if the Relevant RRset for that FQDN contains a CAA
         critical Property for an unknown or unsupported Property Tag.

   Note that according to the conventions set out in [RFC1035], bit 0 is
   the Most Significant Bit and bit 7 is the Least Significant Bit.
   Thus, according to those conventions, the Flags value 1 means that
   bit 7 is set, while a value of 128 means that bit 0 is set.

   All other bit positions are reserved for future use.

   To ensure compatibility with future extensions to CAA, DNS records
   compliant with this version of the CAA specification MUST clear (set
   to "0") all reserved flag bits.  Applications that interpret CAA
   records MUST ignore the value of all reserved flag bits.

   Tag Length:  A single octet containing an unsigned integer specifying
      the tag length in octets.  The tag length MUST be at least 1.

   Tag:  The Property identifier -- a sequence of ASCII characters.

   Tags MAY contain ASCII characters "a" through "z", "A" through "Z",
   and the numbers 0 through 9.  Tags MUST NOT contain any other
   characters.  Matching of tags is case insensitive.

   Tags submitted for registration by IANA MUST NOT contain any
   characters other than the (lowercase) ASCII characters "a" through
   "z" and the numbers 0 through 9.

   Value:  A sequence of octets representing the Property Value.
      Property Values are encoded as binary values and MAY employ
      sub-formats.

   The length of the Value field is specified implicitly as the
   remaining length of the enclosing RDATA section.

4.1.1.  Canonical Presentation Format

   The canonical presentation format of the CAA record is:

      CAA <flags> <tag> <value>

   Where:

   Flags:  An unsigned integer between 0 and 255.

   Tag:  A non-zero-length sequence of ASCII letters and numbers in
      lowercase.

   Value:  The Value field, expressed as either (1) a contiguous set of
      characters without interior spaces or (2) a quoted string.  See
      the <character-string> format specified in [RFC1035], Section 5.1,
      but note that the Value field contains no length byte and is not
      limited to 255 characters.

4.2.  CAA issue Property

   If the issue Property Tag is present in the Relevant RRset for an
   FQDN, it is a request that Issuers:

   1.  Perform CAA issue restriction processing for the FQDN, and

   2.  Grant authorization to issue certificates containing that FQDN to
       the holder of the issuer-domain-name or a party acting under the
       explicit authority of the holder of the issuer-domain-name.

   The CAA issue Property Value has the following sub-syntax (specified
   in ABNF as per [RFC5234]).

   issue-value = *WSP [issuer-domain-name *WSP]
      [";" *WSP [parameters *WSP]]

   issuer-domain-name = label *("." label)
   label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))

   parameters = (parameter *WSP ";" *WSP parameters) / parameter
   parameter = tag *WSP "=" *WSP value
   tag = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
   value = *(%x21-3A / %x3C-7E)

   For consistency with other aspects of DNS administration, FQDN values
   are specified in letter-digit-hyphen Label (LDH-Label) form.

   The following CAA RRset requests that no certificates be issued for
   the FQDN "certs.example.com" by any Issuer other than ca1.example.net
   or ca2.example.org.

   certs.example.com         CAA 0 issue "ca1.example.net"
   certs.example.com         CAA 0 issue "ca2.example.org"

   Because the presence of an issue Property Tag in the Relevant RRset
   for an FQDN restricts issuance, FQDN owners can use an issue Property
   Tag with no issuer-domain-name to request no issuance.

   For example, the following RRset requests that no certificates be
   issued for the FQDN "nocerts.example.com" by any Issuer.

   nocerts.example.com       CAA 0 issue ";"

   An issue Property Tag where the issue-value does not match the ABNF
   grammar MUST be treated the same as one specifying an empty
   issuer-domain-name.  For example, the following malformed CAA RRset
   forbids issuance:

   malformed.example.com     CAA 0 issue "%%%%%"

   CAA authorizations are additive; thus, the result of specifying both
   an empty issuer-domain-name and a non-empty issuer-domain-name is the
   same as specifying just the non-empty issuer-domain-name.

   An Issuer MAY choose to specify parameters that further constrain the
   issue of certificates by that Issuer -- for example, specifying that
   certificates are to be subject to specific validation policies,
   billed to certain accounts, or issued under specific trust anchors.

   For example, if ca1.example.net has requested that its customer
   account.example.com specify their account number "230123" in each of
   the customer's CAA records using the (CA-defined) "account"
   parameter, it would look like this:

   account.example.com   CAA 0 issue "ca1.example.net; account=230123"

   The semantics of parameters to the issue Property Tag are determined
   by the Issuer alone.

4.3.  CAA issuewild Property

   The issuewild Property Tag has the same syntax and semantics as the
   issue Property Tag except that it only grants authorization to issue
   certificates that specify a Wildcard Domain Name and each issuewild
   Property takes precedence over each issue Property when specified.
   Specifically:

   Each issuewild Property MUST be ignored when processing a request for
   an FQDN that is not a Wildcard Domain Name.

   If at least one issuewild Property is specified in the Relevant RRset
   for a Wildcard Domain Name, each issue Property MUST be ignored when
   processing a request for that Wildcard Domain Name.

   For example, the following RRset requests that _only_ ca1.example.net
   issue certificates for "wild.example.com" or "sub.wild.example.com",
   and that _only_ ca2.example.org issue certificates for
   "*.wild.example.com" or "*.sub.wild.example.com".  Note that this
   presumes that there are no CAA RRs for sub.wild.example.com.

   wild.example.com          CAA 0 issue "ca1.example.net"
   wild.example.com          CAA 0 issuewild "ca2.example.org"

   The following RRset requests that _only_ ca1.example.net issue
   certificates for "wild2.example.com", "*.wild2.example.com", or
   "*.sub.wild2.example.com".

   wild2.example.com         CAA 0 issue "ca1.example.net"

   The following RRset requests that _only_ ca2.example.org issue
   certificates for "*.wild3.example.com" or "*.sub.wild3.example.com".
   It does not permit any Issuer to issue for "wild3.example.com" or
   "sub.wild3.example.com".

   wild3.example.com         CAA 0 issuewild "ca2.example.org"
   wild3.example.com         CAA 0 issue ";"

   The following RRset requests that _only_ ca2.example.org issue
   certificates for "*.wild3.example.com" or "*.sub.wild3.example.com".
   It permits any Issuer to issue for "wild3.example.com" or
   "sub.wild3.example.com".

   wild3.example.com         CAA 0 issuewild "ca2.example.org"

4.4.  CAA iodef Property

   The iodef Property specifies a means of reporting certificate issue
   requests or cases of certificate issue for domains for which the
   Property appears in the Relevant RRset, when those requests or
   issuances violate the security policy of the Issuer or the FQDN
   holder.

   The Incident Object Description Exchange Format (IODEF) [RFC7970] is
   used to present the incident report in machine-readable form.

   The iodef Property Tag takes a URL as its Property Value.  The URL
   scheme type determines the method used for reporting:

   mailto:  The IODEF report is reported as a MIME email attachment to
      an SMTP email that is submitted to the mail address specified.
      The mail message sent SHOULD contain a brief text message to alert
      the recipient to the nature of the attachment.

   http or https:  The IODEF report is submitted as a web service
      request to the HTTP address specified using the protocol specified
      in [RFC6546].

   These are the only supported URL schemes.

   The following RRset specifies that reports may be made by means of
   email with the IODEF data as an attachment, a web service [RFC6546],
   or both:

   report.example.com         CAA 0 issue "ca1.example.net"
   report.example.com         CAA 0 iodef "mailto:security@example.com"
   report.example.com         CAA 0 iodef "https://iodef.example.com/"

4.5.  Critical Flag

   The critical flag is intended to permit future versions of CAA to
   introduce new semantics that MUST be understood for correct
   processing of the record, preventing conforming CAs that do not
   recognize the new semantics from issuing certificates for the
   indicated FQDNs.

   In the following example, the Property with a Property Tag of "tbs"
   is flagged as critical.  Neither the ca1.example.net CA nor any other
   Issuer is authorized to issue for "new.example.com" (or any other
   domains for which this is the Relevant RRset) unless the Issuer has
   implemented the processing rules for the "tbs" Property Tag.

   new.example.com       CAA 0 issue "ca1.example.net"
   new.example.com       CAA 128 tbs "Unknown"

5.  Security Considerations

   CAA records assert a security policy that the holder of an FQDN
   wishes to be observed by Issuers.  The effectiveness of CAA records
   as an access control mechanism is thus dependent on observance of CAA
   constraints by Issuers.

   The objective of the CAA record properties described in this document
   is to reduce the risk of certificate mis-issue rather than avoid
   reliance on a certificate that has been mis-issued.  DANE [RFC6698]
   describes a mechanism for avoiding reliance on mis-issued
   certificates.

5.1.  Use of DNS Security

   The use of DNSSEC to authenticate CAA RRs is strongly RECOMMENDED but
   not required.  An Issuer MUST NOT issue certificates if doing so
   would conflict with the Relevant RRset, irrespective of whether the
   corresponding DNS records are signed.

   DNSSEC provides a proof of non-existence for both DNS FQDNs and
   RRsets within FQDNs.  DNSSEC verification thus enables an Issuer to
   determine whether the answer to a CAA record query (1) is empty
   because the RRset is empty or (2) is non-empty but the response has
   been suppressed.

   The use of DNSSEC allows an Issuer to acquire and archive a proof
   that they were authorized to issue certificates for the FQDN.
   Verification of such archives may be an audit requirement to verify
   CAA record-processing compliance.  Publication of such archives may
   be a transparency requirement to verify CAA record-processing
   compliance.

5.2.  Non-compliance by Certification Authority

   CAA records offer CAs a cost-effective means of mitigating the risk
   of certificate mis-issue: the cost of implementing CAA checks is very
   small, and the potential costs of a mis-issue event include the
   removal of an embedded trust anchor.

5.3.  Mis-Issue by Authorized Certification Authority

   The use of CAA records does not prevent mis-issue by an authorized
   CA, i.e., a CA that is authorized to issue certificates for the FQDN
   in question by CAA records.

   FQDN holders SHOULD verify that the CAs they authorize to issue
   certificates for their FQDNs employ appropriate controls to ensure
   that certificates are issued only to authorized parties within their
   organization.

   Such controls are most appropriately determined by the FQDN holder
   and the authorized CA(s) directly and are thus outside the scope of
   this document.

5.4.  Suppression or Spoofing of CAA Records

   Suppression of a CAA record or insertion of a bogus CAA record could
   enable an attacker to obtain a certificate from an Issuer that was
   not authorized to issue for an affected FQDN.

   Where possible, Issuers SHOULD perform DNSSEC validation to detect
   missing or modified CAA RRsets.

   In cases where DNSSEC is not deployed for a corresponding FQDN, an
   Issuer SHOULD attempt to mitigate this risk by employing appropriate
   DNS security controls.  For example, all portions of the DNS lookup
   process SHOULD be performed against the authoritative nameserver.
   Data cached by third parties MUST NOT be relied on as the sole source
   of DNS CAA information but MAY be used to support additional
   anti-spoofing or anti-suppression controls.

5.5.  Denial of Service

   Introduction of a malformed or malicious CAA RR could, in theory,
   enable a Denial-of-Service (DoS) attack.  This could happen by
   modification of authoritative DNS records or by spoofing inflight DNS
   responses.

   This specific threat is not considered to add significantly to the
   risk of running an insecure DNS service.

   An attacker could, in principle, perform a DoS attack against an
   Issuer by requesting a certificate with a maliciously long DNS name.
   In practice, the DNS protocol imposes a maximum name length, and CAA
   processing does not exacerbate the existing need to mitigate DoS
   attacks to any meaningful degree.

5.6.  Abuse of the Critical Flag

   A CA could make use of the critical flag to trick customers into
   publishing records that prevent competing CAs from issuing
   certificates even though the customer intends to authorize multiple
   providers.  This could happen if the customers were setting CAA
   records based on data provided by the CA rather than generating those
   records themselves.

   In practice, such an attack would be of minimal effect, since any
   competent competitor that found itself unable to issue certificates
   due to lack of support for a Property marked critical should
   investigate the cause and report the reason to the customer.  The
   customer will thus discover that they had been deceived.

6.  Deployment Considerations

   A CA implementing CAA may find that they receive errors looking up
   CAA records.  The following are some common causes of such errors, so
   that CAs may provide guidance to their subscribers on fixing the
   underlying problems.

6.1.  Blocked Queries or Responses

   Some middleboxes -- in particular, anti-DDoS appliances -- may be
   configured to drop DNS packets of unknown types, or they may start
   dropping such packets when they consider themselves under attack.
   This generally manifests as a timed-out DNS query or as a SERVFAIL at
   a local recursive resolver.

6.2.  Rejected Queries and Malformed Responses

   Some authoritative nameservers respond with REJECTED or NOTIMP when
   queried for an RR type they do not recognize.  At least one
   authoritative resolver produces a malformed response (with the QR
   (Query/Response) bit set to "0") when queried for unknown RR types.
   Per [RFC1034], the correct response RCODE for unknown RR types is 0
   ("No error condition").

6.3.  Delegation to Private Nameservers

   Some FQDN administrators make the contents of a subdomain
   unresolvable on the public Internet by delegating that subdomain to a
   nameserver whose IP address is private.  A CA processing CAA records
   for such subdomains will receive SERVFAIL from its recursive
   resolver.  The CA MAY interpret that as preventing issuance.  FQDN
   administrators wishing to issue certificates for private FQDNs SHOULD
   use split-horizon DNS with a publicly available nameserver, so that
   CAs can receive a valid, empty CAA response for those FQDNs.

6.4.  Bogus DNSSEC Responses

   Queries for CAA RRs are different from most DNS RR types, because a
   signed, empty response to a query for CAA RRs is meaningfully
   different from a bogus response.  A signed, empty response indicates
   that there is definitely no CAA policy set at a given label.  A bogus
   response may mean either a misconfigured zone or an attacker
   tampering with records.  DNSSEC implementations may have bugs with
   signatures on empty responses that go unnoticed, because for more
   common RR types like A and AAAA, the difference to an end user
   between empty and bogus is irrelevant; they both mean a site is
   unavailable.

   In particular, at least two authoritative resolvers that implement
   live signing had bugs when returning empty RRsets for DNSSEC-signed
   zones, in combination with mixed-case queries.  Mixed-case queries,
   also known as DNS 0x20, are used by some recursive resolvers to
   increase resilience against DNS poisoning attacks.  DNSSEC-signing
   authoritative resolvers are expected to copy the same capitalization
   from the query into their ANSWER section but also to sign the
   response as if they had used all lowercase.  In particular, PowerDNS
   versions prior to 4.0.4 had this bug.

7.  Differences from RFC 6844

   This document obsoletes [RFC6844].  The most important change is to
   the "Certification Authority Processing" section (now called
   "Relevant Resource Record Set" (Section 3), as noted below).
   [RFC6844] specified an algorithm that performed DNS tree-climbing not
   only on the FQDN being processed but also on all CNAMEs and DNAMEs
   encountered along the way.  This made the processing algorithm very
   inefficient when used on FQDNs that utilize many CNAMEs and would
   have made it difficult for hosting providers to set CAA policies on
   their own FQDNs without setting potentially unwanted CAA policies on
   their customers' FQDNs.  This document specifies a simplified
   processing algorithm that only performs tree-climbing on the FQDN
   being processed, and it leaves the processing of CNAMEs and DNAMEs up
   to the CA's recursive resolver.

   This document also includes a "Deployment Considerations" section
   (Section 6) detailing experience gained with practical deployment of
   CAA enforcement among CAs in the WebPKI.

   This document clarifies the ABNF grammar for the issue and issuewild
   tags and resolves some inconsistencies with the document text.  In
   particular, it specifies that parameters are separated with
   semicolons.  It also allows hyphens in Property Tags.

   This document also clarifies the processing of a CAA RRset that is
   not empty but that does not contain any issue or issuewild tags.

   This document removes the section titled "The CAA RR Type," merging
   it with "Mechanism" (Section 4) because the definitions were mainly
   duplicates.  It moves the "Use of DNS Security" section into Security
   Considerations (Section 5).  It renames "Certification Authority
   Processing" to "Relevant Resource Record Set" (Section 3) and
   emphasizes the use of that term to more clearly define which domains
   are affected by a given RRset.

8.  IANA Considerations

   IANA has added this document as a reference for the "Certification
   Authority Restriction Flags" and "Certification Authority Restriction
   Properties" registries and updated references to [RFC6844] within
   those registries to refer instead to this document.  IANA has also
   updated the CAA TYPE in the "Resource Record (RR) TYPEs" subregistry
   of the "Domain Name System (DNS) Parameters" registry with a
   reference to this document.

9.  References

9.1.  Normative References

   [RFC1034]  Mockapetris, P., "Domain names - concepts and facilities",
              STD 13, RFC 1034, DOI 10.17487/RFC1034, November 1987,
              <https://www.rfc-editor.org/info/rfc1034>.

   [RFC1035]  Mockapetris, P., "Domain names - implementation and
              specification", STD 13, RFC 1035, DOI 10.17487/RFC1035,
              November 1987, <https://www.rfc-editor.org/info/rfc1035>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC2181]  Elz, R. and R. Bush, "Clarifications to the DNS
              Specification", RFC 2181, DOI 10.17487/RFC2181, July 1997,
              <https://www.rfc-editor.org/info/rfc2181>.

   [RFC4033]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "DNS Security Introduction and Requirements",
              RFC 4033, DOI 10.17487/RFC4033, March 2005,
              <https://www.rfc-editor.org/info/rfc4033>.

   [RFC4034]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Resource Records for the DNS Security Extensions",
              RFC 4034, DOI 10.17487/RFC4034, March 2005,
              <https://www.rfc-editor.org/info/rfc4034>.

   [RFC4035]  Arends, R., Austein, R., Larson, M., Massey, D., and S.
              Rose, "Protocol Modifications for the DNS Security
              Extensions", RFC 4035, DOI 10.17487/RFC4035, March 2005,
              <https://www.rfc-editor.org/info/rfc4035>.

   [RFC5155]  Laurie, B., Sisson, G., Arends, R., and D. Blacka, "DNS
              Security (DNSSEC) Hashed Authenticated Denial of
              Existence", RFC 5155, DOI 10.17487/RFC5155, March 2008,
              <https://www.rfc-editor.org/info/rfc5155>.

   [RFC5234]  Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234,
              DOI 10.17487/RFC5234, January 2008,
              <https://www.rfc-editor.org/info/rfc5234>.

   [RFC5280]  Cooper, D., Santesson, S., Farrell, S., Boeyen, S.,
              Housley, R., and W. Polk, "Internet X.509 Public Key
              Infrastructure Certificate and Certificate Revocation List
              (CRL) Profile", RFC 5280, DOI 10.17487/RFC5280, May 2008,
              <https://www.rfc-editor.org/info/rfc5280>.

   [RFC6546]  Trammell, B., "Transport of Real-time Inter-network
              Defense (RID) Messages over HTTP/TLS", RFC 6546,
              DOI 10.17487/RFC6546, April 2012,
              <https://www.rfc-editor.org/info/rfc6546>.

   [RFC6698]  Hoffman, P. and J. Schlyter, "The DNS-Based Authentication
              of Named Entities (DANE) Transport Layer Security (TLS)
              Protocol: TLSA", RFC 6698, DOI 10.17487/RFC6698, August
              2012, <https://www.rfc-editor.org/info/rfc6698>.

   [RFC6844]  Hallam-Baker, P. and R. Stradling, "DNS Certification
              Authority Authorization (CAA) Resource Record", RFC 6844,
              DOI 10.17487/RFC6844, January 2013,
              <https://www.rfc-editor.org/info/rfc6844>.

   [RFC7970]  Danyliw, R., "The Incident Object Description Exchange
              Format Version 2", RFC 7970, DOI 10.17487/RFC7970,
              November 2016, <https://www.rfc-editor.org/info/rfc7970>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.

9.2.  Informative References

   [RFC3647]  Chokhani, S., Ford, W., Sabett, R., Merrill, C., and S.
              Wu, "Internet X.509 Public Key Infrastructure Certificate
              Policy and Certification Practices Framework", RFC 3647,
              DOI 10.17487/RFC3647, November 2003,
              <https://www.rfc-editor.org/info/rfc3647>.

Acknowledgements

   The authors would like to thank the following people who contributed
   to the design and documentation of this work item: Corey Bonnell,
   Chris Evans, Stephen Farrell, Jeff Hodges, Paul Hoffman, Tim
   Hollebeek, Stephen Kent, Adam Langley, Ben Laurie, James Manger,
   Chris Palmer, Scott Schmit, Sean Turner, and Ben Wilson.

Authors' Addresses

   Phillip Hallam-Baker
   Venture Cryptography

   Email: phill@hallambaker.com


   Rob Stradling
   Sectigo Ltd.

   Email: rob@sectigo.com


   Jacob Hoffman-Andrews
   Let's Encrypt

   Email: jsha@letsencrypt.org

```

---

# RFC 9116 — security.txt — A File Format to Aid in Security Vulnerability Disclosure

```
﻿



Internet Engineering Task Force (IETF)                         E. Foudil
Request for Comments: 9116                                              
Category: Informational                                  Y. Shafranovich
ISSN: 2070-1721                                 Nightwatch Cybersecurity
                                                              April 2022


       A File Format to Aid in Security Vulnerability Disclosure

Abstract

   When security vulnerabilities are discovered by researchers, proper
   reporting channels are often lacking.  As a result, vulnerabilities
   may be left unreported.  This document defines a machine-parsable
   format ("security.txt") to help organizations describe their
   vulnerability disclosure practices to make it easier for researchers
   to report vulnerabilities.

Status of This Memo

   This document is not an Internet Standards Track specification; it is
   published for informational purposes.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It represents the consensus of the IETF community.  It has
   received public review and has been approved for publication by the
   Internet Engineering Steering Group (IESG).  Not all documents
   approved by the IESG are candidates for any level of Internet
   Standard; see Section 2 of RFC 7841.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   https://www.rfc-editor.org/info/rfc9116.

Copyright Notice

   Copyright (c) 2022 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (https://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Revised BSD License text as described in Section 4.e of the
   Trust Legal Provisions and are provided without warranty as described
   in the Revised BSD License.

Table of Contents

   1.  Introduction
     1.1.  Motivation, Prior Work, and Scope
     1.2.  Terminology
   2.  The Specification
     2.1.  Comments
     2.2.  Line Separator
     2.3.  Digital Signature
     2.4.  Extensibility
     2.5.  Field Definitions
       2.5.1.  Acknowledgments
       2.5.2.  Canonical
       2.5.3.  Contact
       2.5.4.  Encryption
       2.5.5.  Expires
       2.5.6.  Hiring
       2.5.7.  Policy
       2.5.8.  Preferred-Languages
     2.6.  Example of an Unsigned "security.txt" File
     2.7.  Example of a Signed "security.txt" File
   3.  Location of the security.txt File
     3.1.  Scope of the File
   4.  File Format Description and ABNF Grammar
   5.  Security Considerations
     5.1.  Compromised Files and Incident Response
     5.2.  Redirects
     5.3.  Incorrect or Stale Information
     5.4.  Intentionally Malformed Files, Resources, and Reports
     5.5.  No Implied Permission for Testing
     5.6.  Multi-User Environments
     5.7.  Protecting Data in Transit
     5.8.  Spam and Spurious Reports
   6.  IANA Considerations
     6.1.  Well-Known URIs Registry
     6.2.  Registry for security.txt Fields
   7.  References
     7.1.  Normative References
     7.2.  Informative References
   Acknowledgments
   Authors' Addresses

1.  Introduction

1.1.  Motivation, Prior Work, and Scope

   Many security researchers encounter situations where they are unable
   to report security vulnerabilities to organizations because there are
   no reporting channels to contact the owner of a particular resource,
   and no information is available about the vulnerability disclosure
   practices of such owner.

   As per Section 4 of [RFC2142], there is an existing convention of
   using the <SECURITY@domain> email address for communications
   regarding security issues.  That convention provides only a single,
   email-based channel of communication per domain and does not provide
   a way for domain owners to publish information about their security
   disclosure practices.

   There are also contact conventions prescribed for Internet Service
   Providers (ISPs) in Section 2 of [RFC3013], for Computer Security
   Incident Response Teams (CSIRTs) in Section 3.2 of [RFC2350], and for
   site operators in Section 5.2 of [RFC2196].  As per [RFC7485], there
   is also contact information provided by Regional Internet Registries
   (RIRs) and domain registries for owners of IP addresses, Autonomous
   System Numbers (ASNs), and domain names.  However, none of these
   tackle the issue of how security researchers can locate contact
   information and vulnerability disclosure practices for organizations
   in order to report vulnerabilities.

   In this document, we define a richer, machine-parsable, and more
   extensible way for organizations to communicate information about
   their security disclosure practices and ways to contact them.  Other
   details of vulnerability disclosure are outside the scope of this
   document.  Readers are encouraged to consult other documents such as
   [ISO.29147.2018] or [CERT.CVD].

   As per [CERT.CVD], "vulnerability response" refers to reports of
   product vulnerabilities, which is related to but distinct from
   reports of network intrusions and compromised websites ("incident
   response").  The mechanism defined in this document is intended to be
   used for the former ("vulnerability response").  If implementors want
   to utilize this mechanism for incident response, they should be aware
   of additional security considerations discussed in Section 5.1.

   The "security.txt" file is intended to be complementary and not a
   substitute or replacement for other public resources maintained by
   organizations regarding their security disclosure practices.

1.2.  Terminology

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
   "OPTIONAL" in this document are to be interpreted as described in BCP
   14 [RFC2119] [RFC8174] when, and only when, they appear in all
   capitals, as shown here.

   The term "researcher" corresponds to the terms "finder" and
   "reporter" in [ISO.29147.2018] and [CERT.CVD].  The term
   "organization" corresponds to the term "vendor" in [ISO.29147.2018]
   and [CERT.CVD].

   The term "implementors" includes all parties involved in the
   vulnerability disclosure process.

2.  The Specification

   This document defines a text file to be placed in a known location
   that provides information about vulnerability disclosure practices of
   a particular organization.  The format of this file is machine
   parsable and MUST follow the ABNF grammar defined in Section 4.  This
   file is intended to help security researchers when disclosing
   security vulnerabilities.

   By convention, the file is named "security.txt".  The location and
   scope are described in Section 3.

   This text file contains multiple fields with different values.  A
   field contains a "name", which is the first part of a field all the
   way up to the colon (for example: "Contact:") and follows the syntax
   defined for "field-name" in Section 3.6.8 of [RFC5322].  Field names
   are case insensitive (as per Section 2.3 of [RFC5234]).  The "value"
   comes after the field name (for example:
   "mailto:security@example.com") and follows the syntax defined for
   "unstructured" in Section 3.2.5 of [RFC5322].  The file MAY also
   contain blank lines.

   A field MUST always consist of a name and a value (for example:
   "Contact: mailto:security@example.com").  A "security.txt" file can
   have an unlimited number of fields.  Each field MUST appear on its
   own line.  Unless otherwise specified by the field definition,
   multiple values MUST NOT be chained together for a single field.
   Unless otherwise indicated in a definition of a particular field, a
   field MAY appear multiple times.

   Implementors should be aware that some of the fields may contain URIs
   using percent-encoding (as per Section 2.1 of [RFC3986]).

2.1.  Comments

   Any line beginning with the "#" (%x23) symbol MUST be interpreted as
   a comment.  The content of the comment may contain any ASCII or
   Unicode characters in the %x21-7E and %x80-FFFFF ranges plus the tab
   (%x09) and space (%x20) characters.

   Example:

   # This is a comment.

2.2.  Line Separator

   Every line MUST end with either a carriage return and line feed
   characters (CRLF / %x0D %x0A) or just a line feed character (LF /
   %x0A).

2.3.  Digital Signature

   It is RECOMMENDED that a "security.txt" file be digitally signed
   using an OpenPGP cleartext signature as described in Section 7 of
   [RFC4880].  When digital signatures are used, it is also RECOMMENDED
   that organizations use the "Canonical" field (as per Section 2.5.2),
   thus allowing the digital signature to authenticate the location of
   the file.

   When it comes to verifying the key used to generate the signature, it
   is always the security researcher's responsibility to make sure the
   key being used is indeed one they trust.

2.4.  Extensibility

   Like many other formats and protocols, this format may need to be
   changed over time to fit the ever-changing landscape of the Internet.
   Therefore, extensibility is provided via an IANA registry for fields
   as defined in Section 6.2.  Any fields registered via that process
   MUST be considered optional.  To encourage extensibility and
   interoperability, researchers MUST ignore any fields they do not
   explicitly support.

   In general, implementors should "be conservative in what you do, be
   liberal in what you accept from others" (as per [RFC0793]).

2.5.  Field Definitions

   Unless otherwise stated, all fields MUST be considered optional.

2.5.1.  Acknowledgments

   The "Acknowledgments" field indicates a link to a page where security
   researchers are recognized for their reports.  The page being
   referenced should list security researchers that reported security
   vulnerabilities and collaborated to remediate them.  Organizations
   should be careful to limit the vulnerability information being
   published in order to prevent future attacks.

   If this field indicates a web URI, then it MUST begin with "https://"
   (as per Section 2.7.2 of [RFC7230]).

   Example:

   Acknowledgments: https://example.com/hall-of-fame.html

   Example security acknowledgments page:

   We would like to thank the following researchers:

   (2017-04-15) Frank Denis - Reflected cross-site scripting
   (2017-01-02) Alice Quinn  - SQL injection
   (2016-12-24) John Buchner - Stored cross-site scripting
   (2016-06-10) Anna Richmond - A server configuration issue

2.5.2.  Canonical

   The "Canonical" field indicates the canonical URIs where the
   "security.txt" file is located, which is usually something like
   "https://example.com/.well-known/security.txt".  If this field
   indicates a web URI, then it MUST begin with "https://" (as per
   Section 2.7.2 of [RFC7230]).

   While this field indicates that a "security.txt" retrieved from a
   given URI is intended to apply to that URI, it MUST NOT be
   interpreted to apply to all canonical URIs listed within the file.
   Researchers SHOULD use an additional trust mechanism such as a
   digital signature (as per Section 2.3) to make the determination that
   a particular canonical URI is applicable.

   If this field appears within a "security.txt" file and the URI used
   to retrieve that file is not listed within any canonical fields, then
   the contents of the file SHOULD NOT be trusted.

   Canonical: https://www.example.com/.well-known/security.txt
   Canonical: https://someserver.example.com/.well-known/security.txt

2.5.3.  Contact

   The "Contact" field indicates a method that researchers should use
   for reporting security vulnerabilities such as an email address, a
   phone number, and/or a web page with contact information.  This field
   MUST always be present in a "security.txt" file.  If this field
   indicates a web URI, then it MUST begin with "https://" (as per
   Section 2.7.2 of [RFC7230]).  Security email addresses should use the
   conventions defined in Section 4 of [RFC2142].

   The value MUST follow the URI syntax described in Section 3 of
   [RFC3986].  This means that "mailto" and "tel" URI schemes must be
   used when specifying email addresses and telephone numbers, as
   defined in [RFC6068] and [RFC3966].  When the value of this field is
   an email address, it is RECOMMENDED that encryption be used (as per
   Section 2.5.4).

   These SHOULD be listed in order of preference, with the first
   occurrence being the preferred method of contact, the second
   occurrence being the second most preferred method of contact, etc.
   In the example below, the first email address
   ("security@example.com") is the preferred method of contact.

   Contact: mailto:security@example.com
   Contact: mailto:security%2Buri%2Bencoded@example.com
   Contact: tel:+1-201-555-0123
   Contact: https://example.com/security-contact.html

2.5.4.  Encryption

   The "Encryption" field indicates an encryption key that security
   researchers should use for encrypted communication.  Keys MUST NOT
   appear in this field.  Instead, the value of this field MUST be a URI
   pointing to a location where the key can be retrieved.  If this field
   indicates a web URI, then it MUST begin with "https://" (as per
   Section 2.7.2 of [RFC7230]).

   When it comes to verifying the authenticity of the key, it is always
   the security researcher's responsibility to make sure the key being
   specified is indeed one they trust.  Researchers must not assume that
   this key is used to generate the digital signature referenced in
   Section 2.3.

   Example of an OpenPGP key available from a web server:

   Encryption: https://example.com/pgp-key.txt

   Example of an OpenPGP key available from an OPENPGPKEY DNS record:

Encryption: dns:5d2d37ab76d47d36._openpgpkey.example.com?type=OPENPGPKEY

   Example of an OpenPGP key being referenced by its fingerprint:

   Encryption: openpgp4fpr:5f2de5521c63a801ab59ccb603d49de44b29100f

2.5.5.  Expires

   The "Expires" field indicates the date and time after which the data
   contained in the "security.txt" file is considered stale and should
   not be used (as per Section 5.3).  The value of this field is
   formatted according to the Internet profiles of [ISO.8601-1] and
   [ISO.8601-2] as defined in [RFC3339].  It is RECOMMENDED that the
   value of this field be less than a year into the future to avoid
   staleness.

   This field MUST always be present and MUST NOT appear more than once.

   Expires: 2021-12-31T18:37:07z

2.5.6.  Hiring

   The "Hiring" field is used for linking to the vendor's security-
   related job positions.  If this field indicates a web URI, then it
   MUST begin with "https://" (as per Section 2.7.2 of [RFC7230]).

   Hiring: https://example.com/jobs.html

2.5.7.  Policy

   The "Policy" field indicates a link to where the vulnerability
   disclosure policy is located.  This can help security researchers
   understand the organization's vulnerability reporting practices.  If
   this field indicates a web URI, then it MUST begin with "https://"
   (as per Section 2.7.2 of [RFC7230]).

   Example:

   Policy: https://example.com/disclosure-policy.html

2.5.8.  Preferred-Languages

   The "Preferred-Languages" field can be used to indicate a set of
   natural languages that are preferred when submitting security
   reports.  This set MAY list multiple values, separated by commas.  If
   this field is included, then at least one value MUST be listed.  The
   values within this set are language tags (as defined in [RFC5646]).
   If this field is absent, security researchers may assume that English
   is the language to be used (as per Section 4.5 of [RFC2277]).

   The order in which they appear is not an indication of priority; the
   listed languages are intended to have equal priority.

   This field MUST NOT appear more than once.

   Example (English, Spanish and French):

   Preferred-Languages: en, es, fr

2.6.  Example of an Unsigned "security.txt" File

   # Our security address
   Contact: mailto:security@example.com

   # Our OpenPGP key
   Encryption: https://example.com/pgp-key.txt

   # Our security policy
   Policy: https://example.com/security-policy.html

   # Our security acknowledgments page
   Acknowledgments: https://example.com/hall-of-fame.html

   Expires: 2021-12-31T18:37:07z

2.7.  Example of a Signed "security.txt" File

   -----BEGIN PGP SIGNED MESSAGE-----
   Hash: SHA256

   # Canonical URI
   Canonical: https://example.com/.well-known/security.txt

   # Our security address
   Contact: mailto:security@example.com

   # Our OpenPGP key
   Encryption: https://example.com/pgp-key.txt

   # Our security policy
   Policy: https://example.com/security-policy.html

   # Our security acknowledgments page
   Acknowledgments: https://example.com/hall-of-fame.html

   Expires: 2021-12-31T18:37:07z
   -----BEGIN PGP SIGNATURE-----
   Version: GnuPG v2.2

   [signature]
   -----END PGP SIGNATURE-----

3.  Location of the security.txt File

   For web-based services, organizations MUST place the "security.txt"
   file under the "/.well-known/" path, e.g., https://example.com/.well-
   known/security.txt as per [RFC8615] of a domain name or IP address.
   For legacy compatibility, a "security.txt" file might be placed at
   the top-level path or redirect (as per Section 6.4 of [RFC7231]) to
   the "security.txt" file under the "/.well-known/" path.  If a
   "security.txt" file is present in both locations, the one in the
   "/.well-known/" path MUST be used.

   The file MUST be accessed via HTTP 1.0 or a higher version, and the
   file access MUST use the "https" scheme (as per Section 2.7.2 of
   [RFC7230]).  It MUST have a Content-Type of "text/plain" with the
   default charset parameter set to "utf-8" (as per Section 4.1.3 of
   [RFC2046]).

   Retrieval of "security.txt" files and resources indicated within such
   files may result in a redirect (as per Section 6.4 of [RFC7231]).
   Researchers should perform additional analysis (as per Section 5.2)
   to make sure these redirects are not malicious or pointing to
   resources controlled by an attacker.

3.1.  Scope of the File

   A "security.txt" file MUST only apply to the domain or IP address in
   the URI used to retrieve it, not to any of its subdomains or parent
   domains.  A "security.txt" file MAY also apply to products and
   services provided by the organization publishing the file.

   As per Section 1.1, this specification is intended for a
   vulnerability response.  If implementors want to use this for an
   incident response, they should be aware of additional security
   considerations discussed in Section 5.1.

   Organizations SHOULD use the policy directive (as per Section 2.5.7)
   to provide additional details regarding the scope and details of
   their vulnerability disclosure process.

   Some examples appear below:

   # The following only applies to example.com.
   https://example.com/.well-known/security.txt

   # This only applies to subdomain.example.com.
   https://subdomain.example.com/.well-known/security.txt

   # This security.txt file applies to IPv4 address of 192.0.2.0.
   https://192.0.2.0/.well-known/security.txt

   # This security.txt file applies to IPv6 address of 2001:db8:8:4::2.
   https://[2001:db8:8:4::2]/.well-known/security.txt

4.  File Format Description and ABNF Grammar

   The file format of the "security.txt" file MUST be plain text (MIME
   type "text/plain") as defined in Section 4.1.3 of [RFC2046] and MUST
   be encoded using UTF-8 [RFC3629] in Net-Unicode form [RFC5198].

   The format of this file MUST follow the ABNF definition below (which
   incorporates the core ABNF rules from [RFC5234] and uses the case-
   sensitive string support from [RFC7405]).

   body             =  signed / unsigned

   unsigned       =  *line (contact-field eol) ; one or more required
                     *line (expires-field eol) ; exactly one required
                     *line [lang-field eol] *line ; exactly one optional
                     ; order of fields within the file is not important
                     ; except that if contact-field appears more
                     ; than once, the order of those indicates
                     ; priority (see Section 3.5.3)

   ; signed is the production that should match the OpenPGP clearsigned
   ; document
   signed           =  cleartext-header
                       1*(hash-header)
                       CRLF
                       cleartext
                       signature

   cleartext-header =  %s"-----BEGIN PGP SIGNED MESSAGE-----" CRLF

   hash-header      =  %s"Hash: " hash-alg *("," hash-alg) CRLF

   hash-alg         =  token
                         ; imported from RFC 2045; see RFC 4880 Section
                         ; 10.3.3 for a pointer to the registry of
                         ; valid values

   ;cleartext       =  1*( UTF8-octets [CR] LF)
                         ; dash-escaped per RFC 4880 Section 7.1

   cleartext        =  *((line-dash / line-from / line-nodash) [CR] LF)

   line-dash        =  ("- ") "-" *UTF8-char-not-cr
                          ; MUST include initial "- "

   line-from        =  ["- "] "From " *UTF8-char-not-cr
                         ; SHOULD include initial "- "

   line-nodash      =  ["- "] *UTF8-char-not-cr
                         ; MAY include initial "- "

   UTF8-char-not-dash =  UTF8-1-not-dash / UTF8-2 / UTF8-3 / UTF8-4
   UTF8-1-not-dash  =  %x00-2C / %x2E-7F
   UTF8-char-not-cr =  UTF8-1-not-cr / UTF8-2 / UTF8-3 / UTF8-4
   UTF8-1-not-cr    =  %x00-0C / %x0E-7F

   ; UTF8 rules from RFC 3629
   UTF8-octets      =  *( UTF8-char )
   UTF8-char        =  UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
   UTF8-1           =  %x00-7F
   UTF8-2           =  %xC2-DF UTF8-tail
   UTF8-3           =  %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
                       %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
   UTF8-4           =  %xF0 %x90-BF 2( UTF8-tail ) /
                       %xF1-F3 3( UTF8-tail ) /
                       %xF4 %x80-8F 2( UTF8-tail )
   UTF8-tail        =  %x80-BF

   signature        =  armor-header
                       armor-keys
                       CRLF
                       signature-data
                       armor-tail

   armor-header     =  %s"-----BEGIN PGP SIGNATURE-----" CRLF

   armor-keys       =  *(token ": " *( VCHAR / WSP ) CRLF)
                         ; Armor Header Keys from RFC 4880

   armor-tail       =  %s"-----END PGP SIGNATURE-----" CRLF

   signature-data   =  1*(1*(ALPHA / DIGIT / "=" / "+" / "/") CRLF)
                         ; base64; see RFC 4648
                         ; includes RFC 4880 checksum

   line             =  [ (field / comment) ] eol

   eol              =  *WSP [CR] LF

   field            =  ; optional fields
                       ack-field /
                       can-field /
                       contact-field / ; optional repeated instances
                       encryption-field /
                       hiring-field /
                       policy-field /
                       ext-field

   fs               =  ":"

   comment          =  "#" *(WSP / VCHAR / %x80-FFFFF)

   ack-field        =  "Acknowledgments" fs SP uri

   can-field        =  "Canonical" fs SP uri

   contact-field    =  "Contact" fs SP uri

   expires-field    =  "Expires" fs SP date-time

   encryption-field =  "Encryption" fs SP uri

   hiring-field     =  "Hiring" fs SP uri

   lang-field       =  "Preferred-Languages" fs SP lang-values

   policy-field     =  "Policy" fs SP uri

   date-time        =  < imported from Section 5.6 of [RFC3339] >

   lang-tag         =  < Language-Tag from Section 2.1 of [RFC5646] >

   lang-values      =  lang-tag *(*WSP "," *WSP lang-tag)

   uri              =  < URI as per Section 3 of [RFC3986] >

   ext-field        =  field-name fs SP unstructured

   field-name       =  < imported from Section 3.6.8 of [RFC5322] >

   unstructured     =  < imported from Section 3.2.5 of [RFC5322] >

   token            =  < imported from Section 5.1 of [RFC2045] >

   ALPHA            =  %x41-5A / %x61-7A   ; A-Z / a-z

   BIT              =  "0" / "1"

   CHAR             =  %x01-7F
                         ; any 7-bit US-ASCII character,
                         ;  excluding NUL

   CR               =  %x0D
                         ; carriage return

   CRLF             =  CR LF
                         ; Internet standard newline

   CTL              =  %x00-1F / %x7F
                         ; controls

   DIGIT            =  %x30-39
                         ; 0-9

   DQUOTE           =  %x22
                         ; " (Double Quote)

   HEXDIG           =  DIGIT / "A" / "B" / "C" / "D" / "E" / "F"

   HTAB             =  %x09
                         ; horizontal tab

   LF               =  %x0A
                         ; linefeed

   LWSP             =  *(WSP / CRLF WSP)
                         ; Use of this linear-white-space rule
                         ;  permits lines containing only white
                         ;  space that are no longer legal in
                         ;  mail headers and have caused
                         ;  interoperability problems in other
                         ;  contexts.
                         ; Do not use when defining mail
                         ;  headers and use with caution in
                         ;  other contexts.

   OCTET            =  %x00-FF
                         ; 8 bits of data

   SP               =  %x20

   VCHAR            =  %x21-7E
                         ; visible (printing) characters

   WSP              =  SP / HTAB
                         ; white space

   "ext-field" refers to extension fields, which are discussed in
   Section 2.4.

5.  Security Considerations

   Because of the use of URIs and well-known resources, security
   considerations of [RFC3986] and [RFC8615] apply here, in addition to
   the considerations outlined below.

5.1.  Compromised Files and Incident Response

   An attacker that has compromised a website is able to compromise the
   "security.txt" file as well or set up a redirect to their own site.
   This can result in security reports not being received by the
   organization or being sent to the attacker.

   To protect against this, organizations should use the "Canonical"
   field to indicate the locations of the file (as per Section 2.5.2),
   digitally sign their "security.txt" files (as per Section 2.3), and
   regularly monitor the file and the referenced resources to detect
   tampering.

   Security researchers should validate the "security.txt" file,
   including verifying the digital signature and checking any available
   historical records before using the information contained in the
   file.  If the "security.txt" file looks suspicious or compromised, it
   should not be used.

   While it is not recommended, implementors may choose to use the
   information published within a "security.txt" file for an incident
   response.  In such cases, extreme caution should be taken before
   trusting such information, since it may have been compromised by an
   attacker.  Researchers should use additional methods to verify such
   data including out-of-band verification of the Pretty Good Privacy
   (PGP) signature, DNSSEC-based approaches, etc.

5.2.  Redirects

   When retrieving the file and any resources referenced in the file,
   researchers should record any redirects since they can lead to a
   different domain or IP address controlled by an attacker.  Further
   inspection of such redirects is recommended before using the
   information contained within the file.

5.3.  Incorrect or Stale Information

   If information and resources referenced in a "security.txt" file are
   incorrect or not kept up to date, this can result in security reports
   not being received by the organization or sent to incorrect contacts,
   thus exposing possible security issues to third parties.  Not having
   a "security.txt" file may be preferable to having stale information
   in this file.  Organizations must use the "Expires" field (see
   Section 2.5.5) to indicate to researchers when the data in the file
   is no longer valid.

   Organizations should ensure that information in this file and any
   referenced resources such as web pages, email addresses, and
   telephone numbers are kept current, are accessible, are controlled by
   the organization, and are kept secure.

5.4.  Intentionally Malformed Files, Resources, and Reports

   It is possible for compromised or malicious sites to create files
   that are extraordinarily large or otherwise malformed in an attempt
   to discover or exploit weaknesses in the parsing code.  Researchers
   should make sure that any such code is robust against large or
   malformed files and fields, and they may choose to have the code not
   parse files larger than 32 KBs, those with fields longer than 2,048
   characters, or those containing more than 1,000 lines.  The ABNF
   grammar (as defined in Section 4) can also be used as a way to verify
   these files.

   The same concerns apply to any other resources referenced within
   "security.txt" files, as well as any security reports received as a
   result of publishing this file.  Such resources and reports may be
   hostile, malformed, or malicious.

5.5.  No Implied Permission for Testing

   The presence of a "security.txt" file might be interpreted by
   researchers as providing permission to do security testing against
   the domain or IP address where it is published or against products
   and services provided by the organization publishing the file.  This
   might result in increased testing against an organization by
   researchers.  On the other hand, a decision not to publish a
   "security.txt" file might be interpreted by the organization
   operating that website to be a way to signal to researchers that
   permission to test that particular site or project is denied.  This
   might result in pushback against researchers reporting security
   issues to that organization.

   Therefore, researchers shouldn't assume that the presence or absence
   of a "security.txt" file grants or denies permission for security
   testing.  Any such permission may be indicated in the company's
   vulnerability disclosure policy (as per Section 2.5.7) or a new field
   (as per Section 2.4).

5.6.  Multi-User Environments

   In multi-user / multi-tenant environments, it may be possible for a
   user to take over the location of the "security.txt" file.
   Organizations should reserve the "security.txt" namespace at the root
   to ensure no third party can create a page with the "security.txt"
   AND "/.well-known/security.txt" names.

5.7.  Protecting Data in Transit

   To protect a "security.txt" file from being tampered with in transit,
   implementors MUST use HTTPS (as per Section 2.7.2 of [RFC7230]) when
   serving the file itself and for retrieval of any web URIs referenced
   in it (except when otherwise noted in this specification).  As part
   of the TLS handshake, researchers should validate the provided X.509
   certificate in accordance with [RFC6125] and the following
   considerations:

   *  Matching is performed only against the DNS-ID identifiers.

   *  DNS domain names in server certificates MAY contain the wildcard
      character '*' as the complete leftmost label within the
      identifier.

   The certificate may also be checked for revocation via the Online
   Certificate Status Protocol (OCSP) [RFC6960], certificate revocation
   lists (CRLs), or similar mechanisms.

   In cases where the "security.txt" file cannot be served via HTTPS
   (such as localhost) or is being served with an invalid certificate,
   additional human validation is recommended since the contents may
   have been modified while in transit.

   As an additional layer of protection, it is also recommended that
   organizations digitally sign their "security.txt" file with OpenPGP
   (as per Section 2.3).  Also, to protect security reports from being
   tampered with or observed while in transit, organizations should
   specify encryption keys (as per Section 2.5.4) unless HTTPS is being
   used for report submission.

   However, the determination of validity of such keys is out of scope
   for this specification.  Security researchers need to establish other
   secure means to verify them.

5.8.  Spam and Spurious Reports

   Similar to concerns in [RFC2142], denial-of-service attacks via spam
   reports would become easier once a "security.txt" file is published
   by an organization.  In addition, there is an increased likelihood of
   reports being sent in an automated fashion and/or as a result of
   automated scans without human analysis.  Attackers can also use this
   file as a way to spam unrelated third parties by listing their
   resources and/or contact information.

   Organizations need to weigh the advantages of publishing this file
   versus the possible disadvantages and increased resources required to
   analyze security reports.

   Security researchers should review all information within the
   "security.txt" file before submitting reports in an automated fashion
   or reports resulting from automated scans.

6.  IANA Considerations

   Implementors should be aware that any resources referenced within a
   "security.txt" file MUST NOT point to the Well-Known URIs namespace
   unless they are registered with IANA (as per [RFC8615]).

6.1.  Well-Known URIs Registry

   IANA has updated the "Well-Known URIs" registry with the following
   additional values (using the template from [RFC8615]):

   URI suffix:  security.txt
   Change controller:  IETF
   Specification document(s):  RFC 9116
   Status:  permanent

6.2.  Registry for security.txt Fields

   IANA has created the "security.txt Fields" registry in accordance
   with [RFC8126].  This registry contains fields for use in
   "security.txt" files, defined by this specification.

   New registrations or updates MUST be published in accordance with the
   "Expert Review" guidelines as described in Sections 4.5 and 5 of
   [RFC8126].  Any new field thus registered is considered optional by
   this specification unless a new version of this specification is
   published.

   Designated experts should determine whether a proposed registration
   or update provides value to organizations and researchers using this
   format and makes sense in the context of industry-accepted
   vulnerability disclosure processes such as [ISO.29147.2018] and
   [CERT.CVD].

   New registrations and updates MUST contain the following information:

   1.  Name of the field being registered or updated

   2.  Short description of the field

   3.  Whether the field can appear more than once

   4.  New or updated status, which MUST be one of the following:

       current:  The field is in current use.
       deprecated:  The field has been in use, but new usage is
          discouraged.
       historic:  The field is no longer in current use.

   5.  Change controller

   6.  The document in which the specification of the field is published
       (if available)

   Existing registrations may be marked historic or deprecated, as
   appropriate, by a future update to this document.

   The initial registry contains these values:

   Field Name:  Acknowledgments
   Description:  link to page where security researchers are recognized
   Multiple Appearances:  yes
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Canonical
   Description:  canonical URI for this file
   Multiple Appearances:  yes
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Contact
   Description:  contact information to use for reporting
      vulnerabilities
   Multiple Appearances:  yes
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Expires
   Description:  date and time after which this file is considered stale
   Multiple Appearances:  no
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Encryption
   Description:  link to a key to be used for encrypted communication
   Multiple Appearances:  yes
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Hiring
   Description:  link to the vendor's security-related job positions
   Multiple Appearances:  yes
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Policy
   Description:  link to security policy page
   Multiple Appearances:  yes
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

   Field Name:  Preferred-Languages
   Description:  list of preferred languages for security reports
   Multiple Appearances:  no
   Status:  current
   Change controller:  IETF
   Reference:  RFC 9116

7.  References

7.1.  Normative References

   [RFC2046]  Freed, N. and N. Borenstein, "Multipurpose Internet Mail
              Extensions (MIME) Part Two: Media Types", RFC 2046,
              DOI 10.17487/RFC2046, November 1996,
              <https://www.rfc-editor.org/info/rfc2046>.

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997,
              <https://www.rfc-editor.org/info/rfc2119>.

   [RFC2142]  Crocker, D., "Mailbox Names for Common Services, Roles and
              Functions", RFC 2142, DOI 10.17487/RFC2142, May 1997,
              <https://www.rfc-editor.org/info/rfc2142>.

   [RFC2277]  Alvestrand, H., "IETF Policy on Character Sets and
              Languages", BCP 18, RFC 2277, DOI 10.17487/RFC2277,
              January 1998, <https://www.rfc-editor.org/info/rfc2277>.

   [RFC3339]  Klyne, G. and C. Newman, "Date and Time on the Internet:
              Timestamps", RFC 3339, DOI 10.17487/RFC3339, July 2002,
              <https://www.rfc-editor.org/info/rfc3339>.

   [RFC3629]  Yergeau, F., "UTF-8, a transformation format of ISO
              10646", STD 63, RFC 3629, DOI 10.17487/RFC3629, November
              2003, <https://www.rfc-editor.org/info/rfc3629>.

   [RFC3966]  Schulzrinne, H., "The tel URI for Telephone Numbers",
              RFC 3966, DOI 10.17487/RFC3966, December 2004,
              <https://www.rfc-editor.org/info/rfc3966>.

   [RFC3986]  Berners-Lee, T., Fielding, R., and L. Masinter, "Uniform
              Resource Identifier (URI): Generic Syntax", STD 66,
              RFC 3986, DOI 10.17487/RFC3986, January 2005,
              <https://www.rfc-editor.org/info/rfc3986>.

   [RFC4880]  Callas, J., Donnerhacke, L., Finney, H., Shaw, D., and R.
              Thayer, "OpenPGP Message Format", RFC 4880,
              DOI 10.17487/RFC4880, November 2007,
              <https://www.rfc-editor.org/info/rfc4880>.

   [RFC5198]  Klensin, J. and M. Padlipsky, "Unicode Format for Network
              Interchange", RFC 5198, DOI 10.17487/RFC5198, March 2008,
              <https://www.rfc-editor.org/info/rfc5198>.

   [RFC5234]  Crocker, D., Ed. and P. Overell, "Augmented BNF for Syntax
              Specifications: ABNF", STD 68, RFC 5234,
              DOI 10.17487/RFC5234, January 2008,
              <https://www.rfc-editor.org/info/rfc5234>.

   [RFC5322]  Resnick, P., Ed., "Internet Message Format", RFC 5322,
              DOI 10.17487/RFC5322, October 2008,
              <https://www.rfc-editor.org/info/rfc5322>.

   [RFC5646]  Phillips, A., Ed. and M. Davis, Ed., "Tags for Identifying
              Languages", BCP 47, RFC 5646, DOI 10.17487/RFC5646,
              September 2009, <https://www.rfc-editor.org/info/rfc5646>.

   [RFC6068]  Duerst, M., Masinter, L., and J. Zawinski, "The 'mailto'
              URI Scheme", RFC 6068, DOI 10.17487/RFC6068, October 2010,
              <https://www.rfc-editor.org/info/rfc6068>.

   [RFC6125]  Saint-Andre, P. and J. Hodges, "Representation and
              Verification of Domain-Based Application Service Identity
              within Internet Public Key Infrastructure Using X.509
              (PKIX) Certificates in the Context of Transport Layer
              Security (TLS)", RFC 6125, DOI 10.17487/RFC6125, March
              2011, <https://www.rfc-editor.org/info/rfc6125>.

   [RFC6960]  Santesson, S., Myers, M., Ankney, R., Malpani, A.,
              Galperin, S., and C. Adams, "X.509 Internet Public Key
              Infrastructure Online Certificate Status Protocol - OCSP",
              RFC 6960, DOI 10.17487/RFC6960, June 2013,
              <https://www.rfc-editor.org/info/rfc6960>.

   [RFC7230]  Fielding, R., Ed. and J. Reschke, Ed., "Hypertext Transfer
              Protocol (HTTP/1.1): Message Syntax and Routing",
              RFC 7230, DOI 10.17487/RFC7230, June 2014,
              <https://www.rfc-editor.org/info/rfc7230>.

   [RFC7231]  Fielding, R., Ed. and J. Reschke, Ed., "Hypertext Transfer
              Protocol (HTTP/1.1): Semantics and Content", RFC 7231,
              DOI 10.17487/RFC7231, June 2014,
              <https://www.rfc-editor.org/info/rfc7231>.

   [RFC7405]  Kyzivat, P., "Case-Sensitive String Support in ABNF",
              RFC 7405, DOI 10.17487/RFC7405, December 2014,
              <https://www.rfc-editor.org/info/rfc7405>.

   [RFC8174]  Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC
              2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174,
              May 2017, <https://www.rfc-editor.org/info/rfc8174>.

   [RFC8615]  Nottingham, M., "Well-Known Uniform Resource Identifiers
              (URIs)", RFC 8615, DOI 10.17487/RFC8615, May 2019,
              <https://www.rfc-editor.org/info/rfc8615>.

7.2.  Informative References

   [CERT.CVD] Software Engineering Institute, "The CERT Guide to
              Coordinated Vulnerability Disclosure", Carnegie Mellon
              University, CMU/SEI-2017-SR-022, August 2017.

   [ISO.29147.2018]
              ISO, "Information technology - Security techniques -
              Vulnerability disclosure", ISO/IEC 29147:2018, October
              2018.

   [ISO.8601-1]
              ISO, "Date and time - Representations for information
              interchange - Part 1: Basic rules", ISO 8601-1:2019,
              February 2019.

   [ISO.8601-2]
              ISO, "Date and time - Representations for information
              interchange - Part 2: Extensions", ISO 8601-2:2019,
              February 2019.

   [RFC0793]  Postel, J., "Transmission Control Protocol", STD 7,
              RFC 793, DOI 10.17487/RFC0793, September 1981,
              <https://www.rfc-editor.org/info/rfc793>.

   [RFC2196]  Fraser, B., "Site Security Handbook", FYI 8, RFC 2196,
              DOI 10.17487/RFC2196, September 1997,
              <https://www.rfc-editor.org/info/rfc2196>.

   [RFC2350]  Brownlee, N. and E. Guttman, "Expectations for Computer
              Security Incident Response", BCP 21, RFC 2350,
              DOI 10.17487/RFC2350, June 1998,
              <https://www.rfc-editor.org/info/rfc2350>.

   [RFC3013]  Killalea, T., "Recommended Internet Service Provider
              Security Services and Procedures", BCP 46, RFC 3013,
              DOI 10.17487/RFC3013, November 2000,
              <https://www.rfc-editor.org/info/rfc3013>.

   [RFC7485]  Zhou, L., Kong, N., Shen, S., Sheng, S., and A. Servin,
              "Inventory and Analysis of WHOIS Registration Objects",
              RFC 7485, DOI 10.17487/RFC7485, March 2015,
              <https://www.rfc-editor.org/info/rfc7485>.

   [RFC8126]  Cotton, M., Leiba, B., and T. Narten, "Guidelines for
              Writing an IANA Considerations Section in RFCs", BCP 26,
              RFC 8126, DOI 10.17487/RFC8126, June 2017,
              <https://www.rfc-editor.org/info/rfc8126>.

Acknowledgments

   The authors would like to acknowledge the help provided during the
   development of this document by Tom Hudson, Jobert Abma, Gerben
   Janssen van Doorn, Austin Heap, Stephane Bortzmeyer, Max Smith,
   Eduardo Vela, and Krzysztof Kotowicz.

   The authors would also like to acknowledge the feedback provided by
   multiple members of the IETF's LAST CALL, SAAG, and SECDISPATCH
   lists.

   Yakov Shafranovich would like to also thank L.T.S. (for everything).

Authors' Addresses

   Edwin Foudil
   Email: contact@edoverflow.com


   Yakov Shafranovich
   Nightwatch Cybersecurity
   Email: yakov+ietf@nightwatchcybersecurity.com

```

---

