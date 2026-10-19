# CWE et CAPEC — sélection Recon-IA

Sélection des faiblesses (CWE) et schémas d'attaque (CAPEC) correspondant aux constats d'une reconnaissance passive. © The MITRE Corporation — CWE™ et CAPEC™, reproduits selon leurs conditions d'utilisation (https://cwe.mitre.org/about/termsofuse.html).

---

# CWE-16 — Configuration

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/16.html)

## Description

Weaknesses in this category are typically introduced during the configuration of the software.

---

# CWE-79 — Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/79.html)

## Description

The product does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.

There are many variants of cross-site scripting, characterized by a variety of terms or involving different attack topologies. However, they all indicate the same fundamental weakness: improper neutralization of dangerous input between the adversary and a victim.

## Conséquences

- Access Control, Confidentiality : Bypass Protection Mechanism, Read Application Data — The most common attack performed with cross-site scripting involves the disclosure of private information stored in user cookies, such as session information. Typically, a malicious user will craft a client-side script, which -- when parsed by a web browser -- performs some activity on behalf of the victim to an attacker-controlled system (such as sending all site cookies to a given E-mail address […]
- Integrity, Confidentiality, Availability : Execute Unauthorized Code or Commands — In some circumstances it may be possible to run arbitrary code on a victim's computer when cross-site scripting is combined with other flaws, for example, "drive-by hacking."
- Confidentiality, Integrity, Availability, Access Control : Execute Unauthorized Code or Commands, Bypass Protection Mechanism, Read Application Data — The consequence of an XSS attack is the same regardless of whether it is stored or reflected. The difference is in how the payload arrives at the server. XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise. Some cross-site scripting vulnerabilities can be exploited to manipulate or steal cookies, create requests that can be m […]

## Mesures d'atténuation

- [Architecture and Design] Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid [REF-1482]. Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.
- [Implementation, Architecture and Design] Understand the context in which your data will be used and the encoding that will be expected. This is especially important when transmitting data between different components, or when generating outputs that can contain multiple encodings at the same time, such as web pages or multi-part mail messages. Study all expected communication protocols and data representations to determine the required encoding strategies. For any data that will be output to another web page, especially any data that was received from external inputs, use the appropriate encoding on all non-alphanumeric characters. Parts of the same output document may require different encodings, which will vary depending on whether the output is in the: HTML body Element attributes (such as src="XYZ") URIs JavaScript sections C […]
- [Architecture and Design, Implementation] Understand all the potential areas where untrusted inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, filenames, databases, and any external systems that provide data to the application. Remember that such inputs may be obtained indirectly through API calls.
- [Architecture and Design] For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.
- [Architecture and Design] If available, use structured mechanisms that automatically enforce the separation between data and code. These mechanisms may be able to provide the relevant quoting, encoding, and validation automatically, instead of relying on the developer to provide this capability at every point where output is generated.
- [Implementation] Use and specify an output encoding that can be handled by the downstream component that is reading the output. Common encodings include ISO-8859-1, UTF-7, and UTF-8. When an encoding is not specified, a downstream component may choose a different encoding, either by assuming a default encoding or automatically inferring which encoding is being used, which can be erroneous. When the encodings are inconsistent, the downstream component might treat some character or byte sequences as special, even if they are not special in the original encoding. Attackers might then be able to exploit this discrepancy and conduct injection attacks; they even might be able to bypass protection mechanisms that assume the original encoding is also being used by the downstream component. The problem of inconsist […]

---

# CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/200.html)

## Description

The product exposes sensitive information to an actor that is not explicitly authorized to have access to that information.

There are many different kinds of mistakes that introduce information exposures. The severity of the error can range widely, depending on the context in which the product operates, the type of sensitive information that is revealed, and the benefits it may provide to an attacker. Some kinds of sensitive information include: private, personal information, such as personal messages, financial data, health records, geographic location, or contact details system status and environment, such as the operating system and installed packages business secrets and intellectual property network status and configuration the product's own code or internal state metadata, e.g. logging of connections or message headers indirect information, such as a discrepancy between two internal operations that can be observed by an outsider Information might be sensitive to different parties, each of which may have their own expectations for whether the information should be protected. These parties include: the product's own users people or organizations whose information is created or used by the product, even if they are not direct product users the product's administrators, including the admins of the system(s) and/or networks on which the product operates the developer Information exposures can occur in different ways: the code explicitly inserts sensitive information into resources or messages that are intentionally made accessible to unauthorized actors, but should not contain the information - i.e., the information should have been "scrubbed" or "sanitized" a different weakness or mistake indirectly inserts the sensitive information into resources, such as a web script error revealing the full system path of the program. the code manages resources that intentionally contain sensitive information, but the resources are unintentionally made accessible to unauthorized actors. In this case, the information exposure is resultant - i.e., a different weakness enabled the access to the informa […]

## Conséquences

- Confidentiality : Read Application Data

## Mesures d'atténuation

- [Architecture and Design] Compartmentalize the system to have "safe" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area. Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.

---

# CWE-284 — Improper Access Control

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/284.html)

## Description

The product does not restrict or incorrectly restricts access to a resource from an unauthorized actor.

Access control involves the use of several protection mechanisms such as: Authentication (proving the identity of an actor) Authorization (ensuring that a given actor can access a resource), and Accountability (tracking of activities that were performed) When any mechanism is not applied or otherwise fails, attackers can compromise the security of the product by gaining privileges, reading sensitive information, executing commands, evading detection, etc. There are two distinct behaviors that can introduce access control weaknesses: Specification: incorrect privileges, permissions, ownership, etc. are explicitly specified for either the user or the resource (for example, setting a password file to be world-writable, or giving administrator capabilities to a guest user). This action could be performed by the program or the administrator. Enforcement: the mechanism contains errors that prevent it from properly enforcing the specified access control requirements (e.g., allowing the user to specify their own privileges, or allowing a syntactically-incorrect ACL to produce insecure settings). This problem occurs within the program itself, in that it does not actually enforce the intended security policy that the administrator specifies.

## Conséquences

- Other : Varies by Context

## Mesures d'atténuation

- [Architecture and Design, Operation] Very carefully manage the setting, management, and handling of privileges. Explicitly manage trust zones in the software.
- [Architecture and Design] Compartmentalize the system to have "safe" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area. Ensure that appropriate compartmentalization is built into the system design, and the compartmentalization allows for and reinforces privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide the appropriate time to use privileges and the time to drop privileges.

---

# CWE-290 — Authentication Bypass by Spoofing

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/290.html)

## Description

This attack-focused weakness is caused by incorrectly implemented authentication schemes that are subject to spoofing attacks.

## Conséquences

- Access Control : Bypass Protection Mechanism, Gain Privileges or Assume Identity — This weakness can allow an attacker to access resources which are not otherwise accessible without proper authentication.

---

# CWE-295 — Improper Certificate Validation

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/295.html)

## Description

The product does not validate, or incorrectly validates, a certificate.

## Conséquences

- Integrity, Authentication : Bypass Protection Mechanism, Gain Privileges or Assume Identity — When a certificate is invalid or malicious, it might allow an attacker to spoof a trusted entity by interfering in the communication path between the host and client. The product might connect to a malicious host while believing it is a trusted host, or the product might be deceived into accepting spoofed data that appears to originate from a trusted host.

## Mesures d'atténuation

- [Architecture and Design, Implementation] Certificates should be carefully managed and checked to assure that data are encrypted with the intended owner's public key.
- [Implementation] If certificate pinning is being used, ensure that all relevant properties of the certificate are fully validated before the certificate is pinned, including the hostname.

---

# CWE-298 — Improper Validation of Certificate Expiration

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/298.html)

## Description

A certificate expiration is not validated or is incorrectly validated.

## Conséquences

- Integrity, Other : Other — The data read from the system vouched for by the expired certificate may be flawed due to malicious spoofing.
- Authentication, Other : Other — Trust may be assigned to certificates that have been abandoned due to age.

## Mesures d'atténuation

- [Architecture and Design] Check for expired certificates and provide the user with adequate information about the nature of the problem and how to proceed.
- [Implementation] If certificate pinning is being used, ensure that all relevant properties of the certificate are fully validated before the certificate is pinned, including the expiration.

---

# CWE-306 — Missing Authentication for Critical Function

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/306.html)

## Description

The product does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources.

## Conséquences

- Access Control, Other : Gain Privileges or Assume Identity, Varies by Context — Exposing critical functionality essentially provides an attacker with the privilege level of that functionality. The consequences will depend on the associated functionality, but they can range from reading or modifying sensitive data, accessing administrative or other privileged functionality, or possibly even executing arbitrary code.

## Mesures d'atténuation

- [Architecture and Design] Divide the software into anonymous, normal, privileged, and administrative areas. Identify which of these areas require a proven user identity, and use a centralized authentication capability. Identify all potential communication channels, or other means of interaction with the software, to ensure that all channels are appropriately protected, including those channels that are assumed to be accessible only by authorized parties. Developers sometimes perform authentication at the primary channel, but open up a secondary channel that is assumed to be private. For example, a login mechanism may be listening on one network port, but after successful authentication, it may open up a second port where it waits for the connection, but avoids authentication because it assumes that only the authent […]
- [Architecture and Design] For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid CWE-602. Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.
- [Architecture and Design] Where possible, avoid implementing custom, "grow-your-own" authentication routines and consider using authentication capabilities as provided by the surrounding framework, operating system, or environment. These capabilities may avoid common weaknesses that are unique to authentication; support automatic auditing and tracking; and make it easier to provide a clear separation between authentication tasks and authorization tasks. In environments such as the World Wide Web, the line between authentication and authorization is sometimes blurred. If custom authentication routines are required instead of those provided by the server, then these routines must be applied to every single page, since these pages could be requested directly.
- [Architecture and Design] Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. For example, consider using libraries with authentication capabilities such as OpenSSL or the ESAPI Authenticator [REF-45].
- [Implementation, System Configuration, Operation] When storing data in the cloud (e.g., S3 buckets, Azure blobs, Google Cloud Storage, etc.), use the provider's controls to require strong authentication for users who should be allowed to access the data [REF-1297] [REF-1298] [REF-1302].

---

# CWE-319 — Cleartext Transmission of Sensitive Information

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/319.html)

## Description

The product transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors.

## Conséquences

- Integrity, Confidentiality : Read Application Data, Modify Files or Directories — Anyone can read the information by gaining access to the channel being used for communication. Many communication channels can be "sniffed" (monitored) by adversaries during data transmission. For example, in networking, packets can traverse many intermediary nodes from the source to the destination, whether across the internet, an internal network, the cloud, etc. Some actors might have privilege […]
- Integrity, Confidentiality : Read Application Data, Modify Files or Directories, Other — When full communications are recorded or logged, such as with a packet dump, an adversary could attempt to obtain the dump long after the transmission has occurred and try to "sniff" the cleartext from the recorded communications in the dump itself. Even if the information is encoded in a way that is not human-readable, certain techniques could determine which encoding is being used, then decode t […]

## Mesures d'atténuation

- [Architecture and Design] Before transmitting, encrypt the data using reliable, confidentiality-protecting cryptographic protocols.
- [Implementation] When using web applications with SSL, use SSL for the entire session from login to logout, not just for the initial login page.
- [Implementation] When designing hardware platforms, ensure that approved encryption algorithms (such as those recommended by NIST) protect paths from security critical data to trusted user applications.
- [Testing] Use tools and techniques that require manual (human) analysis, such as penetration testing, threat modeling, and interactive tools that allow the tester to record and modify an active session. These may be more effective than strictly automated techniques. This is especially the case with weaknesses that are related to design and business rules.
- [Operation] Configure servers to use encrypted channels for communication, which may include SSL or other secure protocols.

---

# CWE-326 — Inadequate Encryption Strength

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/326.html)

## Description

The product stores or transmits sensitive data using an encryption scheme that is theoretically sound, but is not strong enough for the level of protection required.

A weak encryption scheme can be subjected to brute force attacks that have a reasonable chance of succeeding using current attack methods and resources.

## Conséquences

- Access Control, Confidentiality : Bypass Protection Mechanism, Read Application Data — An attacker may be able to decrypt the data using brute force attacks.

## Mesures d'atténuation

- [Architecture and Design] Use an encryption scheme that is currently considered to be strong by experts in the field.

---

# CWE-327 — Use of a Broken or Risky Cryptographic Algorithm

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/327.html)

## Description

The product uses a broken or risky cryptographic algorithm or protocol.

Cryptographic algorithms are the methods by which data is scrambled to prevent observation or influence by unauthorized actors. Insecure cryptography can be exploited to expose sensitive information, modify data in unexpected ways, spoof identities of other users or devices, or other impacts. It is very difficult to produce a secure algorithm, and even high-profile algorithms by accomplished cryptographic experts have been broken. Well-known techniques exist to break or weaken various kinds of cryptography. Accordingly, there are a small number of well-understood and heavily studied algorithms that should be used by most products. Using a non-standard or known-insecure algorithm is dangerous because a determined adversary may be able to break the algorithm and compromise whatever data has been protected. Since the state of cryptography advances so rapidly, it is common for an algorithm to be considered "unsafe" even if it was once thought to be strong. This can happen when new attacks are discovered, or if computing power increases so much that the cryptographic algorithm no longer provides the amount of protection that was originally thought. For a number of reasons, this weakness is even more challenging to manage with hardware deployment of cryptographic algorithms as opposed to software implementation. First, if a flaw is discovered with hardware-implemented cryptography, the flaw cannot be fixed in most cases without a recall of the product, because hardware is not easily replaceable like software. Second, because the hardware product is expected to work for years, the adversary's computing power will only increase over time.

## Conséquences

- Confidentiality : Read Application Data — The confidentiality of sensitive data may be compromised by the use of a broken or risky cryptographic algorithm.
- Integrity : Modify Application Data — The integrity of sensitive data may be compromised by the use of a broken or risky cryptographic algorithm.
- Accountability, Non-Repudiation : Hide Activities — If the cryptographic algorithm is used to ensure the identity of the source of the data (such as digital signatures), then a broken algorithm will compromise this scheme and the source of the data cannot be proven.

## Mesures d'atténuation

- [Architecture and Design] When there is a need to store or transmit sensitive data, use strong, up-to-date cryptographic algorithms to encrypt that data. Select a well-vetted algorithm that is currently considered to be strong by experts in the field, and use well-tested implementations. As with all cryptographic mechanisms, the source code should be available for analysis. For example, US government systems require FIPS 140-2 certification [REF-1192]. Do not develop custom or private cryptographic algorithms. They will likely be exposed to attacks that are well-understood by cryptographers. Reverse engineering techniques are mature. If the algorithm can be compromised if attackers find out how it works, then it is especially weak. Periodically ensure that the cryptography has not become obsolete. Some older algori […]
- [Architecture and Design] Ensure that the design allows one cryptographic algorithm to be replaced with another in the next generation or version. Where possible, use wrappers to make the interfaces uniform. This will make it easier to upgrade to stronger algorithms. With hardware, design the product at the Intellectual Property (IP) level so that one cryptographic algorithm can be replaced with another in the next generation of the hardware product.
- [Architecture and Design] Carefully manage and protect cryptographic keys (see CWE-320). If the keys can be guessed or stolen, then the strength of the cryptography itself is irrelevant.
- [Architecture and Design] Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid [REF-1482]. Industry-standard implementations will save development time and may be more likely to avoid errors that can occur during implementation of cryptographic algorithms. Consider the ESAPI Encryption feature.
- [Implementation, Architecture and Design] When using industry-approved techniques, use them correctly. Don't cut corners by skipping resource-intensive steps (CWE-325). These steps are often essential for preventing common attacks.

---

# CWE-345 — Insufficient Verification of Data Authenticity

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/345.html)

## Description

The product does not sufficiently verify the origin or authenticity of data, in a way that causes it to accept invalid data.

## Conséquences

- Integrity, Other : Varies by Context, Unexpected State

---

# CWE-346 — Origin Validation Error

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/346.html)

## Description

The product does not properly verify that the source of data or communication is valid.

## Conséquences

- Access Control, Other : Gain Privileges or Assume Identity, Varies by Context — An attacker can access any functionality that is inadvertently accessible to the source.

---

# CWE-350 — Reliance on Reverse DNS Resolution for a Security-Critical Action

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/350.html)

## Description

The product performs reverse DNS resolution on an IP address to obtain the hostname and make a security decision, but it does not properly ensure that the IP address is truly associated with the hostname.

Since DNS names can be easily spoofed or misreported, and it may be difficult for the product to detect if a trusted DNS server has been compromised, DNS names do not constitute a valid authentication mechanism. When the product performs a reverse DNS resolution for an IP address, if an attacker controls the DNS server for that IP address, then the attacker can cause the server to return an arbitrary hostname. As a result, the attacker may be able to bypass authentication, cause the wrong hostname to be recorded in log files to hide activities, or perform other attacks. Attackers can spoof DNS names by either (1) compromising a DNS server and modifying its records (sometimes called DNS cache poisoning), or (2) having legitimate control over a DNS server associated with their IP address.

## Conséquences

- Access Control : Gain Privileges or Assume Identity, Bypass Protection Mechanism — Malicious users can fake authentication information by providing false DNS information.

## Mesures d'atténuation

- [Architecture and Design] Use other means of identity verification that cannot be simply spoofed. Possibilities include a username/password or certificate.
- [Implementation] Perform proper forward and reverse DNS lookups to detect DNS spoofing.

---

# CWE-523 — Unprotected Transport of Credentials

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/523.html)

## Description

Login pages do not use adequate measures to protect the user name and password while they are in transit from the client to the server.

## Conséquences

- Access Control : Gain Privileges or Assume Identity

## Mesures d'atténuation

- [Operation, System Configuration] Enforce SSL use for the login page or any page used to transmit user credentials or other sensitive information. Even if the entire site does not use SSL, it MUST use SSL for login. Additionally, to help prevent phishing attacks, make sure that SSL serves the login page. SSL allows the user to verify the identity of the server to which they are connecting. If the SSL serves login page, the user can be certain they are talking to the proper end system. A phishing attack would typically redirect a user to a site that does not have a valid trusted server certificate issued from an authorized supplier.

---

# CWE-538 — Insertion of Sensitive Information into Externally-Accessible File or Directory

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/538.html)

## Description

The product places sensitive information into files or directories that are accessible to actors who are allowed to have access to the files, but not to the sensitive information.

## Conséquences

- Confidentiality : Read Files or Directories

## Mesures d'atténuation

- [Architecture and Design, Operation, System Configuration] Do not expose file and directory information to the user.

---

# CWE-548 — Exposure of Information Through Directory Listing

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/548.html)

## Description

The product inappropriately exposes a directory listing with an index of all the resources located inside of the directory.

## Conséquences

- Confidentiality : Read Files or Directories — Exposing the contents of a directory can lead to an attacker gaining access to source code or providing useful information for the attacker to devise exploits, such as creation times of files or any information that may be encoded in file names. The directory listing may also compromise private or confidential data.

## Mesures d'atténuation

- [Architecture and Design, System Configuration] Recommendations include restricting access to important directories or files by adopting a need to know requirement for both the document and server root, and turning off features such as Automatic Directory Listings that could expose private files and provide information that could be utilized by an attacker when formulating or conducting an attack.

---

# CWE-601 — URL Redirection to Untrusted Site ('Open Redirect')

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/601.html)

## Description

The web application accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect.

## Conséquences

- Access Control : Bypass Protection Mechanism, Gain Privileges or Assume Identity — The user may be redirected to an untrusted page
that contains malware which may then compromise the
user's system. In some cases, an open redirect can also
enable the immediate download of a file without the
user's permission, because the redirection to an
external site may lead to endpoints on those sites that
automatically trigger a download action ("drive-by
download" [REF-1478]). This will exp […]
- Access Control, Confidentiality, Other : Bypass Protection Mechanism, Gain Privileges or Assume Identity, Other — By modifying the URL value to a malicious site, an attacker may successfully launch a phishing scam. The user may be subjected to phishing attacks by being redirected to an untrusted page. The phishing attack may point to an attacker controlled web page that appears to be a trusted web site. The phishers may then steal the user's credentials and then use these credentials to access the legitimate […]

## Mesures d'atténuation

- [Implementation] Assume all input is malicious. Use an "accept known good" input validation strategy, i.e., use a list of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications, or transform it into something that does. When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules. As an example of business rule logic, "boat" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as "red" or "blue." Do not rely exclusively on looking for malicious or malform […]
- [Architecture and Design] Use an intermediate disclaimer page that provides the user with a clear warning that they are leaving the current site. Implement a long timeout before the redirect occurs, or force the user to click on the link. Be careful to avoid XSS problems (CWE-79) when generating the disclaimer page.
- [Architecture and Design] When the set of acceptable objects, such as filenames or URLs, is limited or known, create a mapping from a set of fixed input values (such as numeric IDs) to the actual filenames or URLs, and reject all other inputs. For example, ID 1 could map to "/login.asp" and ID 2 could map to "http://www.example.com/". Features such as the ESAPI AccessReferenceMap [REF-45] provide this capability.
- [Architecture and Design] Ensure that no externally-supplied requests are honored by requiring that all redirect requests include a unique nonce generated by the application [REF-483]. Be sure that the nonce is not predictable (CWE-330).
- [Architecture and Design, Implementation] Understand all the potential areas where untrusted inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, filenames, databases, and any external systems that provide data to the application. Remember that such inputs may be obtained indirectly through API calls. Many open redirect problems occur because the programmer assumed that certain inputs could not be modified, such as cookies and hidden form fields.
- [Operation] Use an application firewall that can detect attacks against this weakness. It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth [REF-1481].

---

# CWE-614 — Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/614.html)

## Description

The Secure attribute for sensitive cookies in HTTPS sessions is not set.

## Conséquences

- Confidentiality : Read Application Data — Omitting the secure flag makes it possible for the user agent to send the cookies in plaintext over an HTTP session.

## Mesures d'atténuation

- [Implementation] Always set the secure attribute when the cookie should be sent via HTTPS only.

---

# CWE-668 — Exposure of Resource to Wrong Sphere

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/668.html)

## Description

The product exposes a resource to the wrong control sphere, providing unintended actors with inappropriate access to the resource.

Resources such as files and directories may be inadvertently exposed through mechanisms such as insecure permissions, or when a program accidentally operates on the wrong object. For example, a program may intend that private files can only be provided to a specific user. This effectively defines a control sphere that is intended to prevent attackers from accessing these private files. If the file permissions are insecure, then parties other than the user will be able to access those files. A separate control sphere might effectively require that the user can only access the private files, but not any other files on the system. If the program does not ensure that the user is only requesting private files, then the user might be able to access other files on the system. In either case, the end result is that a resource has been exposed to the wrong party.

## Conséquences

- Confidentiality : Read Application Data — An adversary that gains access to a resource exposed to a wrong sphere could potentially retrieve private data from that resource, thus breaking the intended confidentiality of that data.
- Integrity : Modify Application Data — An adversary that gains access to a resource exposed to a wrong sphere could potentially modify data held within that resource, thus breaking the intended integrity of that data and causing the system relying on that resource to make unintended decisions.
- Other : Varies by Context — The consequences may vary widely depending on how the product uses the affected resource.

---

# CWE-693 — Protection Mechanism Failure

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/693.html)

## Description

The product does not use or incorrectly uses a protection mechanism that provides sufficient defense against directed attacks against the product.

This weakness covers three distinct situations. A "missing" protection mechanism occurs when the application does not define any mechanism against a certain class of attack. An "insufficient" protection mechanism might provide some defenses - for example, against the most common attacks - but it does not protect against everything that is intended. Finally, an "ignored" mechanism occurs when a mechanism is available and in active use within the product, but the developer has not applied it in some code path.

## Conséquences

- Access Control : Bypass Protection Mechanism

---

# CWE-757 — Selection of Less-Secure Algorithm During Negotiation ('Algorithm Downgrade')

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/757.html)

## Description

A protocol or its implementation supports interaction between multiple actors and allows those actors to negotiate which algorithm should be used as a protection mechanism such as encryption or authentication, but it does not select the strongest algorithm that is available to both parties.

When a security mechanism can be forced to downgrade to use a less secure algorithm, this can make it easier for attackers to compromise the product by exploiting weaker algorithm. The victim might not be aware that the less secure algorithm is being used. For example, if an attacker can force a communications channel to use cleartext instead of strongly-encrypted data, then the attacker could read the channel by sniffing, instead of going through extra effort of trying to decrypt the data using brute force techniques.

## Conséquences

- Access Control : Bypass Protection Mechanism

---

# CWE-798 — Use of Hard-coded Credentials

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/798.html)

## Description

The product contains hard-coded credentials, such as a password or cryptographic key.

There are two main variations: Inbound: the product contains an authentication mechanism that checks the input credentials against a hard-coded set of credentials. In this variant, a default administration account is created, and a simple password is hard-coded into the product and associated with that account. This hard-coded password is the same for each installation of the product, and it usually cannot be changed or disabled by system administrators without manually modifying the program, or otherwise patching the product. It can also be difficult for the administrator to detect. Outbound: the product connects to another system or component, and it contains hard-coded credentials for connecting to that component. This variant applies to front-end systems that authenticate with a back-end service. The back-end service may require a fixed password that can be easily discovered. The programmer may simply hard-code those back-end credentials into the front-end product.

## Conséquences

- Access Control : Bypass Protection Mechanism — If hard-coded passwords are used, it is almost certain that malicious users will gain access to the account in question. Any user of the product that hard-codes passwords may be able to extract the password. Client-side systems with hard-coded passwords pose even more of a threat, since the extraction of a password from a binary is usually very simple.
- Integrity, Confidentiality, Availability, Access Control, Other : Read Application Data, Gain Privileges or Assume Identity, Execute Unauthorized Code or Commands, Other — This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code. If the password is ever discovered or published (a common occurrence on the Internet), then anybody with knowledge of this password can access the product. Finally, since all installations of the product will have the sam […]

## Mesures d'atténuation

- [Architecture and Design] For outbound authentication: store passwords, keys, and other credentials outside of the code in a strongly-protected, encrypted configuration file or database that is protected from access by all outsiders, including other local users on the same system. Properly protect the key (CWE-320). If you cannot use encryption to protect the file, then make sure that the permissions are as restrictive as possible [REF-7]. In Windows environments, the Encrypted File System (EFS) may provide some protection.
- [Architecture and Design] For inbound authentication: Rather than hard-code a default username and password, key, or other authentication credentials for first time logins, utilize a "first login" mode that requires the user to enter a unique strong password or key.
- [Architecture and Design] If the product must contain hard-coded credentials or they cannot be removed, perform access control checks and limit which entities can access the feature that requires the hard-coded credentials. For example, a feature might only be enabled through the system console instead of through a network connection.
- [Architecture and Design] For inbound authentication using passwords: apply strong one-way hashes to passwords and store those hashes in a configuration file or database with appropriate access control. That way, theft of the file/database still requires the attacker to try to crack the password. When handling an incoming password during authentication, take the hash of the password and compare it to the saved hash. Use randomly assigned salts for each separate hash that is generated. This increases the amount of computation that an attacker needs to conduct a brute-force attack, possibly limiting the effectiveness of the rainbow table method.
- [Architecture and Design] For front-end to back-end connections: Three solutions are possible, although none are complete. The first suggestion involves the use of generated passwords or keys that are changed automatically and must be entered at given time intervals by a system administrator. These passwords will be held in memory and only be valid for the time intervals. Next, the passwords or keys should be limited at the back end to only performing actions valid for the front end, as opposed to having full access. Finally, the messages sent should be tagged and checksummed with time sensitive values so as to prevent replay-style attacks.

---

# CWE-942 — Permissive Cross-domain Security Policy with Untrusted Domains

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/942.html)

## Description

The product uses a web-client protection
mechanism such as a Content Security Policy (CSP) or
cross-domain policy file, but the policy includes untrusted
domains with which the web client is allowed to
communicate.

If a cross-domain policy file includes domains
that should not be trusted, such as when using wildcards
under a high-level domain, then the application could be
attacked by these untrusted domains. In many cases, the
attack can be launched without the victim even being aware
of it.

## Conséquences

- Confidentiality, Integrity, Availability, Access Control : Execute Unauthorized Code or Commands, Bypass Protection Mechanism, Read Application Data, Varies by Context — With an overly permissive policy file, an attacker may be able to bypass the web browser's same-origin policy and conduct many of the same attacks seen in Cross-Site Scripting (CWE-79). An attacker can exploit the weakness to transfer private information from the victim's machine to the attacker, manipulate or steal cookies that may include session information, create malicious requests to a web s […]

## Mesures d'atténuation

- [Architecture and Design, Operation] Define a restrictive Content Security Policy [REF-1486] or cross-domain policy file.
- [Architecture and Design, Operation] Avoid using wildcards in the CSP / cross-domain policy file. Any domain matching the wildcard expression will be implicitly trusted, and can perform two-way interaction with the target server.
- [Architecture and Design, Operation] For Flash, modify crossdomain.xml to use meta-policy options such as 'master-only' or 'none' to reduce the possibility of an attacker planting extraneous cross-domain policy files on a server.

---

# CWE-1004 — Sensitive Cookie Without 'HttpOnly' Flag

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/1004.html)

## Description

The product uses a cookie to store sensitive information, but the cookie is not marked with the HttpOnly flag.

## Conséquences

- Confidentiality : Read Application Data — If the HttpOnly flag is not set, then sensitive information stored in the cookie may be exposed to unintended parties.
- Integrity : Gain Privileges or Assume Identity — If the cookie in question is an authentication cookie, then not setting the HttpOnly flag may allow an adversary to steal authentication data (e.g., a session ID) and assume the identity of the user.

## Mesures d'atténuation

- [Implementation] Leverage the HttpOnly flag when setting a sensitive cookie in a response.

---

# CWE-1021 — Improper Restriction of Rendered UI Layers or Frames

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/1021.html)

## Description

The web application does not restrict or incorrectly restricts frame objects or UI layers that belong to another application or domain.

## Conséquences

- Access Control : Gain Privileges or Assume Identity, Bypass Protection Mechanism, Read Application Data, Modify Application Data — An attacker can trick a user into performing actions that are masked and hidden from the user's view. The impact varies widely, depending on the functionality of the underlying application. For example, in a social media application, clickjacking could be used to trick the user into changing privacy settings.

## Mesures d'atténuation

- [Implementation] The use of X-Frame-Options allows developers of web content to restrict the usage of their application within the form of overlays, frames, or iFrames. The developer can indicate from which domains can frame the content. The concept of X-Frame-Options is well documented, but implementation of this protection mechanism is in development to cover gaps. There is a need for allowing frames from multiple domains.
- [Implementation] A developer can use a "frame-breaker" script in each page that should not be framed. This is very helpful for legacy browsers that do not support X-Frame-Options security feature previously mentioned. It is also important to note that this tactic has been circumvented or bypassed. Improper usage of frames can persist in the web application through nested frames. The "frame-breaking" script does not intuitively account for multiple nested frames that can be presented to the user.
- [Implementation] This defense-in-depth technique can be used to prevent the improper usage of frames in web applications. It prioritizes the valid sources of data to be loaded into the application through the usage of declarative policies. Based on which implementation of Content Security Policy is in use, the developer should use the "frame-ancestors" directive or the "frame-src" directive to mitigate this weakness. Both directives allow for the placement of restrictions when it comes to allowing embedded content.
- [Implementation] In addition to frames or iframes as previously mentioned, the web application is expected to place restrictions on whether it is allowed to be rendered within objects, embed, or applet elements.

---

# CWE-1104 — Use of Unmaintained Third Party Components

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/1104.html)

## Description

The product relies on third-party components that are not
actively supported or maintained by the original developer or a trusted proxy
for the original developer.

## Conséquences

- Other : Reduce Maintainability, Varies by Context — Relying on unmaintained components makes it difficult or impossible to fix significant bugs and vulnerabilities, can render code obsolete, and undermine security by complicating maintenance and increasing the risk of new vulnerabilities.

---

# CWE-1275 — Sensitive Cookie with Improper SameSite Attribute

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/1275.html)

## Description

The SameSite attribute for sensitive cookies is not set, or an insecure value is used.

The SameSite attribute controls how cookies are sent for cross-domain requests. This attribute may have three values: 'Lax', 'Strict', or 'None'. If the 'None' value is used, a website may create a cross-domain POST HTTP request to another website, and the browser automatically adds cookies to this request. This may lead to Cross-Site-Request-Forgery (CSRF) attacks if there are no additional protections in place (such as Anti-CSRF tokens).

## Conséquences

- Confidentiality, Integrity, Non-Repudiation, Access Control : Modify Application Data — If the website does not impose additional defense against CSRF attacks, failing to use the 'Lax' or 'Strict' values could increase the risk of exposure to CSRF attacks. The likelihood of the integrity breach is Low because a successful attack does not only depend on an insecure SameSite attribute. In order to perform a CSRF attack there are many conditions that must be met, such as the lack of CSR […]

## Mesures d'atténuation

- [Implementation] Set the SameSite attribute of a sensitive cookie to 'Lax' or 'Strict'. This instructs the browser to apply this cookie only to same-domain requests, which provides a good Defense in Depth against CSRF attacks. When the 'Lax' value is in use, cookies are also sent for top-level cross-domain navigation via HTTP GET, HEAD, OPTIONS, and TRACE methods, but not for other HTTP methods that are more like to cause side-effects of state mutation.

---

# CWE-1395 — Dependency on Vulnerable Third-Party Component

Source : MITRE CWE (https://cwe.mitre.org/data/definitions/1395.html)

## Description

The product has a dependency on a third-party component that contains one or more known vulnerabilities.

Many products are large enough or complex enough that part of their functionality uses libraries, modules, or other intellectual property developed by third parties who are not the product creator. For example, even an entire operating system might be from a third-party supplier in some hardware products. Whether open or closed source, these components may contain publicly known vulnerabilities or hidden functionality such as malware that could be exploited by adversaries to compromise the product.

## Conséquences

- Confidentiality, Integrity, Availability : Varies by Context — The consequences vary widely, depending on the vulnerabilities that exist in the component; how those vulnerabilities can be "reached" by adversaries, as the exploitation paths and attack surface will vary depending on how the component is used; and the criticality of the privilege levels and features for which the product relies on the component.

## Mesures d'atténuation

- [Requirements, Policy] In some industries such as healthcare [REF-1320] [REF-1322] or technologies such as the cloud [REF-1321], it might be unclear about who is responsible for applying patches for third-party vulnerabilities: the vendor, the operator/customer, or a separate service. Clarifying roles and responsibilities can be important to minimize confusion or unnecessary delay when third-party vulnerabilities are disclosed.
- [Requirements] Require a Bill of Materials for all components and sub-components of the product. For software, require a Software Bill of Materials (SBOM) [REF-1247] [REF-1311].
- [Architecture and Design, Implementation, Integration, Manufacturing] Maintain a Bill of Materials for all components and sub-components of the product. For software, maintain a Software Bill of Materials (SBOM). According to [REF-1247], "An SBOM is a formal, machine-readable inventory of software components and dependencies, information about those components, and their hierarchical relationships."
- [Operation, Patching and Maintenance] Actively monitor when a third-party component vendor announces vulnerability patches; fix the third-party component as soon as possible; and make it easy for operators/customers to obtain and apply the patch.
- [Operation, Patching and Maintenance] Continuously monitor changes in each of the product's components, especially when the changes indicate new vulnerabilities, end-of-life (EOL) plans, etc.

---

# CAPEC-89 — Pharming

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/89.html)

- Probabilité d'attaque : High
- Sévérité typique : Very High

## Description

A pharming attack occurs when the victim is fooled into entering sensitive data into supposedly trusted locations, such as an online bank site or a trading platform. An attacker can impersonate these supposedly trusted sites and have the victim be directed to their site rather than the originally intended one. Pharming does not require script injection or clicking on malicious links for the attack to succeed.

## Prérequis

- Vulnerable DNS software or improperly protected hosts file or router that can be poisoned
- A website that handles sensitive information but does not use a secure connection and a certificate that is valid is also prone to pharming

## Mesures d'atténuation

- All sensitive information must be handled over a secure connection.
- Known vulnerabilities in DNS or router software or in operating systems must be patched as soon as a fix has been released and tested.
- End users must ensure that they provide sensitive information only to websites that they trust, over a secure connection with a valid certificate issued by a well-known certificate authority.

Faiblesses liées : CWE-346, CWE-350

---

# CAPEC-94 — Adversary in the Middle (AiTM)

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/94.html)

- Probabilité d'attaque : High
- Sévérité typique : Very High

## Description

An adversary targets the communication between two components (typically client and server), in order to alter or obtain data from transactions. A general approach entails the adversary placing themself within the communication channel between the two components.

## Prérequis

- There are two components communicating with each other.
- An attacker is able to identify the nature and mechanism of communication between the two target components.
- An attacker can eavesdrop on the communication between the target components.
- Strong mutual authentication is not used between the two target components yielding opportunity for attacker interposition.
- The communication occurs in clear (not encrypted) or with insufficient and spoofable encryption.

## Mesures d'atténuation

- Ensure Public Keys are signed by a Certificate Authority
- Encrypt communications using cryptography (e.g., SSL/TLS)
- Use Strong mutual authentication to always fully authenticate both ends of any communications channel.
- Exchange public keys using a secure channel

Faiblesses liées : CWE-300, CWE-290, CWE-593, CWE-287, CWE-294

---

# CAPEC-98 — Phishing

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/98.html)

- Probabilité d'attaque : High
- Sévérité typique : Very High

## Description

Phishing is a social engineering technique where an attacker masquerades as a legitimate entity with which the victim might do business in order to prompt the user to reveal some confidential information (very frequently authentication credentials) that can later be used by an attacker. Phishing is essentially a form of information gathering or "fishing" for information.

## Prérequis

- An attacker needs to have a way to initiate contact with the victim. Typically that will happen through e-mail.
- An attacker needs to correctly guess the entity with which the victim does business and impersonate it. Most of the time phishers just use the most popular banks/services and send out their "hooks" to many potential victims.
- An attacker needs to have a sufficiently compelling call to action to prompt the user to take action.
- The replicated website needs to look extremely similar to the original website and the URL used to get to that website needs to look like the real URL of the said business entity.

## Mesures d'atténuation

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also be to type the URL of your bank in the browser directly and only then log in. Also, never reply to any e-mails that ask you to provide sensitive information of any kind.

Faiblesses liées : CWE-451

---

# CAPEC-103 — Clickjacking

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/103.html)

- Probabilité d'attaque : Medium
- Sévérité typique : High

## Description

An adversary tricks a victim into unknowingly initiating some action in one system while interacting with the UI from a seemingly completely different, usually an adversary controlled or intended, system.

## Prérequis

- The victim is communicating with the target application via a web based UI and not a thick client
- The victim's browser security policies allow at least one of the following JavaScript, Flash, iFrames, ActiveX, or CSS.
- The victim uses a modern browser that supports UI elements like clickable buttons (i.e. not using an old text only browser)
- The victim has an active session with the target system.
- The target system's interaction window is open in the victim's browser and supports the ability for initiating sensitive actions on behalf of the user in the target system

## Mesures d'atténuation

- If using the Firefox browser, use the NoScript plug-in that will help forbid iFrames.
- Turn off JavaScript, Flash and disable CSS.
- When maintaining an authenticated session with a privileged target system, do not use the same browser to navigate to unfamiliar sites to perform other activities. Finish working with the target system and logout first before proceeding to other tasks.

Faiblesses liées : CWE-1021

---

# CAPEC-141 — Cache Poisoning

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/141.html)

- Probabilité d'attaque : High
- Sévérité typique : High

## Description

An attacker exploits the functionality of cache technologies to cause specific data to be cached that aids the attackers' objectives. This describes any attack whereby an attacker places incorrect or harmful material in cache. The targeted cache can be an application's cache (e.g. a web browser cache) or a public cache (e.g. a DNS or ARP cache). Until the cache is refreshed, most applications or clients will treat the corrupted cache value as valid. This can lead to a wide range of exploits including redirecting web browsers towards sites that install malware and repeatedly incorrect calculations based on the incorrect value.

## Prérequis

- The attacker must be able to modify the value stored in a cache to match a desired value.
- The targeted application must not be able to detect the illicit modification of the cache and must trust the cache value in its calculations.

## Mesures d'atténuation

- Configuration: Disable client side caching.
- Implementation: Listens for query replies on a network, and sends a notification via email when an entry changes.

Faiblesses liées : CWE-348, CWE-345, CWE-349, CWE-346

---

# CAPEC-142 — DNS Cache Poisoning

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/142.html)

- Probabilité d'attaque : High
- Sévérité typique : High

## Description

A domain name server translates a domain name (such as www.example.com) into an IP address that Internet hosts use to contact Internet resources. An adversary modifies a public DNS cache to cause certain names to resolve to incorrect addresses that the adversary specifies. The result is that client applications that rely upon the targeted cache for domain name resolution will be directed not to the actual address of the specified domain name but to some other address. Adversaries can use this to herd clients to sites that install malware on the victim's computer or to masquerade as part of a Pharming attack.

## Prérequis

- A DNS cache must be vulnerable to some attack that allows the adversary to replace addresses in its lookup table.Client applications must trust the corrupted cashed values and utilize them for their domain name resolutions.

## Mesures d'atténuation

- Configuration: Make sure your DNS servers have been updated to the latest versions
- Configuration: UNIX services like rlogin, rsh/rcp, xhost, and nfs are all susceptible to wrong information being held in a cache. Care should be taken with these services so they do not rely upon DNS caches that have been exposed to the Internet.
- Configuration: Disable client side DNS caching.

Faiblesses liées : CWE-348, CWE-345, CWE-349, CWE-346, CWE-350

---

# CAPEC-157 — Sniffing Attacks

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/157.html)

- Sévérité typique : Medium

## Description

In this attack pattern, the adversary intercepts information transmitted between two third parties. The adversary must be able to observe, read, and/or hear the communication traffic, but not necessarily block the communication or change its content. Any transmission medium can theoretically be sniffed if the adversary can examine the contents between the sender and recipient. Sniffing Attacks are similar to Adversary-In-The-Middle attacks (CAPEC-94), but are entirely passive. AiTM attacks are predominantly active and often alter the content of the communications themselves.

## Prérequis

- The target data stream must be transmitted on a medium to which the adversary has access.

## Mesures d'atténuation

- Encrypt sensitive information when transmitted on insecure mediums to prevent interception.

Faiblesses liées : CWE-311

---

# CAPEC-163 — Spear Phishing

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/163.html)

- Probabilité d'attaque : High
- Sévérité typique : High

## Description

An adversary targets a specific user or group with a Phishing (CAPEC-98) attack tailored to a category of users in order to have maximum relevance and deceptive capability. Spear Phishing is an enhanced version of the Phishing attack targeted to a specific user or group. The quality of the targeted email is usually enhanced by appearing to come from a known or trusted entity. If the email account of some trusted entity has been compromised the message may be digitally signed. The message will contain information specific to the targeted users that will enhance the probability that they will follow the URL to the compromised site. For example, the message may indicate knowledge of the targets employment, residence, interests, or other information that suggests familiarity. As soon as the user follows the instructions in the message, the attack proceeds as a standard Phishing attack.

## Prérequis

- None. Any user can be targeted by a Spear Phishing attack.

## Mesures d'atténuation

- Do not follow any links that you receive within your e-mails and certainly do not input any login credentials on the page that they take you too. Instead, call your Bank, PayPal, eBay, etc., and inquire about the problem. A safe practice would also be to type the URL of your bank in the browser directly and only then log in. Also, never reply to any e-mails that ask you to provide sensitive information of any kind.

Faiblesses liées : CWE-451

---

# CAPEC-169 — Footprinting

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/169.html)

- Probabilité d'attaque : High
- Sévérité typique : Very Low

## Description

An adversary engages in probing and exploration activities to identify constituents and properties of the target.

## Prérequis

- An application must publicize identifiable information about the system or application through voluntary or involuntary means. Certain identification details of information systems are visible on communication networks (e.g., if an adversary uses a sniffer to inspect the traffic) due to their inherent structure and protocol standards. Any system or network that can be detected can be footprinted. However, some configuration choices may limit the useful information that can be collected during a […]

## Mesures d'atténuation

- Keep patches up to date by installing weekly or daily if possible.
- Shut down unnecessary services/ports.
- Change default passwords by choosing strong passwords.
- Curtail unexpected input.
- Encrypt and password-protect sensitive data.
- Avoid including information that has the potential to identify and compromise your organization's security such as access to business plans, formulas, and proprietary documents.

Faiblesses liées : CWE-200

---

# CAPEC-194 — Fake the Source of Data

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/194.html)

- Sévérité typique : Medium

## Description

An adversary takes advantage of improper authentication to provide data or services under a falsified identity. The purpose of using the falsified identity may be to prevent traceability of the provided data or to assume the rights granted to another individual. One of the simplest forms of this attack would be the creation of an email message with a modified "From" field in order to appear that the message was sent from someone other than the actual sender. The root of the attack (in this case the email system) fails to properly authenticate the source and this results in the reader incorrectly performing the instructed action. Results of the attack vary depending on the details of the attack, but common results include privilege escalation, obfuscation of other attacks, and data corruption/manipulation.

## Prérequis

- This attack is only applicable when a vulnerable entity associates data or services with an identity. Without such an association, there would be no reason to fake the source.

Faiblesses liées : CWE-287

---

# CAPEC-217 — Exploiting Incorrectly Configured SSL/TLS

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/217.html)

- Probabilité d'attaque : Low

## Description

An adversary takes advantage of incorrectly configured SSL/TLS communications that enables access to data intended to be encrypted. The adversary may also use this type of attack to inject commands or other traffic into the encrypted stream to cause compromise of either the client or server.

## Prérequis

- Access to the client/server stream.

## Mesures d'atténuation

- Do not use SSL, as all SSL versions have been broken and should not be used. If TLS is not an option for the client or server, consider setting timeouts on SSL sessions to extremely low values to lessen the potential impact.
- Only use TLS version 1.2+, as versions 1.0 and 1.1 are insecure.
- Configure TLS to use secure algorithms. The current recommendation is to use ECDH, ECDSA, AES256-GCM, and SHA384 for the most security.

Faiblesses liées : CWE-201

---

# CAPEC-300 — Port Scanning

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/300.html)

- Sévérité typique : Low

## Description

An adversary uses a combination of techniques to determine the state of the ports on a remote target. Any service or application available for TCP or UDP networking will have a port open for communications over the network.

## Prérequis

- The adversary requires logical access to the target's network in order to carry out this type of attack.

Faiblesses liées : CWE-200

---

# CAPEC-459 — Creating a Rogue Certification Authority Certificate

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/459.html)

- Probabilité d'attaque : Medium
- Sévérité typique : Very High

## Description

An adversary exploits a weakness resulting from using a hashing algorithm with weak collision resistance to generate certificate signing requests (CSR) that contain collision blocks in their "to be signed" parts. The adversary submits one CSR to be signed by a trusted certificate authority then uses the signed blob to make a second certificate appear signed by said certificate authority. Due to the hash collision, both certificates, though different, hash to the same value and so the signed blob works just as well in the second certificate. The net effect is that the adversary's second X.509 certificate, which the Certification Authority has never seen, is now signed and validated by that Certification Authority.

## Prérequis

- Certification Authority is using a hash function with insufficient collision resistance to generate the certificate hash to be signed

## Mesures d'atténuation

- Certification Authorities need to stop using deprecated or cryptographically insecure hashing algorithms to hash the certificates that they are about to sign. Instead they should be using stronger hashing functions such as SHA-256 or SHA-512.

Faiblesses liées : CWE-327, CWE-295, CWE-290

---

# CAPEC-543 — Counterfeit Websites

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/543.html)

- Sévérité typique : High

## Description

Adversary creates duplicates of legitimate websites. When users visit a counterfeit site, the site can gather information or upload malware.

## Prérequis

- None

---

# CAPEC-600 — Credential Stuffing

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/600.html)

- Probabilité d'attaque : High
- Sévérité typique : High

## Description

An adversary tries known username/password combinations against different systems, applications, or services to gain additional authenticated access. Credential Stuffing attacks rely upon the fact that many users leverage the same username/password combination for multiple systems, applications, and services.

## Prérequis

- The system/application uses one factor password based authentication, SSO, and/or cloud-based authentication.
- The system/application does not have a sound password policy that is being enforced.
- The system/application does not implement an effective password throttling mechanism.
- The adversary possesses a list of known user accounts and corresponding passwords that may exist on the target.

## Mesures d'atténuation

- Leverage multi-factor authentication for all authentication services and prior to granting an entity access to the domain network.
- Create a strong password policy and ensure that your system enforces this policy.
- Ensure users are not reusing username/password combinations for multiple systems, applications, or services.
- Do not reuse local administrator account credentials across systems.
- Deny remote use of local admin credentials to log into domain systems.
- Do not allow accounts to be a local administrator on more than one system.

Faiblesses liées : CWE-522, CWE-307, CWE-308, CWE-309, CWE-262, CWE-263, CWE-654

---

# CAPEC-620 — Drop Encryption Level

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/620.html)

- Sévérité typique : High

## Description

An attacker forces the encryption level to be lowered, thus enabling a successful attack against the encrypted data.

Faiblesses liées : CWE-757

---

# CAPEC-630 — TypoSquatting

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/630.html)

- Probabilité d'attaque : Low
- Sévérité typique : Medium

## Description

An adversary registers a domain name with at least one character different than a trusted domain. A TypoSquatting attack takes advantage of instances where a user mistypes a URL (e.g. www.goggle.com) or not does visually verify a URL before clicking on it (e.g. phishing attack). As a result, the user is directed to an adversary-controlled destination. TypoSquatting does not require an attack against the trusted domain or complicated reverse engineering.

## Prérequis

- An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.

## Mesures d'atténuation

- Authenticate all servers and perform redundant checks when using DNS hostnames.
- Purchase potential TypoSquatted domains and forward to legitimate domain.

---

# CAPEC-631 — SoundSquatting

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/631.html)

- Probabilité d'attaque : Low
- Sévérité typique : Medium

## Description

An adversary registers a domain name that sounds the same as a trusted domain, but has a different spelling. A SoundSquatting attack takes advantage of a user's confusion of the two words to direct Internet traffic to adversary-controlled destinations. SoundSquatting does not require an attack against the trusted domain or complicated reverse engineering.

## Prérequis

- An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.

## Mesures d'atténuation

- Authenticate all servers and perform redundant checks when using DNS hostnames.
- Purchase potential SoundSquatted domains and forward to legitimate domain.

---

# CAPEC-632 — Homograph Attack via Homoglyphs

Source : MITRE CAPEC (https://capec.mitre.org/data/definitions/632.html)

- Probabilité d'attaque : Low
- Sévérité typique : Medium

## Description

An adversary registers a domain name containing a homoglyph, leading the registered domain to appear the same as a trusted domain. A homograph attack leverages the fact that different characters among various character sets look the same to the user. Homograph attacks must generally be combined with other attacks, such as phishing attacks, in order to direct Internet traffic to the adversary-controlled destinations.

## Prérequis

- An adversary requires knowledge of popular or high traffic domains, that could be used to deceive potential targets.

## Mesures d'atténuation

- Authenticate all servers and perform redundant checks when using DNS hostnames.
- Utilize browsers that can warn users if URLs contain characters from different character sets.

Faiblesses liées : CWE-1007

