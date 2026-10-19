# CISA AA26-281A — Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data

Source : CISA, avis de cybersécurité AA26-281A (Tue, 06 Oct 2026 12:22:53 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-281a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Advisory at a Glance

Title

Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data

Original Publication

October 8, 2026

Executive Summary

Chinese government-linked cyber threat actors, enabled by the Integrity Technology Group, are combining automated scanning tools, large-scale botnets, and hands-on exploitation techniques to target and steal sensitive data from organizations worldwide, including US critical infrastructure sectors. These actors exploit vulnerabilities by using scanning tools, cross-site scripting attacks, and password spraying on Microsoft Exchange servers, while establishing persistence through VPN software and exfiltrating emails and credentials using scripts. To help mitigate against this activity, organizations should prioritize disabling unused services and ports, sanitizing web application inputs to prevent injection attacks, implementing multifactor authentication for all services, and applying timely patches to reduce risks of compromise.

Affected Products

CVE-2014-6278

CVE-2015-3306

CVE-2015-5477

CVE-2016-3081

CVE-2019-11510

CVE-2021-22205

CVE-2021-3199

CVE-2023-22894

Key Actions

Disable unused services and ports, such as automatic configuration, remote access, or file sharing protocols.

Sanitize user input in web applications to prevent possible cross-site scripting (XSS) payload injection.

Implement identity, credential, and access management (ICAM) policies, and then require multifactor authentication (MFA) for services (to the extent possible).

Indicators of Compromise

For a downloadable copy of indicators of compromise, see:

AA26-281A STIX XML

AA26-281A STIX JSON

Intended Audience

Organizations: Government; Federal Civilian Executive Branch (FCEB); State, Local, Tribal, and Territorial (SLTT); Critical Infrastructure.

Sectors: Government Services and Facilities, Critical Manufacturing, Healthcare and Public Health, and Information Technology.

Roles: Defensive Cybersecurity Analysts, Vulnerability Analysts, Security Systems Managers, Incident Response Analysts

Introduction

Integrity Technology Group, a China-based company with links to the Chinese government, enables China-linked threat actors to exploit US and foreign organization networks across multiple sectors using various tools and techniques. This advisory provides an analysis of tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) from Integrity Technology Group and the threat actors they enable (hereafter referred to as “the threat actors”). The analysis in this advisory provides network defenders with detection and mitigation guidance to reduce the risk of threat actors compromising critical data.

The threat actors use a unique combination of large-scale botnets, virtual private network (VPN) infrastructure, living-off-the-land (LOTL) techniques, and repositories of computer network exploitation (CNE) tools. Although these techniques are not unique to Chinese threat actors, this advisory details how the threat actors use them to support CNE activity.

The threat actors targeted victims across multiple US critical infrastructure sectors, including: Government Services and Facilities, Critical Manufacturing, Healthcare and Public Health, and Information Technology. The actors also targeted victims in US law enforcement, education, and religious organizations, as well as organizations across Southeast Asia, Africa, and North America.

The information in this advisory originates from technical evidence recovered from, and observed during, multiple Federal Bureau of Investigation (FBI) investigations related to Integrity Technology Group.

The FBI, Cybersecurity and Infrastructure Security Agency (CISA), National Security Agency (NSA), United Kingdom National Cyber Security Centre (NCSC-UK), Australian Signals Directorate’s Australian Cyber Security Centre (ASD’s ACSC), the Canadian Centre for Cyber Security (Cyber Centre), Japan’s National Police Agency (NPA) and National Cybersecurity Office (NCO), New Zealand’s National Cyber Security Centre (NCSC-NZ), and Spain’s Centro Nacional de Inteligencia (CNI), hereafter referred to as “the authoring organizations”—are releasing this joint cybersecurity advisory to urge network defenders from government and relevant organizations to:

Hunt for potential compromises from this activity.

Better protect against this threat activity and other Chinese government-linked cyber targeting.

This advisory also provides our US federal, state, local, territorial, and tribal (FSLTT) government agencies, and international and industry partners, with the indicators and details necessary to proactively defend their networks against this threat and protect critical data.

For more information on People’s Republic of China (PRC) state-sponsored malicious cyber activity in general, see the FBI’s Cyber Threat Overview: China webpage. For more information on China-linked malicious cyber activity, see CISA’s People’s Republic of China Threat Overview and Advisories webpage.

The authoring organizations encourage network defenders to implement the recommendations in the Mitigations section of this advisory to reduce the likelihood and impact of these incidents.

Download the PDF version of this report:

Chinese Government-linked Cyber Threat Actors Combine Automated and Hands-on Hacking Tools to Steal Sensitive Data
(PDF, 1.41 MB
)

For a downloadable copy of IOCs, see:

AA26-281A STIX
(JSON, 1,021.16 KB
)

AA26-281A STIX XML
(XML, 658.87 KB
)

Threat Actor Background

Integrity Technology Group (Integrity Tech) is a China-based for-profit company with links to the Chinese government. Integrity Tech employs individuals who support malicious cyber activity in different ways, including acquiring or building cyber tools for use and sale, acquiring and hosting infrastructure, and compromising networks across global victims, which the authoring organizations track as China-based malicious cyber activity. The services provided by Integrity Tech also contribute to the larger Chinese cyber ecosystem, which aims to exfiltrate sensitive data from victims around the world.

Notably, the threat actors enabled by Integrity Tech use TTPs consistent with the cyber activity publicly known as Flax Typhoon, Ethereal Panda, and Red Juliett, among others. However, these threat actors may also perform activity not associated with Integrity Tech.

Note: Cybersecurity companies have different methods of tracking and attributing cyber actors and these may not be a 1:1 correlation to the US Government's methodology and understanding for all activity related to these groupings.

Technical Details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 19. See Appendix A: Indicators of Compromise and the MITRE ATT&CK Tactics and Techniques section of this advisory for a table of the threat actors’ activity mapped to MITRE ATT&CK tactics and techniques.

Reconnaissance

The threat actors use a variety of open source scanning tools to find vulnerabilities in networks and web-based applications, including: BBScan, dirsearch, Fscan, ksubdomain, masscan, NMAP, OneForAll, ShuiZe, and wpscan [T1595.002]. See Appendix A: Indicators of Compromise for a complete list of scanning tools.

Some of these tools contain features useful for fingerprinting remote applications, testing remote authentication protocols, or enumerating the pages of a website. The use of open source tools typically found on GitHub suggests the threat actors tend to look for more vulnerable targets. In general, the threat actors focus on scanning ports 21 (file transfer protocol [FTP]), 22 (SSH), 53 (domain name system [DNS]), 80 (HTTP), 443 (HTTPS), and 1080 (SOCKS). When scanning websites with dirsearch, the threat actors attempt to enumerate PHP and ASP (.NET) pages.

MicroScan

As early as 2017, these threat actors have also used a malicious application known as “MicroScan.” This Python-based web application contains over 1,300 penetration testing scripts written to scan websites for specific vulnerabilities. The threat actors used these scripts to target services including OpenSSL, Oracle WebLogic, Rejetto, WordPress, Juniper ScreenOS, Jenkins, and Apache Struts. See Appendix B: Observed Common Vulnerabilities and Exposures for a list of successfully exploited common vulnerabilities and exposures (CVEs) recovered from penetration testing scripts. Figure 1 shows a MicroScan account dashboard displaying detected vulnerabilities.

Figure 1. MicroScan Account Dashboard Showing Detected Vulnerabilities

Initial Access and Execution

Since at least mid-January 2021, the threat actors have gained access to victim networks and cloud-based services primarily through command line utilities built on exploit codes written in popular programming languages, such as Python and Go [T1059.006]. Additionally, the threat actors have used JavaScript [T1059.007] and HTML code to execute cross-site scripting (XSS) attacks. XSS vulnerabilities allow malicious actors to use unwitting third-party applications vulnerable to XSS to modify content on a webpage [T1189] and target other victims.

During the investigations, the FBI recovered an XSS payload used by the threat actors. When executed on a vulnerable website running JavaScript, this payload modifies webpage content to display username and password fields, facilitating user credential harvesting (see Figure 2).

Figure 2. Executed XSS Payload

After a user enters any username and password, the executed XSS payload page generates a link to download a password-protected .zip file. The .zip file’s contents originate from encoded bytes within the XSS payload and contain the executable file live700_v1.exe.

Analysis of live700_v1.exe demonstrated the executable begins a process named DiagTrack.exe, which shares its name with legitimate Windows software [T1036.003]. DiagTrack.exe then establishes encrypted communications over the HTTP protocol with the domain dns.studiocloud.xyz, which the FBI attributes to Integrity Tech. Given that the executable also contains functions designed to query data from user mailboxes, the FBI assesses the malware likely targets user email data for exfiltration.

EBurst

The threat actors use EBurst, an open source Python-based tool, to target accounts in the Microsoft Office365 Cloud environment. The tool compromises email accounts on Microsoft Exchange servers using multiple interfaces for password spraying [T1110.003] and password guessing [T1110.001] against each supplied email address. Based on the open source EBurst ReadMe file, these interfaces include:

Exchange Control Panel (ECP);

Exchange Web Services (EWS);

Offline Address Book (OAB);

Outlook Web Access (OWA);

Remote Procedure Call (RPC);

Application Programming Interface (API);

Messaging Application Programming Interface (MAPI);

PowerShell;

Autodiscover; and

Microsoft-Server-ActiveSync.

Network defenders should include these interfaces when defending against EBurst.

Persistence

To establish persistence, the threat actors install virtual private network (VPN) software clients on victim devices [T1133] to obfuscate command and control (C2) communications or other actions, further preventing victims from attributing malicious network activity.

The threat actors typically download SoftEther installers onto victim devices from threat actor-controlled infrastructure using PowerShell or LOTL binaries for Windows Systems [T1059.001]. For Linux/Unix distributions, the threat actors download SoftEther installers via curl or wget. For either operating system, the actors configure the SoftEther client to automatically reconnect on startup. They often name the installers conhost.exe or dllhost.exe to appear as common Windows executables [T1036.003]. Additionally, endpoint detection software is less likely to flag SoftEther because it is a legitimate VPN software.

In […]

---

# CISA AA26-251A — China-Based Artificial Intelligence Companies Conducting Industrial-Scale Distillation Campaigns Against U.S. AI Companies

Source : CISA, avis de cybersécurité AA26-251A (Fri, 04 Sep 2026 12:12:28 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-251a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Executive summary

China-based artificial intelligence (AI) companies are conducting systematic extraction of proprietary functionalities and capabilities of U.S. AI companies’ models through industrial-scale knowledge distillation campaigns that form the core—not merely a supplement—of their AI development strategy. While “distillation” is recognized as a legitimate and useful technique in AI research, China-based AI companies are engaging in aggressive, malicious, and targeted distillation activities at an industrial scale that extract restricted proprietary functionalities and capabilities of U.S. frontier AI models. The National Security Agency (NSA), Cybersecurity and Infrastructure Security Agency (CISA), and Federal Bureau of Investigation (FBI) (hereafter referred to as the authoring agencies) are releasing this joint Cybersecurity Advisory to alert organizations about these malicious activities and techniques and recommend mitigations to reduce their potential impact.

Likely with Chinese government awareness, DeepSeek, Moonshot AI, Alibaba, MiniMax, StepFun, and Z.AI extracted billions of tokens across millions of exchanges/requests from U.S. frontier AI models, including variants of Claude, GPT, Gemini, and Grok, since at least late 2024. DeepSeek has conducted organized campaigns since at least 2024 targeting reasoning capabilities, specialized optimizations, and domain-specific functions to train its R1 and V3 models. Alibaba leveraged industrial-scale distillation to improve the company’s Qwen family of AI models. Moonshot AI, MiniMax, Stepfun, and Z.AI also engaged in malicious knowledge distillation of U.S. AI companies’ models.

China-based AI companies route distillation requests through multiple pathways to gain unauthorized access, consequently violating U.S. AI companies’ terms of use. These pathways include native application programming interfaces (APIs), remote cloud providers, and third-party aggregators that automatically obfuscate user metadata to avoid detection. Further, China-based AI companies use a gray market of proxies known as “transfer stations” to bypass U.S. AI companies’ geographic restrictions, breach terms of use, evade safeguards, and undermine traceability. China-based AI companies achieve cost savings for their industrial-scale distillation campaigns through bulk procurement of the U.S. AI companies’ premium subscriptions shared across teams of developers. Advanced industrial-scale distillation tactics include chain-of-thought (CoT) reasoning extraction, automated failover between pathways during blocking attempts, and sophisticated quality evaluation frameworks to detect defensive countermeasures. China-based AI companies that conduct industrial-scale distillation against U.S. AI models see significantly shorter AI development timelines and reduced financial expenditures in training a frontier model.

China-based AI companies deliberately distribute operations across multiple providers, platforms, and pathways to avoid single-point detection. They also attempt to distill the best capabilities and proprietary features of each U.S. frontier model to train their China-based AI models. This represents systematic extraction of proprietary functionalities and capabilities threatening U.S. technological leadership. Addressing industrial-scale distillation merits a coordinated response across the AI ecosystem, including effective information-sharing, spanning the U.S. Government, private industry, and allied nations.

The authoring agencies recommend U.S. AI companies take three immediate actions:

Implement comprehensive detection and mitigation: Detect anomalous and malicious prompts, accounts, networks, and behaviors. Additionally, monitor subscription-to-usage ratios, immediate maximum usage from new accounts, and enterprise-scale throughput patterns.

Deploy targeted response changes: Subtly alter responses for suspected malicious distillation attempts to attenuate the payoffs to companies conducting industrial-scale distillation campaigns.

Establish cross-organization intelligence sharing: Correlate activity across model providers, cloud platforms, and API aggregators to reveal distributed campaigns.

Attribution

Since at least late 2024, China-based AI companies, including DeepSeek (DeepSeek Artificial Intelligence Technology Research Co., Ltd.), Moonshot AI (Beijing Moonshot Technology Co., Ltd.), Alibaba Group, MiniMax (Shanghai MiniMax Co., Ltd.), StepFun (Shanghai Jieyue Xingchen Intelligence Technology Co., Ltd.), and Z.AI, have conducted high-volume knowledge distillation campaigns against several U.S. AI companies. The sheer scale of these campaigns and their sophistication indicate that distillation is not a supplement to these companies’ AI model development, but the critical core of it.

Likely with the knowledge of the Chinese government, the China-based AI sector has turned to a comprehensive distillation strategy in an attempt to bridge the technological and performance gaps between their AI models and U.S. frontier AI models. To access U.S. AI companies’ application programming interfaces (APIs), China-based AI companies use a gray market of API proxies known as “transfer stations” to bypass U.S. AI companies’ regional restrictions, breach terms of use, evade safeguards, and undermine traceability.

DeepSeek

DeepSeek has been conducting an organized distillation campaign against U.S. AI companies’ frontier AI models since at least late 2024 to generate synthetic training data for its models, including R1, released in early 2025. The company targeted specific knowledge domains to extract proprietary functionality and reasoning capabilities to reduce their compute and research costs. DeepSeek’s publicly quoted training costs of $5.6M are misleading as it does not include the true cost of the data acquired through extensive malicious distillation.1

Between late 2024 and mid-2025, DeepSeek distilled specialized training data and capabilities from the following U.S. frontier AI company models to train their R1 and V3 models:

Claude 3.7

Claude Sonnet 4

Claude Sonnet 4.5

Claude Opus 4.1

Gemini 2.5 Pro Preview

Gemini 2.5 Flash Preview

GPT-4

GPT-4o

GPT-4 Mini

GPT-4 Nano

GPT-5

Grok 4

The specific knowledge and capabilities distilled included:

Legal specialization optimization

API rule-driven tasks

Writing using CoT drafts

Agentic functions

Question and answer optimization

Coach/assistant capabilities

Functional creation optimization

Supervised fine-tuning (SFT) optimization

Creative and occupational writing optimization

Moonshot AI

Moonshot AI has conducted a widespread distillation campaign against U.S. frontier AI companies since at least mid-2025. Notably, Moonshot AI extracted significant Claude Fable 5 data to train its Kimi-K3 model and GPT-4o data to train its Kimi-K2 model. The company has used the following models to distill SFT optimization, reinforcement learning (RL), software engineering, and math capabilities:

Claude Opus 4.1

Claude Sonnet 3.7

Claude Sonnet 4

Claude Sonnet 4.5

Claude Sonnet 4.5 Thinking

Claude Fable 5

GPT-oss-20b

GPT-3

GPT-4o

GPT-4o mini

GPT-5

GPT-5 Codex

GPT-5 Pro

Gemini 2.5 Flash

Gemini 2.5 Flash-Image

Gemini 2.5 Pro

Nano Banana

Grok Code Fast-1

Other companies

Several other China-based AI companies, including Alibaba, MiniMax, StepFun, and Z.AI have also leveraged distillation techniques to build their AI models. In late 2025, Alibaba distilled Claude-4, Claude Opus, Claude Sonnet, and GPT-5 to improve their AI models’ software engineering skills, customer service dialogue functionality, image/character creation, and integration of RL, SFT, and distillation capabilities.

In late 2025, MiniMax distilled CoT reasoning, RL, SFT, and software engineering capabilities to improve its M2 model from Claude Code, Claude Sonnet 4, Claude Opus, Gemini 1, Gemini 2.5 Pro, and Gemini 3 Pro. MiniMax used Claude Code for internal software development tasks, including code generation, analysis, and refinement. MiniMax even used prompt injections to try to trick Claude Code into believing it was a MiniMax product.

Between late 2025 and early 2026, StepFun distilled data from Claude Opus 4.1 and 4.5, Claude Sonnet 4.5, Claude Haiku 4.5, GPT-5 Mini, GPT-5 Pro, GPT-5.1, GPT-5.1 Codex, and GPT-5.2 to improve its Step 4 model’s coding and agentic functions. By mid-2026, Z.AI had distilled billions of tokens of GPT-5.5 data and Claude Opus 4.8 data to develop the CoT reasoning capabilities of its model.

Table 1: China-based AI Companies Engaged in Knowledge Distillation Against U.S. AI Companies (From at least 2024-2026)

China-based AI Company

U.S. AI Models Distilled

Functionalities and Domains Distilled

DeepSeek

(DeepSeek Artificial Intelligence

Technology Research Co., Ltd.)

深度求索AI基础技术研究有限公司

Claude Sonnet 3.7

Claude Sonnet 4

Claude Sonnet 4.5

Claude Opus 4.1

Gemini 2

Gemini 2.5 Pro Preview

Gemini 2.5 Flash Preview

GPT-4

GPT-4o

GPT-4 Mini

GPT-4 Nano

GPT-5

Grok 3 Mini

Grok 4

Legal specialization optimization

API rule-driven tasks

Writing using CoT drafts

Question and answer optimization

Coach/assistant capabilities

Functional creation optimization

SFT optimization

Agentic capabilities

Creative and occupational writing optimization

Moonshot AI

(Beijing Moonshot Technology Co., Ltd.)

北京揽月星辰科技有限公司

Claude Opus 4.1

Claude Sonnet 3.7

Claude Sonnet 4

Claude Sonnet 4.5

Claude Sonnet 4.5 Thinking

Claude Fable 5

GPT-oss-20b;

GPT-3

GPT-4o mini

GPT-5

GPT-5 Codex

GPT-5 Pro

Gemini 2.5 Flash

Gemini 2.5 Flash-Image

Gemini 2.5 Pro

Nano Banana

xAI Grok Code Fast-1

SFT

RL

Software engineering

Math capabilities

Alibaba

阿里集团

Claude 4

Claude Sonnet

GPT-5

Customer service dialogue

Virtual character creation

SFT, RL, and distillation training

Evaluating and training datasets

End-to-end agentic workflows

Software engineering

MiniMax

(Shanghai MiniMax Co., Ltd.)

上海稀宇极智科技有限公司

Claude Code

Claude Sonnet 4

Claude Opus 4.5

Gemini 1

Gemini 2.5 Pro

Gemini 3 Pro

GPT-5

CoT reasoning

Agentic functionality

Code review

SFT dataset refinement

Software engineering tasks

StepFun

(Shanghai Jieyue Xingchen

Intelligence Technology Co., Ltd.)

上海阶跃星辰智能科技有限公司

Claude Opus 4.1

Claude Opus 4.5

Claude Sonnet 4.5

Claude Haiku 4.5

GPT-5 Mini

GPT-5 Pro

GPT-5.1

GPT-5.1 Codex

GPT-5.1 Codex Mini

GPT-5.2

Code development

Agentic functions

Z.AI

北京智谱华章科技有限公司

GPT-5.5

Claude Opus 4.8

CoT reasoning

Tactics, techniques, and procedures

China-based AI companies employ sophisticated tactics, techniques, and procedures (TTPs). These TTPs map to the MITRE® ATLASTM2 framework, progressing through multiple adversary lifecycle phases from initial access through exfiltration. The China-based AI companies using these techniques include DeepSeek, Moonshot AI, MiniMax, StepFun, Z.AI, and other China-based AI companies targeting U.S. frontier AI models.

Table 2: MITRE ATLAS Mappings

TTP Title

ID

Description

Resource Development

Acquire Infrastructure

AML.T0008

China-based entities establish and maintain sophisticated infrastructure supporting sustained extraction operations through tiered budget management and diverse supplier relationships.

China-based entities circumvent both Chinese and U.S. AI access controls through a large gray market of API proxies, or “transfer stations,” which resell access to frontier models at a fraction of the official price. In doing so, they create a scalable mechanism for evading provider safeguards and eroding traceability.

AI Model Access

AI Model Inference API Access

AML.T0040

China-based entities have been exploiting AI model inference APIs through the creation of fraudulent accounts that are not registered to legitimate users. These actors leverage multiple accounts with similar registration details and payment methods, frequently switch between various AI models, and utilize third-party […]

---

# CISA AA26-237A — A Tale of Two SOCs: Insights From Two Red Team Assessments

Source : CISA, avis de cybersécurité AA26-237A (Thu, 20 Aug 2026 12:32:14 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Advisory at a Glance

Title

A Tale of Two SOCs: Insights From Two Red Team Assessments

Original Publication

August 25, 2026

Executive Summary

The Cybersecurity and Infrastructure Security Agency (CISA) conducted simultaneous red team assessments at two organizations and observed different defensive outcomes. In both environments, the red team achieved full domain compromise and accessed sensitive business systems (SBSs) and cloud resources. Organization A failed to detect or contain the activity, but Organization B rapidly identified initial compromise attempts, isolated affected systems, and forced the red team into an assume breach model.

This advisory details the red team’s activity and organizations’ defensive actions, offering lessons learned and mitigations to help critical infrastructure organizations strengthen detection, response, and protections in IT, cloud, and operational technology (OT) environments.

Lessons Learned

Untuned detection tools lead to missed threats. Without well-defined baselines and alert filtering, false positives and routine alerts overwhelm network defenders.

Organizational silos and bureaucratic hurdles prevent effective incident response. Detection tools are only as effective as the people, processes, and procedures supporting them; fragmented communication, unclear responsibilities, and limited defender authority hinder effective incident response.

Cloud environments are often an underestimated risk. Organizations often lack security controls for cloud environments and processes for responding to a cloud compromise.

Key Actions

Establish and continuously maintain a baseline and reduce alert noise by fine tuning.

Break down silos and empower network defenders.

Implement Conditional Access policies for workload identities and monitor for excessive or unused permissions.

Establish and regularly review comprehensive procedures for detecting, remediating, and revoking access/refresh tokens in the event of a cloud compromise.

Intended Audience

Organizations: Federal Civilian Executive Branch agencies; state, local, tribal, and territorial governments; critical infrastructure.

Roles: System administrators, incident responders, defensive cybersecurity analysts, vulnerability analysts, network operators, security systems managers, and all network defenders.

Introduction

The Cybersecurity and Infrastructure Security Agency’s (CISA’s) red team simulates real‐world malicious cyber operations to assess an organization’s ability to detect, investigate, and respond to malicious cyber activity. Emulating cyber threat actor tradecraft, the red team attempts to gain and maintain persistent access to an organization’s network and sensitive business systems (SBSs) while avoiding detection.

CISA conducted two simultaneous red team assessments using similar tradecraft but observed different defensive responses. In one organization (Organization A), the team gained initial access to multiple workstations, gained elevated privileges over the domain, and moved laterally to SBSs and cloud resources undetected. In the second organization (Organization B), network defenders quickly detected the initial compromise and quarantined the affected systems.

Because Organization B detected the initial compromise, the red team moved to an assume breach model, where Organization B trusted agents (TAs) provided access to a host that replicated the level of access the red team would have had if defenders had not detected their activity. From there, the red team escalated privileges and moved laterally to SBSs, cloud resources, and a bastion host in the OT demilitarized zone (DMZ), where defenders again detected activity and isolated the system.

In coordination with the assessed organizations, CISA is releasing this Cybersecurity Advisory to describe the red team’s activity and the organization’s defensive responses and to share lessons learned that critical infrastructure organizations can use to strengthen their IT, cloud, and OT cybersecurity posture.

CISA encourages critical infrastructure organizations to implement the recommendations in the Mitigations section of this advisory to reduce the likelihood and impact of malicious cyber incidents.

Download the PDF version of this report:

A Tale of Two SOCs: Insights From Two Red Team Assessments
(PDF, 937.09 KB
)

Technical Details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 19. See the MITRE ATT&CK Tactics and Techniques section of this advisory for a table of the red team’s activity mapped to MITRE ATT&CK tactics and techniques.

Overview

CISA is authorized—upon request—to provide analyses, expertise, and other technical assistance to critical infrastructure owners and operators and to provide operational and timely technical assistance to federal and non-federal entities, with respect to cybersecurity risks (see generally 6 U.S.C. §§ 652[c][5], 659[c][6]). CISA conducted two concurrent red team assessments: one at a Government Services and Facilities Sector organization (Organization A), and one at a Water and Wastewater Systems Sector organization (Organization B).

During CISA’s red team assessments, the red team simulates malicious cyber operations to assess an organization’s threat detection and response capabilities. The red team attempts to gain and maintain persistent access to an organization’s enterprise network, avoid detection, evade defenses, and access SBSs (applications, data stores, or infrastructure components where compromise would materially impact the organization's operations, finances, or customer data) selected by the organization. For the assessments described in this advisory, the team also attempted to gain access to cloud resources and to demonstrate their ability to access Organization B’s OT systems without actually doing so.

Organization A

Red Team Cyber Threat Activity

Initial Access and Active Directory Discovery

During reconnaissance, CISA’s red team identified a web application with default credentials [T1589.001] for multiple built-in user accounts that allowed the team to send emails from an internal email address. The team used the internal email address to send phishing emails [T1566] and gained initial access to four workstations.

From the workstations, the red team leveraged a modified BloodHound1 collector, customized to avoid static endpoint detection and response (EDR) signatures, to query and scrape Active Directory (AD) information. This information included AD users [T1087.002], computers [T1018], groups [T1069.002], access control lists, organizational units, and group policy objects (GPOs) [T1615]. The team found that one compromised workstation had the default Machine Account Quota (MAQ) of 10, allowing unprivileged users to add up to 10 computer accounts to the domain.

The red team also queried the organization’s Active Directory Certificate Service (ADCS) certificate templates. Misconfigured ADCS templates are common and can allow low-privileged accounts to request a certificate on behalf of other users and computers, including highly privileged accounts. The team identified multiple templates with an ESC1 misconfiguration, which allows any user to request certificates for all users and computer accounts (see scenario ESC1 in SpecterOp’s Certified Pre-Owned: Abusing Active Directory Certificate Services). The red team exploited the misconfigured MAQ to create a machine account [T1136.002] and then exploited a misconfigured ADCS template to request a certificate for the newly created machine account [T1649]. They could then obtain certificates for any user account, providing means for lateral movement.

Post Exploitation: Privilege Escalation and Lateral Movement

Sensitive Business Systems

After the red team gained elevated privileges over the domain, they began post-exploitation activities and attempted to access SBSs. To access the SBSs, the team needed to identify their network location and security controls.

The team’s plan to achieve SBS access included the following steps:

Use previously acquired AD data to identify users and groups related to the SBS.

Query system center configuration manager (SCCM) servers to enumerate user-device relationships and identify the workstations assigned to each user [T1033].

Move laterally from the SCCM server to the target users’ workstations.

Find credential material on the target user’s workstation to access the SBS.

Verify administrative access to the SBS would allow compromise of the availability, integrity, and/or confidentiality of the system and its data.

For each SBS, the red team used similar discovery and initial access techniques but unique credential retrieval methods. For SBS 1, a database, the team located cleartext credentials on an administrative user’s workstation providing access to the system [T1552]. For SBS 2, also a database, the red team searched the targeted user’s workstations for connections.json and product-preferences.xml files for a Structured Query Language (SQL) developer tool. The team decrypted these files to obtain the cleartext password to the database [T1552.001]. For SBS 3, an automated processing system, the red team acquired long-lived static Amazon Web Service (AWS) identity and access management (IAM) user credentials saved in configuration files in targeted users’ home directories. These credentials do not expire because the organization had not configured credential expiration or rotation.

For SBS 2 and 3, the red team expanded access beyond users’ physical workstations to include their virtual desktops, which limited their access to the active, interactive sessions held by users. While virtual workstations add security controls, such as segmenting networks of sensitive systems to only allow virtual hosts, they are generally synchronized with a root drive of the distributed file system (DFS). The red team compromised the root DFS drive, granting them access to local files of all users’ virtual desktops, regardless of the existence of an active session. This allowed the team to quickly search for cloud configuration files containing credentials and database connection files for thousands of users.

The red team obtained administrative access to all targeted SBSs without defensive intervention by proxying tools [T1090.001] through compromised workstations and using the collected credentials.

Microsoft Entra Systems

After compromising the target SBSs, the red team attempted to compromise Organization A’s Microsoft cloud environment by compromising Organization A’s Microsoft Entra ID (formerly Azure AD) through applications. The team targeted Entra ID applications with Application permissions, which allow applications to access data without user consent (compared to Delegated permissions, which allow applications to access data with user consent). By compromising an application that had elevated Application permissions, the red team would gain the same permissions as the application because these applications operate outside the scope of traditional conditional access policies (CAPs) that provide controls for user access and activity.

Note: Microsoft’s Conditional Access for workload identities extends traditional CAPs to service principals (SPs) used by applications and governs Application permissions by allowing organizations to broadly apply access policies to applications. Implementing Conditional Access for workload identities would have protected against red team exploiting use of Application permissions; however, the red team never observed an organization using Conditional Access for workload identities.

The team compromised applications and used their permissions by:

Enumerating the organization’s cloud resources using the publicly available tools, including AzureHound2 and ROADrecon,3 to gather information about applications, their permissions, and their owners [T1526] [T1588.002].

Identifying applic […]

---

# CISA AA26-231A — Defending Against an Active Threat to Siemens S7 Series PLCs

Source : CISA, avis de cybersécurité AA26-231A (Fri, 14 Aug 2026 16:06:03 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Executive summary

Note: This advisory relates to an active threat to Siemens S7 Series programmable logic controllers (PLCs). However, ongoing PLC targeting activity is broader than Siemens PLCs. All PLC owners and operators should apply relevant mitigations to reduce the risk to their devices and systems. The Siemens-specific content in this advisory should be understood and applied as one subset of the wider threat landscape.

Top Mitigations

Inventory all Siemens S7 Series programmable logic controllers (PLCs)

Apply critical security patches

Ensure PLCs are not accessible from the Internet

Strengthen access controls

Monitor for unauthorized activity

Harden PLC services, protocols, and ladder logic integrity

Hunt for anomalies that may indicate a compromise

The National Security Agency (NSA), Cybersecurity and Infrastructure Security Agency (CISA), Federal Bureau of Investigation (FBI), Department of Energy (DOE), and Environmental Protection Agency (EPA)—hereafter referred to as the authoring agencies—are releasing this Cybersecurity Advisory to warn owners and operators of industrial control systems (ICSs) of an active cyber threat to Siemens S7 Series PLCs and provide relevant mitigations to protect and defend them.

The threat actors are conducting reconnaissance and capability development against U.S.-based Siemens PLC installations using AI-generated exploitation scripts disguised as legitimate monitoring tools. The actors leverage Internet scanning services to find Internet-exposed PLCs running outdated software or that are otherwise poorly protected. The U.S. critical infrastructure sectors most targeted by this threat activity include Critical Manufacturing, Energy, Water and Wastewater, Chemical, Food and Agriculture, and Commercial Facilities. This is not a theoretical risk—it is an active threat. Depending on the specific circumstances, exploitation of poorly protected PLCs could lead to disruption of critical industrial processes, safety incidents, downtime or equipment damage, compromise of sensitive data, compliance violations, and cascading impacts across interconnected systems.

The authoring agencies urge all owners and operators of operational technology (OT) systems using Siemens S7 Series and other PLC devices to proactively check their systems:

are properly protected with all applicable security patches and updates,

are isolated from the Internet wherever possible,

have strong access controls, and

employ security tooling to monitor ICS environments for anomalous or malicious activity.

These mitigations are particularly important for owners and operators who work with third-party service providers or system integrators who may have remote access to PLCs, as the asset owners may not realize that their systems are exposed and at risk.

Technical details

Note: This advisory uses the MITRE ATT&CK® Matrix for ICS1 framework, version 19, and the MITRE ATT&CK Matrix for Enterprise framework, version 19. This advisory also uses MITRE D3FENDTM, version 1.5.0. See Appendix A and Appendix B for tables of the activity mapped to MITRE ATT&CK and MITRE D3FEND tactics, techniques, and countermeasures.

Threat actor targeting

Threat actors are actively targeting the following Siemens PLC models:

S7-200 Series (all CPU variants)

S7-300 Series (all CPU variants including 314, 315, 317 models)

S7-400 Series (all CPU variants)

S7-1200 Series (CPU 1211C, 1212C, 1214C, 1215C, 1217C variants)

S7-1500 Series (all CPU variants, including F-series safety controllers)

Threat actors are using AI assistance to generate exploitation scripts using publicly available information on these Siemens S7 Series PLCs for initial access, credential access, denial of service, and other objectives. If these PLCs are exposed to the Internet or insufficiently segmented, then threat actors can exploit various critical and high severity known vulnerabilities in these PLCs.

Note: Using AI to generate exploitation scripts represents an evolution in threat actor capabilities, dramatically reducing the technical expertise and time required to develop working ICS exploitation scripts and malicious tools. In addition, AI enables adversaries to rapidly leverage additional attack vectors and adapt to defensive measures. Threat actors can easily collect public information about vulnerabilities and weaknesses, find exposed and exploitable PLCs, and use AI-generated scripts to act on that information. If PLCs are exposed to the Internet, they are at high risk for exploitation.

Threat actors are leveraging open source industrial automation libraries—specifically snap7.dll/python-snap7—combined with AI-assisted scripting to create custom tools that mimic legitimate OT monitoring solutions. These tools provide read/write access to Siemens S7 Series PLC memory, configuration data, and ladder logic programs via the S7comm protocol.

Threat actor techniques

Threat actors are:

Using Internet scanning services (e.g., Censys, ZoomEye) to identify Internet-exposed or insufficiently segmented Siemens S7 Series PLCs [T1596.005]

Rapidly iterating exploit code through AI-assisted development, lowering technical barriers to ICS attacks [T1587.004, T1588.007]

Taking advantage of insecure credentials to access exposed devices that have unconfigured (default) or minimally configured authentication [T1694]

Deploying AI-generated Python scripts that incorporate the snap7.dll library from public repositories [T0834] to gain read/write access to the PLC and mimic legitimate tools

Masquerading malicious scripts as legitimate monitoring tools to evade detection by security teams [T0849]

Conducting read/write operations on data blocks, potentially for reconnaissance, capability testing, or pre-positioning for effects operations [T0893, T0821]

The authoring agencies assess this activity pattern is likely intended as persistent reconnaissance in targeted sectors and facilities to develop capabilities and prepare to cause operational effects against critical infrastructure. For capability development, actors are testing and refining their exploitation techniques against specific PLC models to improve their ability to compromise the PLCs. To prepare for operational effects, actors are leveraging read access to understand target environments, enabling preparation and positioning for future write operations to cause disruption or other operational impacts.

Potential operational impacts

The U.S. critical infrastructure sectors most targeted by this threat activity include Critical Manufacturing, Energy, Water and Wastewater, Chemical, Food and Agriculture, and Commercial Facilities. Additionally, Siemens S7 Series PLCs are used in other sectors, including the Defense Industrial Base (DIB), and could be targeted there as well. Unauthorized access to PLCs could result in:

Disruption of critical industrial processes affecting production throughput, product quality, and public services

Safety incidents affecting personnel through manipulation of safety interlocks, emergency shutdown systems, or process parameters

Equipment damage and extended operational downtime from process upsets, improper sequencing, or forced equipment operation outside design parameters

Compromise of sensitive operational data, including proprietary process recipes, control strategies, and facility configurations

Cascading impacts across interconnected systems affecting supply chains, dependent facilities, and integrated business operations

Regulatory compliance violations and potential liability from process safety management failures

Mitigation actions

Since threat actors are developing capabilities using AI to compromise PLCs using known vulnerabilities, misconfigurations, and other weaknesses and then may use compromised PLCs to interfere with normal operations, the authoring agencies urge organizations to implement comprehensive defense-in-depth strategies, in addition to Common Vulnerabilities and Exposures (CVE) remediation, to protect and defend their PLCs.

Detection opportunities

Organizations should implement detection strategies and hunt for anomalies that may indicate a compromise, focusing on [D3-PM]:

Anomalous S7comm behavior: Connections from non-engineering workstations, unusual data block access patterns, or write operations outside change windows

Reconnaissance indicators: Sequential IP scanning on port 102, repeated connection attempts with varying parameters, or enumeration of CPU properties

Tool artifacts: Snap7.dll library usage outside approved engineering workstations, Python scripts with S7comm functionality, or unauthorized monitoring software installations

Temporal anomalies: S7comm activity during off-hours, unexpected connection patterns consistent with automated scripting rather than human operators, or configuration changes without corresponding work orders or change tickets

Geographic anomalies: Connections originating from unexpected countries or IP ranges not associated with vendors or integrators

Preventative hardening actions

To counter threats to PLCs, the authoring agencies recommend all PLC owners and operators follow the mitigations in joint guidance Primary Mitigations to Reduce Cyber Threats to Operational Technology.

To harden Siemens S7 Series PLCs, the authoring agencies strongly urge all owners implement the hardening steps below. Entities that rely on systems integrators or third-party managed service providers should share this advisory with those parties and request implementation of the following mitigations:

1. Conduct an immediate inventory of all Siemens S7 Series PLCs in your environment [D3-HCI]:

Verify current firmware versions for all S7-200, S7-300, S7-400, S7-1200, and S7-1500 controllers against backup gold copy

Identify any systems directly or indirectly accessible from untrusted networks

Map all engineering workstations with Totally Integrated Automation (TIA) Portal, STEP 7, or S7 programming access

2. Apply critical security patches as soon as possible [D3-SU]:

Update Siemens S7 Series PLC firmware to the latest versions that address known vulnerabilities

Prioritize Internet-facing or demilitarized zone (DMZ)-resident controllers

Update TIA Portal and STEP 7 software to current versions

Consult Siemens ProductCERT advisories for information on known vulnerabilities, along with relevant workarounds and mitigations

Test all updates in a development environment before production deployment

3. Verify network segmentation and ensure PLCs are NOT accessible from the Internet [D3-NI]:

Audit firewall rules for any exposed S7comm services (Transmission Control Protocol [TCP] port 102)

Block TCP port 102 at perimeter firewalls entirely

Implement a DMZ architecture that separates OT and IT networks

Deploy unidirectional gateways for data historian connections where appropriate

Verify there is no unauthorized routing between corporate and industrial networks

4. Review and strengthen access controls [D3-NAM, D3-CH]:

Restrict TIA Portal/STEP 7 access to authorized engineering workstations only by MAC/IP allowlisting on PLCs

Enable PLC password protection on all Siemens S7 Series controllers

Configure protection levels (such as write protection and read/write protection) on Siemens S7 Series devices

Remove or change default SNMP community strings

Implement application allowlisting on all engineering workstations

Enable multi-factor authentication for all remote access to OT networks

5. Enable comprehensive logging and monitoring [D3-PM, D3-NTA]:

Deploy ICS-aware intrusion detection (e.g., Claroty, Dragos Platform, Nozomi Networks, or similar)

Monitor all S7comm traffic on TCP port 102 for connections outside maintenance windows

Alert on unauthorized PUT/GET operations, especially write commands to data blocks or configuration areas of memory

Log all TIA Portal/STEP 7 connections to PLCs with timestamps and source IPs

Establish a baseline […]

---

# CISA AA26-222A — StopRansomware: Gunra Ransomware

Source : CISA, avis de cybersécurité AA26-222A (Wed, 05 Aug 2026 08:27:56 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-222a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Advisory at a Glance

Title

StopRansomware: Gunra Ransomware

Original Publication

August 10, 2026

Executive Summary

Gunra is a ransomware-as-a-service (RaaS) used by affiliates to target government, critical infrastructure, and other organizations. The Gunra ransomware variant first appeared in 2025 and expanded to RaaS operations in 2026. The actors leverage a double-extortion model, both encrypting data and threatening to publish exfiltrated data to a dedicated leak site (DLS) if the ransom is not paid. This advisory provides technical details of the activity, as well as tailored detection and mitigation guidance to protect at-risk organizations from Gunra.

Key Actions

Prioritize patching known exploited vulnerabilities in internet-facing systems, including virtual private network (VPN) gateways and remote desktop protocol (RDP)-exposed infrastructure.

Implement and test offline, immutable backups stored in a physically separate, segmented location to ensure recoverability without ransom payment.

Segment networks to restrict lateral movement from an initially compromised device to other systems in the organization.

Indicators of Compromise

For a downloadable copy of indicators of compromise, see:

AA26-222A STIX XML (54 KB)

AA26-222A STIX JSON (61 KB)

Intended Audience

Organizations: Government, Critical Infrastructure

Sectors: Healthcare and public health, financial services and insurance, critical manufacturing and construction, transportation systems and logistics, government services and facilities, utilities, academia, media and communications, retail, and professional and nonprofit services.

Roles: Cybersecurity architects, defensive cybersecurity analysts, vulnerability analysts, systems administrators, and security systems managers.

Introduction

Note: This joint Cybersecurity Advisory is part of an ongoing #StopRansomware effort to publish advisories for network defenders that detail various ransomware variants and ransomware threat actors. These #StopRansomware advisories include recently and historically observed tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) to help organizations protect against ransomware. Visit stopransomware.gov to see all #StopRansomware advisories and to learn more about other ransomware threats and no-cost resources.

The Federal Bureau of Investigation (FBI), Cybersecurity and Infrastructure Security Agency (CISA), Department of Defense Cyber Crime Center (DC3), National Security Agency (NSA), U.S. Secret Service (USSS), and Republic of Korea’s National Police Agency (KNPA)—hereafter referred to as “the authoring agencies”—are releasing this joint advisory to alert organizations to the emerging Gunra ransomware threat and to provide detection and mitigation guidance.

Gunra first emerged in April 2025 as a sophisticated double-extortion ransomware variant derived from the leaked Conti1 ransomware source code. As of early 2026, Gunra expanded its operations through a structured ransomware-as-a-service (RaaS) affiliate program advertised on dark web forums to financially motivated cybercriminals. Gunra actors demand ransom via a customized, Tor-based negotiation portal and threaten to publish exfiltrated data on a dedicated leak site (DLS) if victims do not comply.

Gunra victims observed on the actors’ DLS span organizations across multiple sectors in the Americas, Europe, Middle East, Africa, and the Asia-Pacific.2 These sectors include:

Healthcare and public health

Financial services and insurance

Critical manufacturing and construction

Transportation systems and logistics

Government services and facilities

Utilities

Academia

Media and communications

Retail

Professional and nonprofit services

The authoring agencies encourage organizations to implement the recommendations in the Mitigations section of this advisory to mitigate cyber threats related to Gunra ransomware, including:

Prioritizing patching known exploited vulnerabilities in internet-facing systems, including virtual private network (VPN) gateways and remote desktop protocol (RDP)-exposed infrastructure.

Implementing and testing offline, immutable backups stored in a physically separate, segmented location to ensure recoverability without ransom payment.

Segmenting networks to restrict lateral movement from an initially compromised device to other systems in the organization.

Download the PDF version of this report:

AA26-222A StopRansomware Gunra Ransomware
(PDF, 1.07 MB
)

For a downloadable copy of IOCs, see:

AA26-222A STIX XML
(XML, 54.18 KB
)

AA26-222A STIX JSON
(JSON, 61.00 KB
)

Technical Details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 19.1. See the MITRE ATT&CK Tactics and Techniques section of this advisory for a table of the threat actors’ activity mapped to MITRE ATT&CK tactics and techniques.

Overview

The FBI originally observed Gunra ransomware in April 2025. The threat actors quickly established a DLS on the Tor network to list victims and publish exfiltrated data. As of January 2026, Gunra launched a formal RaaS affiliate program on dark web forums, providing affiliates with access to a management panel, a configurable ransomware builder, cross-platform locker payloads, and structured affiliate documentation.3 The FBI observed the group adopting new branding aliases (notably operating under the name Golden Community) to support this expansion. Gunra has further commercialized its platform by actively recruiting penetration testers and ethical hackers to serve as initial access brokers, offering a share of the ransom profits in exchange for enterprise network access.

Based on FBI observations, Gunra actors use a traditional double-extortion model, exfiltrating sensitive victim data prior to encryption and threatening to publish the leaked data on their DLS unless the ransom is paid. Victims receive a ransom note in every affected directory guiding them to a Tor-based negotiation portal where they are assigned a Client ID and an initial password. Subsequently, victims receive instructions to contact the Gunra actors via qTox (an encrypted messaging application) to negotiate ransom payments within five to seven days. If the ransom is not paid, Gunra actors threaten to sell victim data on the DLS.

Gunra ransomware appears to be based on, or significantly influenced by, the Conti ransomware source code leaked in 2022.4 Initially, Gunra actors’ campaigns focused on Windows environments; reporting in mid-2025 indicated the group introduced a Linux variant and moved toward broader cross-platform targeting.5

Initial Access

The FBI observed Gunra actors obtaining initial access [TA0001] primarily through the exploitation of known vulnerabilities in internet-facing devices [T1190], including firewall and VPN appliances. The FBI observed exploits based on the following Common Vulnerabilities and Exposures (CVEs):

CVE-2024-55591 [CWE-288: Authentication Bypass Using an Alternate Path or Channel]: Authentication bypass vulnerability affecting specific FortiOS and FortiProxy versions (see CVE record for more details).

CVE-2025-24472 [CWE-288: Authentication Bypass Using an Alternate Path or Channel]: Authentication bypass vulnerability affecting specific FortiOS and FortiProxy versions (see CVE record for more details).

Additionally, for initial access, KNPA observed Gunra actors exploit credential-exposure and Secure Shell (SSH) access control vulnerabilities in internet-facing VPN gateways to gain unauthorized remote access.

Execution

Gunra’s Windows encryptor relies on native operating system (OS) application programming interfaces (APIs) to drive both execution and targeted encryption activity. The binary uses the FindFirstFileW/FindNextFileW API calls [T1106] to enumerate files and directories on all accessible drive letters (A through Z), enabling comprehensive traversal of the file system prior to encryption of victim data.

Persistence, Privilege Escalation, Lateral Movement, and Command and Control

Gunra actors regularly exploit Impacket libraries psexec.py and smbclient.py to move laterally across victim networks using the Server Message Block (SMB) protocol [T1021.002].

KPNA observed that against one victim, Gunra actors gained access to an administrator account for a secure socket layer (SSL)-VPN appliance [T1133] by exploiting default credentials when account lockout controls were not present [T1078.001][T1078.002]. The actors subsequently downloaded OpenSSH (an SSH tunneling tool) [T1105] from an external attacker-controlled server to establish connections between compromised systems and maintain persistence in the victim’s environment [T1572].

After gaining access to an internet-connected workstation used by a network administrator, Gunra actors accessed the SSL-VPN administrative web console and identified an unused account that had access to both the internet-facing and internal corporate networks. The actors modified the account configuration to bypass the mandatory password change requirement enforced on the account and subsequently leveraged it for malicious activities [T1098].

Using stolen session information, Gunra actors gained initial access to the internal virtual desktop infrastructure (VDI) environment and conducted lateral movement via RDP [T1021.001]. The actors pivoted to multiple critical systems, including the VDI authentication web server, the internal Active Directory (AD) server, and virtual desktops assigned to IT personnel.

Credential Access

The FBI observed multiple instances of Gunra actors using secretsdump.py (another Impacket library) to conduct OS credential dumping [T1003.003] against compromised domain controllers to extract password hashes of user accounts from the NT Directory Services (NTDS) file. This enabled pass-the-hash [T1550.002] or pass-the-ticket [T1550.003] attacks for lateral movement into other privileged systems.

For one victim, Gunra actors manipulated the network traffic control functionality of an SSL-VPN appliance to collect credentials and session information transmitted by users authenticating to a corporate VDI authentication portal [T1040]. The actors then used stolen session cookies to conduct session hijacking [T1539], impersonating legitimate users to gain access to the internal network.

For the same victim, the Gunra actors modified authentication processing files on the corporate VDI authentication portal server to allow successful authentication when a specific, Gunra-designated one time password (OTP) value was entered, thereby enabling the continuous bypass of multi-factor authentication (MFA) [T1556.006].

Additionally, the actors accessed a Hiware system access control server via SSH from a compromised virtual desktop and stole a symmetric encryption key stored on the server. The stolen key enabled the actors to decrypt passwords for enterprise server accounts stored within the database [T1555] and perform credential dumping of credentials associated with all enterprise servers [T1003].

Stealth, Defense Impairment, and Discovery

Gunra employs multiple stealth and defense impairment techniques to hinder detection and analysis. While active within victim networks, Gunra actors typically attempt to mask their presence by deleting system/network access logs [T1685] and clearing command history [T1070.003]. Additionally, to evade administrator detection, Gunra actors primarily conduct malicious activities and internal infrastructure reconnaissance [T1049] during late-night and early-morning hours (10:00 p.m. – 06:00 a.m.) [T1678].

The ransomware binary is self-contained and performs full volume encryption without observable network indicators (e.g., domain name system, HTTP).6 The Windows binary includes the IsDebuggerPresent API [T1622], which defends against reverse engineering by detecting if the application is being run in a debugger.7

To avoid dedicating encryptio […]

---

# CISA AA26-204A — Russian State-Supported Cyber Actors Conduct Phishing Campaign Targeting Users of Zimbra Collaboration Suite

Source : CISA, avis de cybersécurité AA26-204A (Tue, 21 Jul 2026 15:08:02 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-204a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Russian State-Supported Cyber Actors Conduct Phishing Campaign Targeting Users of Zimbra Collaboration Suite

Executive summary

A group of Russian state-supported cyber actors has been targeting and compromising various Western government and commercial organizations using the Zimbra Collaboration Suite (ZCS) software since at least July 2025. The Russian state-supported advanced persistent threat (APT) group’s activity is tracked in the cybersecurity community under several names (see Cybersecurity industry tracking), primarily as “LAUNDRY BEAR,” a name initially coined by the Netherlands General Intelligence and Security Service (AIVD) and Defence Intelligence and Security Service (MIVD) [1].

LAUNDRY BEAR’s targeting is almost certainly to gather sensitive information for the Russian Federation, with these actors primarily focusing on the covert acquisition of email data. Previous campaigns indicated LAUNDRY BEAR relied on unsophisticated initial access techniques—including password spraying, phishing, and pass-the-cookie—allowing the group to successfully run high-volume operations. The latest campaign targeting ZCS uses a novel exploit that was a zero-day vulnerability when first exploited and continues to be successfully exploited. The vulnerability, Common Vulnerabilities and Exposures (CVE) CVE-2025-66376, was patched in November 2025. This demonstrates LAUNDRY BEAR’s intent and ability to deploy increasingly sophisticated technical capabilities.

Unlike traditional phishing campaigns that persuade a user into taking an action, such as clicking a link or opening a file, LAUNDRY BEAR’s latest campaign leverages a view-based exploit that only requires a user to view a malicious email within a vulnerable version of the webmail service. Once viewed, the exploit attempts to exfiltrate the victim’s last 90 days of email communications, the organization email directory (i.e., Global Address List [GAL]), and other sensitive information to servers controlled by LAUNDRY BEAR. The exploit also attempts to establish persistent access to victim accounts through a variety of means as detailed in the Persistence and credential access section.

This Cybersecurity Advisory (CSA) warns of this ongoing malicious threat activity and urges organizations to update their vulnerable software and implement additional mitigations to thwart these Russian state-supported actors’ continued success. The CSA is being released by the following authoring and co-sealing agencies:

United States National Security Agency (NSA)

United States Federal Bureau of Investigation (FBI)

Netherlands Defence Intelligence and Security Service (MIVD)

Netherlands General Intelligence and Security Service (AIVD)

United States Cybersecurity and Infrastructure Security Agency (CISA)

United States Defense Counterintelligence and Security Agency (DCSA)

United States Department of Defense Cyber Crime Center (DC3)

United States Department of the Treasury

United States Naval Criminal Investigative Service (NCIS)

Australian Signals Directorate’s Australian Cyber Security Centre (ASD’s ACSC)

Communications Security Establishment Canada’s (CSE’s) Canadian Centre for Cyber Security (Cyber Centre)

New Zealand National Cyber Security Centre (NCSC-NZ)

United Kingdom National Cyber Security Centre (NCSC-UK)

Czech Republic National Cyber and Information Security Agency (NÚKIB)1

Danish Defence Intelligence Service (DDIS)2

Estonian Foreign Intelligence Service (EFIS)3

Finnish Defence Intelligence (FDI)4

Finnish Security and Intelligence Service (SUPO)5

French General Directorate for Internal Security (DGSI)6

French National Cybersecurity Agency (ANSSI)7

Italian External Intelligence and Security Agency (AISE)8

Italian Internal Intelligence and Security Agency (AISI)9

Security and Intelligence Service of the Republic of Moldova (SIS RM)10

Polish Foreign Intelligence Agency (AW)11

The Military Counterintelligence Service of Poland (SKW)12

Spain National Intelligence Centre (CNI)13

Sweden National Cyber Security Centre (NCSC-SE)14

The authoring agencies urge any organizations using ZCS to implement the recommendations listed within the Mitigations section of this advisory to reduce the risk associated with this activity. This CSA also includes specific remediations for organizations to implement if they discover the presence of the listed Indicators of compromise (IOCs).

As more organizations update their ZCS software based on this CSA, LAUNDRY BEAR may discontinue the current campaign exploiting this vulnerability; however, based on the success of this and previous campaigns, it is very likely that the group will continue to target ZCS and other email systems used by organizations in Western countries. The actors will almost certainly continue to rely on email to engage potential victims by exploiting novel vulnerabilities and, when necessary, use social engineering techniques to assist with their efforts. The authoring agencies recommend organizations regularly update their mail service software and continuously monitor their email systems and emails for malicious activity.

For a downloadable list of IOCs, see:

AA26-204A.stix.xml (STIX XML)

AA26-204A.stix.json (STIX JSON)

Cybersecurity industry tracking

The cybersecurity industry provides overlapping cyber threat intelligence, indicators of compromise (IOCs), and mitigation recommendations related to these Russian state-supported cyber actors. While not exhaustive, the following are threat group names commonly used for these actors within the cybersecurity community:

LAUNDRY BEAR

Void Blizzard [2]

CL-STA-1114 [3]

TA488 (formerly UNK_PitStop) [4]

Note: Cybersecurity companies have different methods of tracking and attributing cyber actors, and this may not be a 1:1 correlation to the U.S. government’s understanding for all activity related to these groupings.

Background

Public advisories from Netherlands General Intelligence and Security Service (AIVD), Netherlands Defence Intelligence and Security Service (MIVD), and Microsoft highlighted these Russian state-supported advanced persistent threat (APT) actors in May 2025, calling them LAUNDRY BEAR and Void Blizzard respectively [1] [2]. Both advisories assessed that the group was engaged in malicious cyber activity as early as April 2024.

The May 2025 advisories highlighted a cluster of activity targeting cloud-based email environments, including Microsoft Exchange in particular, and abusing legitimate APIs to perform data exfiltration in bulk [T1114.002]. The group relied on unsophisticated means of initial access, including procuring stolen credentials on criminal marketplaces [T1078], and using social engineering techniques to lure targets into interacting with a malicious site masquerading as a legitimate one. As of April 2025, one of these sites resembled a European Defence & Security Summit registration portal that required registrants to sign in to their Microsoft account to view. Once a user entered their Microsoft credentials into this malicious site, LAUNDRY BEAR’s modified version of the open source adversary emulation toolkit, Evilginx, intercepted the user’s credentials. LAUNDRY BEAR then used this authentication data, including passwords and session tokens, to access the compromised account and conduct mass email exfiltration, as well as harvest other information. This method of compromise is commonly known as an adversary-in-the-middle (AiTM) technique [T1557].

Beginning around July 2025, LAUNDRY BEAR shifted toward a more technical method of email compromise, highlighting their continued efforts to covertly acquire email communications from a variety of Western organizations of interest and deliver them to the Russian Federation. Using a custom-developed capability [T1587.001] named “Улей” or “Ulej” (Russian for beehive), LAUNDRY BEAR successfully targeted and exfiltrated sensitive user information from organizations who use the Zimbra Collaboration Suite (ZCS) product [T1114]. Data LAUNDRY BEAR attempted to exfiltrate from compromised accounts included:

Last 90 days of emails,

Email address,

Password [T1589.001],

Global Address List (GAL) [T1087],

Two-factor authentication (2FA) tokens, and

Newly-created Application Passcode [T1098].

The covert and persistent nature of this activity, along with the absence of any known financial extortion, almost certainly indicates this group’s involvement in espionage activities with Russian government backing. Additionally, extensive Ukrainian targeting, prior to use against U.S. and other NATO allies, outlines an increasing trend within Russian cyber threat groups to target Ukrainian users first—both as a priority target and as a testbench for malicious cyber techniques before broader global deployment.

Targeting details

LAUNDRY BEAR has targeted and compromised users in various organizations, including those associated with:

the Defense Industrial Base (DIB),

the federal and local government,

education,

energy,

law enforcement,

media,

non-governmental organizations, and

technology.

Technical details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 19. This advisory also uses MITRE D3FENDTM version 1.4.015. See Appendix A and Appendix B for tables of the activity mapped to MITRE ATT&CK and D3FEND tactics, techniques, and countermeasures.

Ulej is a novel data exfiltration and aggregation capability, that currently (as of the publication of this report) supports a campaign specifically targeting users of ZCS webmail servers. This capability is used to exploit CVE-2025-66376 [Common Weakness Enumeration (CWE) CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')], but likely could be adapted to exploit other vulnerabilities. It exfiltrates emails and other sensitive user data from a victim’s system immediately after exploitation and stores the data in an actor-controlled unattributable virtual private server (VPS) [T1074.002] running LAUNDRY BEAR’s “Flowerbed” collection framework. The collected data is almost certainly further exfiltrated to internal network resources for review and long-term retention.

Reconnaissance

LAUNDRY BEAR uses the Ulej capability to exploit the CVE-2025-66376 vulnerability in organizations using ZCS. This campaign’s targeted victimology and limited exploitation capabilities likely indicate this group manually identifies and targets the victim organizations. LAUNDRY BEAR likely identifies organizations with public-facing Zimbra infrastructure by port scanning [T1595] and fingerprinting datasets easily procured through various commercial vendors [T1596.005].

After identifying a target organization, the group likely compiles email addresses for individual users to target with the exploit [T1589.002] from datasets offered by commercial vendors [T1597.002], open source intelligence [T1593], or previously exfiltrated data [T1597].

Resource development

The actors procure VPSs from a variety of providers [T1583.003], including those with Know Your Customer (KYC) requirements, and often use fabricated identities. LAUNDRY BEAR primarily uses Mullvad VPN [T1583] when interacting with these servers, further demonstrating the group’s intent to mask their identity and maintain operations security (OPSEC). After the server is provisioned, an automated process deploys the Docker containers necessary for Ulej’s Flowerbed framework [T1608], which then receives and aggregates the data Ulej exfiltrates. These servers are typically only used for 7-60 days before moving to new infrastructure.

Flowerbed framework

Flowerbed is a Python project that uses Docker for containerization. The project includes four different Docker containers:

Catcher,

Certbot,

Nginx, and

Gardener.

Catcher acts as both a DNS and HTTP server to receive and aggregate exfiltrated victim information [T1048]. For additional information on Catcher, refer to the E […]

---

# CISA AA26-194A — Improve Router Hygiene to Protect Against Russian State-Sponsored Targeting

Source : CISA, avis de cybersécurité AA26-194A (Wed, 08 Jul 2026 14:43:49 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-194a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Russian Government-Sponsored Activity Targets Poorly Configured and Vulnerable Devices Across Critical Sectors

Executive summary

Russian Federal Security Service (FSB) Center 16 cyber actors continue to exploit poorly configured and vulnerable networking devices worldwide, opportunistically compromising multiple critical infrastructure sector networks. This joint Cybersecurity Advisory (CSA) builds on FBI’s Russian Government Cyber Actors Targeting Networking Devices, Critical Infrastructure Public Service Announcement of the decade-plus FSB Center 16 cyber activity by providing additional tactics, techniques, and procedures (TTPs) to enable defenders to more fully understand and counter the threat. [1]

This CSA is being released by the following authoring and co-sealing agencies:

United States National Security Agency (NSA)

United States Cybersecurity and Infrastructure Security Agency (CISA)

United States Federal Bureau of Investigation (FBI)

United States Department of Defense Cyber Crime Center (DC3)

Australian Signals Directorate’s Australian Cyber Security Centre (ASD’s ACSC)

Communications Security Establishment Canada’s (CSE’s) Canadian Centre for Cyber Security (Cyber Centre)

New Zealand National Cyber Security Centre (NCSC-NZ)

United Kingdom National Cyber Security Centre (NCSC-UK)

Czech Republic National Cyber and Information Security Agency (NÚKIB)1

Danish Defence Intelligence Service (DDIS)2

Estonian Foreign Intelligence Service (EFIS)3

Estonian Information System Authority (RIA)4

Finnish Defence Intelligence (FDI)5

Finnish Security and Intelligence Service (SUPO)6

French National Cybersecurity Agency (ANSSI)7

Italian External Intelligence and Security Agency (AISE)8

Italian Internal Intelligence and Security Agency (AISI)9

The Military Counterintelligence Service of Poland (SKW)10

Sweden National Cyber Security Centre (NCSC-SE)11

The authoring and co-sealing agencies strongly urge device owners and network defenders to take mitigation and remediation actions against Russian government-sponsored exploitation of vulnerable routers.

Figure 1: FSB Center 16 activity and recommended mitigation actions

Download the PDF version of this report:

Improve Router Hygiene to Protect Against Russian State-Sponsored Targeting (PDF, 816KB)

Cybersecurity industry tracking

The cybersecurity industry provides overlapping cyber threat intelligence, indicators of compromise (IOCs), and mitigation recommendations related to this activity. Although not all encompassing, the following list contains the most notable threat group names commonly used within the cybersecurity community related to this activity:

Berserk Bear

Energetic Bear

Crouching Yeti

Dragonfly

Ghost Blizzard

Static Tundra

Note: Cybersecurity companies have different methods of tracking and attributing cyber actors, and this list may not provide a 1:1 correlation to the authoring agencies’ understanding for all activity related to these groupings.

Targeting details

Critical infrastructure sectors most at risk from the Russian Federal Security Service (FSB) Center 16 cyber actors’ targeting include:

Communications,

Defense Industrial Base,

Energy,

Financial Services,

Government Services and Facilities, especially organizations at the state and local level, and

Healthcare and Public Health.

Technical details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise12 framework, version 19. See Appendix A for tables of the activity mapped to MITRE ATT&CK tactics and techniques. This advisory also uses MITRE DEFENDTM version 1.4.0.

The Russian FSB Center 16 cyber actors primarily use scanning to identify poorly configured networking devices, primarily routers, for exploitation. The actors scan for Internet IP ranges with active Simple Network Management Protocol (SNMP) agents that accept common or default community strings for authentication [T1595.001, T1595.002]. These scans, run via proxies, consist of SNMP Set-Requests from a spoofed IP address [T1027] containing Object Identifiers (OIDs) that instruct the SNMP agent on poorly configured networking devices to [T1569, T1602.001, T1090]:

Copy its configuration to a file, often called “config.bkp” or “output.txt” [T1003, T1602.002].

Transfer the file, typically using Trivial File Transfer Protocol (TFTP), to an actor-controlled leased virtual private server (VPS) or compromised FTP server [T1583.003, T1090, T1071, T1048].

While SNMP scanning is the primary method the actors use to discover and exploit poorly configured networking devices, they occasionally exploit common vulnerabilities and exposures (CVEs) in Cisco devices, Cisco’s Smart Install (SMI) functionality, and web portals to manage network devices. The actors previously exploited at least the following CVEs [T1584.008, T1588.005, T1190, T1068]:

CVE-2018-0171

CVE-2008-412813

Many of these TTPs overlap with activity by other malicious cyber actors, such as Salt Typhoon. Even though this CSA focuses on Russian FSB Center 16 cyber activity, the mitigations below should detect and counter these and similar TTPs used by other actors.

Mitigation actions

The authoring agencies highly recommend network defenders implement the following mitigations to harden networks against this exploitation:

Disable Cisco Smart Install on all devices [D3-ACH]. [2]

Use SNMPv3 with “authPriv” configured to the most modern encryption standard that is supported by the device instead of SNMPv1 or SNMPv2 [D3-ACH]. [3]

Disable SNMPv1 and SNMPv2. These are legacy protocols and should no longer be needed on current devices. If they are necessary, change all community strings from defaults and only allow read-only community strings rather than read-write access.

SNMPv3 adds strong authentication and data encryption that are unavailable in SNMPv1 and v2. SNMPv3 replaces clear text shared passwords, known as community strings, with more securely encoded parameters, and authenticates and encrypts data [D3-MAN, D3-MENCR].

Use strong, unique passwords for local accounts on network devices and configure credentials to be stored securely to prevent reuse of compromised passwords [D3-CH].

Cisco devices protect passwords in the configuration file using different hashing types. Use hashing type 8 for user credentials. Avoid using hashing type 0, 4, and 7 as they are insecure or store passwords in plaintext in the configuration file. [4]

Monitor for unusual credentials that do not conform to standard organizational naming conventions [D3-PM].

Monitor for and alert on logins using local accounts. Local accounts should only be used in emergency situations when accounts supported by centralized authentication servers are unavailable. Centralized authentication to network devices should support multi-factor authentication where feasible. [3]

Monitor and restrict access to SNMP OIDs using a Management Information Base (MIB) allow list [D3-ACH]. [5] Reference the vendor-specific MIB for the network devices and monitor OIDs for indications of reconnaissance or misconfiguration in logs or intrusion detection systems (IDS). IDS rules should be written for inbound SNMP Set-Requests that contain OIDs targeting sensitive device data [D3-PM].

Example OIDs include:

1.3.6.1.4.1.9.9.96.1.1 (Cisco Config Copy)

1.3.6.1.4.1.9.9.96.1.1.1.1.5 (Config Copy Server Address, value for this OID is where the configuration file is being sent to)

Restrict management protocols [D3-NTF].

Use Access Control Lists (ACLs) to only allow management protocols, such as SNMP, from management devices, preferably on an out-of-band network. [3]

On edge firewalls and devices deny all external communications on the following ports unless mission critical, with strict monitoring if blocking is not feasible:

User Datagram Protocol (UDP) port 69 (TFTP)

Transmission Control Protocol (TCP) port 4786 (SMI)

UDP ports 161 and 162 (SNMP)

TCP/UDP ports 10161 and 10162 (SNMPv3)

Update network device software and firmware images, especially to patch known vulnerabilities, and upgrade end-of-life devices to supported ones.

Use an attack surface management service to identify and secure Internet-facing systems with weak configurations and known vulnerabilities [D3-NVA].

U.S.-based federal, state, local, tribal, and territorial governments and U.S. critical infrastructure organiztions should consider signing up for CISA’s no-cost Cyber Hygiene services.

U.S. Defense Industrial Base organizations should consider signing up for NSA’s DIB Cybersecurity Services.

Resources

United States:

Russia Threat Overview and Advisories

Network Infrastructure Security Guide

Canada:

Routers cyber security best practices (ITSAP.80.019)

Security considerations for edge devices (ITSM.80.101)

Guidance on securely configuring network protocols (ITSP.40.062)

Baseline security requirements for network security zones (ITSP.80.022)

Top 10 IT security actions to protect Internet-connected networks and information (ITSM.10.089)

Works cited

[1] FBI. Russian Government Cyber Actors Targeting Networking Devices, Critical Infrastructure. Alert Number: I-082025-PSA. 2025. https://www.ic3.gov/PSA/2025/PSA250820

[2] NSA. Cisco Smart Install Protocol Misuse. 2017. https://media.defense.gov/2019/Jul/16/2002157833/-1/-1/0/CSA-CISCO-SMART-INSTALL-PROTOCOL-MISUSE.PDF

[3] NSA. Network Infrastructure Security Guide. 2023. https://media.defense.gov/2022/Jun/15/2003018261/-1/-1/0/CTR_NSA_NETWORK_INFRASTRUCTURE_SECURITY_GUIDE_20220615.PDF

[4] NSA. Cybersecurity Information Sheet Cisco Password Types: Best Practices. 2022. https://media.defense.gov/2022/Feb/17/2002940795/-1/-1/0/CSI_CISCO_PASSWORD_TYPES_BEST_PRACTICES_20220217.PDF

[5] NSA. Cybersecurity Information Sheet: Reducing the Risk of Simple Network Management Protocol (SNMP) Abuse. 2026. https://media.defense.gov/2026/Jul/09/2003959459/-1/-1/0/CSI_REDUCING_RISK_OF_SNMP_ABUSE.PDF

Footnotes

1 Národní úřad pro kybernetickou a informační bezpečnost

2 Forsvarets Efterretningstjeneste

3 Välisluureamet

4 Riigi Infosüsteem Amet

5 Sotilastiedustelu

6 Suojelupoliisi

7 Agence nationale de la sécurité des systèmes d’information

8 Agenzia Informazioni e Sicurezza Esterna

9 Agenzia Informazioni e Sicurezza Interna

10 Służba Kontrwywiadu Wojskowego

11 Nationellt Cybersäkerhetscenter

12 MITRE and ATT&CK are registered trademarks of The MITRE Corporation. MITRE DEFEND is a trademark of the MITRE Corporation.

13 CVE-2008-4128 only affects end-of-life Cisco devices.

Disclaimer of Endorsement

The information and opinions contained in this document are provided "as is" and without any warranties or guarantees. Reference herein to any specific commercial products, process, or service by trade name, trademark, manufacturer, or otherwise, does not constitute or imply its endorsement, recommendation, or favoring by the United States Government, and this guidance shall not be used for advertising or product endorsement purposes.

Purpose

This document was developed in furtherance of the authoring agencies’ cybersecurity missions, including their responsibilities to identify and disseminate threats, and to develop and issue cybersecurity specifications and mitigations. This information may be shared broadly to reach all appropriate stakeholders.

Contact

United States organizations

National Security Agency (NSA)

Cybersecurity Report Feedback: CybersecurityReports@nsa.gov

Defense Industrial Base Inquiries and Cybersecurity Services: DIB_Defense@cyber.nsa.gov

Media Inquiries / Press Desk: NSA Media Relations: 443-634-0721, MediaRelations@nsa.gov

Cybersecurity and Infrastructure Security Agency (CISA) and Federal Bureau of Investigation (FBI)

U.S. organizations are encouraged to report suspicious or criminal activity related to information in this advisory to CISA via the agency’s Incident Reporting System, its 24/7 Operations Center (report@cisa.gov or 888-282-0870), or your local FBI field office. When […]

---

# CISA AA26-113A — Defending Against China-Nexus Covert Networks of Compromised Devices

Source : CISA, avis de cybersécurité AA26-113A (Tue, 21 Apr 2026 11:12:37 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-113a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Defending against china-nexus covert networks of compromised devices

executive summary

Defending against China-nexus covert networks of compromised devices

Explaining the widespread shift in tactics, techniques and procedures (TTPs) towards networks of compromised infrastructure, and how to defend against it

Summary

With support from the UK Cyber League, this advisory has been jointly released by the National Cyber Security Centre (NCSC-UK) and international partners:

Australian Signals Directorate’s (ASD’s) Australian Cyber Security Centre (ACSC)

Communications Security Establishment Canada’s (CSE’s) Canadian Centre for Cyber Security (Cyber Centre)

Germany Federal Office for the Protection of the Constitution - Bundesamt für Verfassungsschutz (BfV)

Germany Federal Intelligence Service – Bundesnachrichtendienst (BND)

Germany Federal Office for Information Security - Bundesamt für Sicherheit in der Informationstechnik (BSI)

Japan National Cybersecurity Office (NCO) - 国家サイバー統括室

Netherlands General Intelligence and Security Service - Algemene Inlichtingen- en Veiligheidsdienst (AIVD)

Netherlands Defence Intelligence and Security Service - Militaire Inlichtingen- en Veiligheidsdienst (MIVD)

New Zealand National Cyber Security Centre (NCSC-NZ)

Spain National Cryptologic Centre – Centro Criptológico Nacional (CCN)

Sweden National Cyber Security Centre - Nationellt cybersäkerhetscenter (NCSC-SE)

United States Cybersecurity and Infrastructure Security Agency (CISA)

United States Department of Defense Cyber Crime Center (DC3)

United States Federal Bureau of Investigation (FBI)

United States National Security Agency (NSA)

Its purpose is to provide network defenders with the tools needed to defend against China-nexus cyber actors and their tactic of using large scale networks of compromised devices (covert networks) to route their cyber activity.

Introduction

Over the past few years there has been a major shift in the tactics, techniques and procedures (TTPs) used by China-nexus cyber actors, moving away from the use of individually procured infrastructure, and towards the use of externally provisioned, large-scale networks of compromised devices.

The NCSC believes that the majority of China-nexus threat actors are using these networks (hereafter “covert networks”), that multiple covert networks have been created and are being constantly updated, and that a single covert network could be being used by multiple actors. These networks are mainly made up of compromised Small Office Home Office (SOHO) routers, as well as Internet of Things (IoT) and smart devices.

Anyone who is a target of China-nexus cyber actors may be impacted by the use of covert networks. They have been used by Chinese state-sponsored actors Volt Typhoon to pre-position offensive cyber capabilities on critical national infrastructure. The group Flax Typhoon used a different covert network of compromised infrastructure to conduct cyber espionage.

The use of covert networks of compromised devices - also known as botnets - to facilitate malicious cyber activity is not new, but China-nexus cyber actors are now using them strategically, and at scale.

This advisory describes the typical makeup of a covert network and what they are being used for. It also includes protective advice for organizations being targeted by cyber activity using a covert network as an access vector.

Covert Networks

Covert networks are used to connect across the internet in a low-cost, low-risk, deniable way, disguising the origin and attribution of malicious activity. Actors have been observed using them for each phase of their Cyber Kill Chains, from performing scans as part of reconnaissance, to the delivery of malware, communicating with said malware, and exfiltrating stolen data from a victim. They can also be used for general deniable internet browsing, allowing threat actors to research exploitation techniques, new TTPs, and their victims without attribution. Some covert networks are also used by legitimate customers to browse the internet, making it challenging to attribute malicious activity.

There is evidence that covert networks used by China-nexus actors are created and maintained by Chinese information security companies. A network known to network defenders as Raptor Train, which in 2024 infected more than 200,000 devices worldwide, was controlled and managed by the Chinese company, Integrity Technology Group. This company was also assessed by the FBI to be responsible for the computer intrusion activities attributed to China-based hackers known as Flax Typhoon.

Botnet operations represent a significant threat to the UK by exploiting vulnerabilities in everyday internet-connected devices with the potential to carry out large-scale cyber attacks – NCSC Director of Operations, Paul Chichester

Covert networks mostly consist of compromised SOHO routers, but they also pull in any vulnerable device they can exploit at scale. Raptor Train was made up of thousands of SOHO routers and IoT devices, such as web cameras and video recorders, as well as firewalls and Network Attached Storage (NAS) devices. The KV Botnet used by Volt Typhoon was mainly made up of vulnerable Cisco and NetGear routers. The edge devices were vulnerable because they were “end of life” – out of date and no longer receiving updates or security patches by their manufacturers.

The cyber security industry has been aware of examples of these networks for some time and has publicly reported on the widespread scale of the threat and its implications. Mandiant Intelligence produced a public blog in May 2024 talking about covert networks in which they highlighted a key issue for defenders – indicator of compromise (IOC) Extinction. If a particular threat group could now come from one of many covert networks, each with potentially hundreds of thousands of endpoints, and each used by multiple threat actors, old network defense paradigms of static malicious IP block lists will be less effective. This is compounded by the dynamic nature of these networks where new nodes will be added as old devices are patched or removed from use.

Typical Network Topology

The number of covert networks used by China-nexus cyber actors is large, with new networks regularly developed and deployed. The existing covert networks change too, either because of defensive or legal action, or simply as a result of software updates and new exploits being used to target different technologies for incorporation into the network.

Because of this, a description of all known covert networks in detail, including how they are constructed and how they communicate, would immediately be out of date – and for most network defenders would not be practically useful.

However, most covert networks of compromised devices use the same basic set up. Understanding this generalized structure can aid researchers and defenders by helping them to understand which part of a network they may have found, and how to defend against it.

A diagram illustrating the basic setup of a covert network.

The diagram above illustrates the basic setup of a covert network, where typically an actor will connect to the network via an on-ramp or entry node. Their traffic will be forwarded through multiple compromised devices, used as traversal nodes, before exiting the network from an exit node, usually in the same geographic region as the target.

Protective Advice

Defending from attackers using covert networks is not straightforward, and defensive tactics will be different based on the levels of resource and the nature of the target organization. General advice for good cyber security practice should be followed, and some key messages can be found in the appendix of this advisory.

The following advice is specifically tailored to steps which can be taken to combat the risk of attacks coming from large, dynamic networks of compromised devices.

Further guidance for all organizations facing cyber security threats is available on the NCSC website.

This guidance should be considered alongside all applicable laws and regulations of the UK and co-sealing countries relating to the security of networks and data. It will be each organization’s responsibility to ensure compliance with any such laws and regulations. Organizations should note that following the recommended actions set out below will not remove all risks.

All organizations

The NCSC recommends the following steps for all affected organizations to either take themselves, or ask their managed service and/or security providers to investigate for them:

Map and understand network edge devices, developing a clear understanding of organizational assets and what should be connecting to them.

Baseline normal connections, especially to corporate virtual private networks (VPNs) or other similar services.

Would you expect connections from consumer broadband ranges?

Leverage available dynamic threat feeds which include covert network infrastructure.

Implement multifactor authentication for remote connections.

Smaller organizations should consider creating and actioning a free NCSC Cyber Action Toolkit.

Larger or more at-risk organizations

Some more comprehensive measures may be appropriate if the risk to an organization is high enough, to be conducted either in-house or through a security provider:

Apply IP address allow lists rather than deny lists for connections to corporate VPNs for remote workers.

Use geographic allow lists or profile incoming connections based on operating system, time zones, and/or organization specific system configuration settings.

Implement zero trust policies for connections.

Enforce machine certificates for Secure Sockets Layer (SSL) connections.

Reduce the internet-facing presence of the IT estate.

Investigate machine learning techniques to profile normal network edge activity to detect and block anomalies.

The NCSC's Cyber Essentials can help protect organizations of all sizes.

Largest or most at-risk organizations

If Advanced Persistent Threat (APT) tracking is part of an organization’s in-house capability, or if it is part of the service provided by a security vendor, consider tracking China-nexus covert networks as APTs in their own right.

Active hunting – look for connections from IP addresses likely to be part of a covert network of compromised devices, for instance those hosting SOHO routers or IoT devices.

Track and map covert networks reported by industry or government by looking at banners and certificates.

Use threat reporting and threat feeds to create and implement dynamic blocklists and create alert rules to detect incoming threats.

Consider using NetFlow feeds to look upstream and map covert networks to find new nodes.

The NCSC Cyber Assessment Framework provides guidance for organizations under the highest levels of threat, including those operating essential services, in sectors such as energy, healthcare, transport, digital infrastructure and government.

MITRE ATT&CK®

This advisory has been compiled with respect to the MITRE ATT&CK® framework, a globally accessible knowledge base of adversary tactics and techniques based on real-world observations.

Tactic

ID

Technique

Procedure

Resource Development

T1584.005

Compromise Infrastructure: Botnet

Botnets are used as core components of covert networks

Resource Development

T1584.008

Compromise Infrastructure: Network Devices

Devices are compromised and added to botnets

Resource Development

T1583.003

Acquire Infrastructure: Virtual Private Server

Virtual private servers (VPS) are used in covert networks, typically as on-ramps

Command and Control

T1090.003

Proxy: Multi-hop Proxy

Used by China-nexus cyber actors to route traffic

Appendix: Cyber Security Best Practices

In addition to the protective advice outlined in this advisory, a number of cyber security best practices will also be useful in defending against the activity described […]

---

# CISA AA26-097A — Iranian-Affiliated Cyber Actors Exploit Programmable Logic Controllers Across US Critical Infrastructure

Source : CISA, avis de cybersécurité AA26-097A (Mon, 06 Apr 2026 07:03:58 EDT) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Advisory at a Glance

Title

Iranian-Affiliated Cyber Actors Exploit Programmable Logic Controllers Across US Critical Infrastructure

Original Publication

April 7, 2026

Last Update

July 22, 2026

Executive Summary

The authoring agencies urgently warn U.S. organizations of ongoing Iranian-affiliated cyber targeting of internet-connected operational technology (OT) devices, including programmable logic controllers (PLCs). These actions disrupted PLCs across several U.S. critical infrastructure sectors through malicious project file interactions and manipulation of data on human machine interface (HMI) and supervisory control and data acquisition (SCADA) displays, resulting in operational disruption and financial loss.

Last Update Description

This update adds new guidance on detecting malicious changes in reusable code modules exploited within Rockwell Automation PLC programs. It also expands scope to include observed targeting of Schneider Electric, Siemens, and potentially other branded/manufactured PLCs, emphasizing the importance of restricting direct internet access and providing best practices for secure deployment.

Affected Products

Potentially all internet exposed PLCs, including Rockwell Automation/Allen-Bradley, Schneider Electric, Siemens, and other branded/manufactured PLCs.

Key Actions

Install PLCs consistent with manufacturers' guidelines and security best practices.

Remove PLCs from direct internet exposure via secure gateway and firewall; work with IT/OT team members and/or integrators to perform this action.

Query available logs for the provided indicators of compromise (IOCs) and check available logs for suspicious traffic on the ports associated with OT devices, including 44818, 2222, 102, and 502, especially traffic originating from foreign hosting providers.

For Rockwell Automation devices, place the physical mode switch on the controller into run position. If you suspect your organization was targeted, including against other branded PLC devices, contact the authoring agencies and PLC manufacturer for guidance.

Indicators of Compromise

For a downloadable copy of July 22, 2026 IOCs, see:

AA26-097A STIX XML (July 2026) (29 KB)

AA26-097A STIX JSON (July 2026) (30 KB)

For a downloadable copy of historical April 7, 2026 IOCs, see:

AA26-097A STIX XML (36 KB)

AA26-097A STIX JSON (12 KB)

Intended Audience

Organizations: Critical Infrastructure

Sectors: Government Services and Facilities, Water and Wastewater Systems (WWS), and Energy

Roles: Integrators, asset owners, defensive cybersecurity analysts, OT cybersecurity engineers, cybersecurity architects, secure systems developer

Introduction

Note: This advisory was originally published on April 7, 2026, to provide tactics, techniques, and procedures (TTPs) and indicators of compromise (IOCs) related to ongoing cyber exploitation of internet-connected operational technology (OT) devices by Iranian-affiliated advanced persistent threat (APT) actors. The authoring agencies updated this advisory on July 22, 2026, to add new guidance on detecting malicious changes in reusable code modules leveraged within Rockwell Automation PLC programs. It also expands the manufacturer scope to include observed targeting of Schneider Electric, Siemens, and potentially other branded/manufactured PLCs, emphasizing the importance of restricting direct internet access and providing best practice resources for secure deployment.

The Federal Bureau of Investigation (FBI), Cybersecurity and Infrastructure Security Agency (CISA), National Security Agency (NSA), Environmental Protection Agency (EPA), Department of Energy (DOE), United States Cyber Command – Cyber National Mission Force (CNMF), and Department of the Treasury (Treasury) (hereafter referred to as the “authoring agencies”) are urgently warning U.S. organizations of ongoing cyber exploitation of internet-connected OT devices—including PLCs manufactured by Rockwell Automation/Allen-Bradley, Schneider Electric, Siemens, and potentially other manufactured PLCs—across multiple U.S. critical infrastructure sectors. As a result of this activity, organizations from multiple U.S. critical infrastructure sectors experienced disruptions through malicious interactions with PLC project files1 and the manipulation of data displayed on human machine interface (HMI) and supervisory control and data acquisition (SCADA) displays. In a few cases, this activity caused operational disruption and financial loss.

The authoring agencies assess a group of Iranian-affiliated APT actors is conducting this activity to cause disruptive effects within the United States. The group targeted devices spanning multiple U.S. critical infrastructure sectors, including Government Services and Facilities (to include local municipalities), Water and Wastewater Systems (WWS), and Energy Sectors. The authoring agencies previously reported on similar activity targeting PLCs by CyberAv3ngers (aka Shahid Kaveh Group)—a cyber threat actor affiliated with Iran’s Islamic Revolutionary Guard Corps (IRGC) Cyber Electronic Command (CEC).

Due to the widespread use of these PLCs, and the potential for additional targeting of other branded OT devices across critical infrastructure, the authoring agencies recommend U.S. organizations urgently review the TTPs and IOCs in this advisory for indications of current or historical activity on their networks, and apply the recommendations listed in the Mitigations section of this advisory to reduce the risk of compromise.

If owners and operators discover an affected internet-accessible device in their environment, additional technical measures may be necessary to evaluate the risk of compromise. Please engage your cyber incident response plans and contact the authoring agencies and applicable vendors through existing support channels available to customers and integrators (see Contact Information) to receive support, mitigation, and investigation assistance.

For more information on Iranian malicious cyber activity, see CISA’s Iran Threat Overview and Advisories webpage and the FBI’s Iran Threat and Iran Cyber Threat Overview webpages.

Download the PDF version of this report:

Iranian-Affiliated Cyber Actors Exploit Programmable Logic Controllers Across US Critical Infrastructure
(PDF, 1.09 MB
)

(New, July 22, 2026) For a downloadable copy of July 22, 2026 IOCs, see:

AA26-097A STIX XML (XML, 29 KB)

AA26-097A STIX JSON (JSON, 30 KB)

For a downloadable copy of historical April 7, 2026 IOCs, see:

AA26-097A.stix_.xml
(XML, 35.97 KB
)

AA26-097A.stix_.json
(JSON, 11.87 KB
)

Background Information

Similar Historical Activity Targeting Programmable Logic Controllers

During a similar campaign beginning in November 2023, the IRGC CEC-affiliated cyber threat actors known as "CyberAv3ngers” targeted U.S.-based PLCs and HMIs, causing disruptive effects. Private industry and open sources also refer to this group as Hydro Kitten, Storm-0784, APT Iran, Bauxite, Mr. Soul, Soldiers of Solomon, UNC5691, and the Shahid Kaveh Group. These attacks compromised at least 75 devices, targeting U.S.-based Unitronics PLC devices with an HMI used across multiple critical infrastructure sectors, including the WWS. APT actors developed and deployed custom ladder logic code to these devices, replacing the valid ladder logic with malicious code that continues to be observed to date.

For more information on this group’s activity, see the joint Cybersecurity Advisory IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors, Including US Water and Wastewater Systems Facilities.

Ongoing Threat Actor Activity Against U.S.-Based Programmable Logic Controllers

The FBI observed Iranian-affiliated APT actors targeting internet-exposed PLCs with the intent to cause disruptions—including maliciously interacting with project files, and manipulating data displayed on HMI and SCADA displays—to U.S. critical infrastructure organizations. Iranian-affiliated APT targeting campaigns against U.S. critical infrastructure have recently escalated, likely in response to hostilities between Iran, and the United States and Israel.

(New, July 22, 2026) At one U.S. victim, the FBI observed the APT actors download a malicious project file to a targeted PLC using configuration software. Analysis indicated the project file retained ladder logic for downstream function but added logic that overrode specific instruction sets responsible for maintaining safe operating parameters in the victim’s environment.

Since at least March 2026, the authoring agencies identified (through engagements with victim organizations) an Iranian-affiliated APT group disrupted the function of PLCs. Organizations across several U.S. critical infrastructure sectors (including Government Services and Facilities, WWS, and Energy Sectors) deployed these PLCs within a wide variety of industrial automation processes. Some of the victims experienced operational disruption and financial loss.

Technical Details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 19. See the MITRE ATT&CK Tactics and Techniques section of this advisory for tables of the threat actors’ activity mapped to MITRE ATT&CK tactics and techniques.

Initial Access

(Updated, July 22, 2026) The authoring agencies observed Iranian-affiliated APT actors using several foreign-based IP addresses to access internet-facing PLCs manufactured by Rockwell Automation/Allen-Bradley, Schneider Electric, Siemens, and potentially other manufactured PLCs [T0883]. The actors used leased, third-party hosted infrastructure and manufacturers’ PLC programming software to connect to misconfigured victim PLCs. Inbound malicious traffic has been observed targeting PLC devices on the following ports: 44818, 2222, 102, and 502, as well as targeting modems on port 22. Targeted devices include:

Rockwell Automation: CompactLogix and Micro850 PLCs

Schneider Electric: BMX P34/Modicon M340 PLCs

Siemens: S7-1200 series PLCs

Command and Control

(Updated, July 22, 2026) The targeting of ports [T0885] associated with other OT vendors’ protocols suggests these actors are opportunistically targeting devices manufactured by companies other than Rockwell Automation/Allen-Bradley, including Schneider Electric and Siemens. In one reported instance, the actors utilized Dropbear Secure Shell (SSH) software on victim modems to enable them to gain remote access through port 22 [T1219].

Exfiltration

(New, July 22, 2026) The authoring agencies observed Iranian-affiliated APT actors using configuration software—such as Rockwell Automation’s Studio 5000 Logix Designer, Schneider Electric’s EcoStruxure Control Expert, and Siemens’ Totally Integrated Automation (TIA) Portal—on leased, third-party hosted infrastructure to exfiltrate device project files from PLC devices to threat-actor-controlled infrastructure [T1041].

Impact

(Updated, July 22, 2026) After the actors extracted device project files, the FBI and CISA identified the modification and deletion of project file logic, to include Add-On Instructions (AOIs) and data manipulation on HMI and SCADA displays [T1565]. Additionally, the changes disabled critical shutdown and alarm logic, allowing systems to enter unsafe conditions without notifying operators of the anomalies.

Note: An AOI is analogous to a “Function Block” or “User Defined Function Block” used in other PLC vendor programs.

Indicators of Compromise

See Table 1 and Table 2 for recent IP addresses used by the Iranian-affiliated APT actors to communicate with PLCs manufactured by Rockwell Automation/Allen-Bradley, Schneider Electric, and Siemens in the United States.

Disclaimer: The FBI observed the threat actors using the IP addresses listed below in the specified time frames. This data is being provided for customers to query against logs for indications of historical targeting by the Iranian-affiliated APT actors. The authoring agencies recommend o […]

---

# CISA AA25-343A — Pro-Russia Hacktivists Conduct Opportunistic Attacks Against US and Global Critical Infrastructure

Source : CISA, avis de cybersécurité AA25-343A (Fri, 05 Dec 2025 14:35:38 EST) — https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-343a — domaine public (œuvre du gouvernement fédéral américain). Contenu tiers rapporté à titre documentaire.

Summary

Note: This joint Cybersecurity Advisory is being published as an addition to the Cybersecurity and Infrastructure Security Agency (CISA) May 6, 2025, joint fact sheet Primary Mitigations to Reduce Cyber Threats to Operational Technology and European Cybercrime Centre’s (EC3) Operation Eastwood, in which CISA, Federal Bureau of Investigation (FBI), Department of Energy (DOE), Environmental Protection Agency (EPA), and EC3 shared information about cyber incidents affecting the operational technology (OT) and industrial control systems (ICS) of critical infrastructure entities in the United States and globally.

FBI, CISA, National Security Agency (NSA), and the following partners—hereafter referred to as “the authoring organizations”—are releasing this joint advisory on the targeting of critical infrastructure by pro-Russia hacktivists:

U.S. Department of Energy (DOE)

U.S. Environmental Protection Agency (EPA)

U.S. Department of Defense Cyber Crime Center (DC3)

Europol European Cybercrime Centre (EC3)

EUROJUST – European Union Agency for Criminal Justice Cooperation

Australian Signals Directorate’s Australian Cyber Security Centre (ASD’s ACSC)

Canadian Centre for Cyber Security (Cyber Centre)

Canadian Security Intelligence Service (CSIS)

Czech Republic Military Intelligence (VZ)

Czech Republic National Cyber and Information Security Agency (NÚKIB)

Czech Republic National Centre Against Terrorism, Extremism, and Cyber Crime (NCTEKK)

French National Cybercrime Unit – Gendarmerie Nationale (UNC)

French National Jurisdiction for the Fight Against Organized Crime (JUNALCO)

German Federal Office for Information Security (BSI)

Italian State Police (PS)

Latvian State Police (VP)

Lithuanian Criminal Police Bureau (LKPB)

New Zealand National Cyber Security Centre (NCSC-NZ)

Romanian National Police (PR)

Spanish Civil Guard (GC)

Spanish National Police (CNP)

Swedish Polisen (SC3)

United Kingdom National Cyber Security Centre (NCSC-UK)

The authoring organizations assess pro-Russia hacktivist groups are conducting less sophisticated, lower-impact attacks against critical infrastructure entities, compared to advanced persistent threat (APT) groups. These attacks use minimally secured, internet-facing virtual network computing (VNC) connections to infiltrate (or gain access to) OT control devices within critical infrastructure systems. Pro-Russia hacktivist groups—Cyber Army of Russia Reborn (CARR), Z-Pentest, NoName057(16), Sector16, and affiliated groups—are capitalizing on the widespread prevalence of accessible VNC devices to execute attacks against critical infrastructure entities, resulting in varying degrees of impact, including physical damage. Targeted sectors include Water and Wastewater Systems, Food and Agriculture, and Energy.

The authoring organizations encourage critical infrastructure organizations to implement the recommendations in the Mitigations section of this advisory to reduce the likelihood and impact of pro-Russia hacktivist-related incidents. For additional information on Russian state-sponsored malicious cyber activity, see CISA’s Russia Threat Overview and Advisories webpage.

Download the PDF version of this report:

AA25 343A Pro-Russia Hacktivists Conduct Opportunistic Attacks Against US and Global Critical Infrastructure
(PDF, 1.70 MB
)

Background and Development of Pro-Russia Hacktivist Groups

Over the past several years, the authoring organizations have observed pro-Russia hacktivist groups conducting cyber operations against numerous organizations and critical infrastructure sectors worldwide. The escalation of the Russia-Ukraine conflict in 2022 significantly increased the number of these pro-Russia groups. Consisting of individuals who support Russia’s agenda but lack direct governmental ties, most of these groups target Ukrainian and allied infrastructure. However, among the increasing number of groups, some appear to have associations with the Russian state through direct or indirect support.

Cyber Army of Russia Reborn

The authoring organizations assess that the Russian General Staff Main Intelligence Directorate (GRU) Main Center for Special Technologies (GTsST) military unit 74455—tracked in the cybersecurity community under several names (see Appendix B: Additional Designators Used for Cited Groups)—is likely responsible for supporting the creation of CARR —also known as “The People’s Cyber Army of Russia”—in late February or early March of 2022. Actors suspected to be from GRU unit 74455 likely funded the tools CARR threat actors used to conduct distributed denial-of-service (DDoS) attacks through at least September 2024.

In April 2022, the group began using a new Telegram channel featuring the name “CyberArmyofRussia_Reborn” to organize and plan group actions. The channel creators recruited actors to use CARR as an unattributable platform for conducting cyber activities beneath the level of an APT, aimed at deterring anti-Russia rhetoric. CARR threat actors presented themselves as a group of pro-Russia hacktivists supporting Russia’s stance on the Ukrainian conflict, and they soon began claiming responsibility for DDoS attacks against the U.S. and Europe for supporting Ukraine.

CARR documented these actions through embellished images and videos shared on their social media channels, promoting Russian ideology, disseminating talking points, and publicizing leaked information from hacks attributed to Russian state threat actors.

In late 2023, CARR expanded their operations to include attacks on industrial control systems (ICS), claiming an intrusion against a European wastewater treatment facility in October 2023. In November 2023, CARR targeted human-machine interface (HMI) devices, claiming intrusions at two U.S. dairy farms.

The authoring organizations assess that by late September 2024, CARR channel administrators became dissatisfied with the level of support and funding provided by the GRU. This dissatisfaction led CARR administrators and an administrator from another hacktivist group, NoName057(16), to create the Z-Pentest group, employing the same tactics, techniques, and procedures (TTPs) as CARR but separate from GRU involvement.

NoName057(16)

The authoring organizations assess that the Center for the Study and Network Monitoring of the Youth Environment (CISM), established on behalf of the Kremlin, created NoName057(16) as a covert project within the organization. Senior executives and employees within CISM developed and customized the NoName057(16) proprietary DDoS tool DDoSia, paid for the group’s network infrastructure, served as administrators on NoName057(16) Telegram channels, and selected DDoS targets.

Active since March 2022, NoName057(16) has conducted frequent DDoS attacks against government and private sector entities in North Atlantic Treaty Organization (NATO) member states and other European countries perceived as hostile to Russian geopolitical interests. The group operates primarily through Telegram channels and used GitHub, alongside various websites and repositories, to host DDoSia and share materials and TTPs with their followers.

In 2024, NoName057(16) began collaborating closely with other pro-Russia hacktivist groups, operating a joint chat with CARR by mid-2024. In July 2024, NoName057(16) jointly claimed responsibility with CARR for an alleged intrusion against OT assets in the U.S. The high degree of cooperation with CARR likely contributed to the formation of Z-Pentest, which is composed of actors and administrators from both teams, in September 2024.

Z-Pentest

Established in September 2024, Z-Pentest is composed of members from CARR and NoName057(16). The group specializes in OT intrusion operations targeting globally dispersed critical infrastructure entities. Additionally, the group uses “hack and leak” operations and defacement attacks to draw attention to their pro-Russia messaging. Unlike other pro-Russia hacktivist groups, Z-Pentest largely avoids DDoS activities, claiming OT intrusions as attempts to garner more attention from the media.

Shortly after Z-Pentest’s inception, the group announced alliances with CARR and NoName057(16), possibly to leverage the other groups’ subscribers to grow the new channel. In March 2025, Z-Pentest posted evidence claiming OT device intrusions to their channel using a NoName057(16) cyberattack campaign hashtag. Similarly, in April 2025, Z-Pentest shared a video purporting defacement of an HMI by changing system names to NoName057(16) and CARR references. Z-Pentest continues to create new alliances with other groups, like Sector16, to continue growing their subscriber base and incidentally propagate TTPs with new partners.

Sector16

Formed in January 2025, Sector16 is a novice pro-Russia hacktivist group that emerged through collaboration with Z-Pentest. Sector16 actively maintains an online presence, including a public Telegram channel where they share videos, statements, and claims of compromising U.S. energy infrastructure. These communications often align with pro-Russia narratives and reflect their self-proclaimed support for Russian geopolitical objectives.

Members of Sector16 may have received indirect support from the Russian government in exchange for conducting specific cyber operations that further Russian strategic goals. This aligns with broader Russian cyber strategies that involve leveraging non-state threat actors for certain cyber activities, adding a layer of deniability.

Technical Details

Note: This advisory uses the MITRE ATT&CK® Matrix for Enterprise framework, version 18. See the MITRE ATT&CK Tactics and Techniques section of this advisory for a table of the threat actors’ activity mapped to MITRE ATT&CK tactics and techniques.

TTP Overview

Pro-Russia hacktivist groups employ easily disseminated and replicated TTPs across various entities, increasing the likelihood of widespread adoption and escalating the frequency of intrusions. These groups have limited capabilities, frequently misunderstanding the processes they aim to disrupt. Their apparent low level of technical knowledge results in haphazard attacks where actors intend to cause physical damage but cannot accurately anticipate actual impact. Despite these limitations, the authoring organizations have observed these groups willfully cause actual harm to vulnerable critical infrastructure.

Pro-Russia hacktivist groups use the TTPs in this Cybersecurity Advisory to target virtual network computing (VNC)-connected HMI devices. These groups are primarily seeking notoriety with their actions. While they have caused damage in some instances, they regularly make false or exaggerated claims about their attacks on critical infrastructure to garner more attention. They frequently misrepresent their capabilities and the impacts of their actions, portraying minor incursions as significant breaches, but such incursions can still lead to lost time and resources for operators remediating systems.

Additionally, pro-Russia hacktivists use an opportunistic targeting methodology. They leverage superficial criteria, such as victim availability and existing vulnerabilities, rather than focusing on strategically significant entities. Their lack of strategic focus can lead to a broad array of targets, ranging from water treatment facilities to oil well systems. Pro-Russia hacktivists have demonstrated a pattern of frequently taking advantage of the widespread availability of vulnerable VNC connections. While system owners typically use VNC connections for legitimate remote system access functions, threat actors can maliciously use these connections to broadly target numerous platforms and services. Consequently, these groups can indiscriminately compromise critical infrastructure entities, including those in the Water and Wastewater, Food and Agriculture, and Energy Sectors.

Pro-Russia hacktivist groups have successfully targeted supervisory control and data […]
