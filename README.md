# Cloudora Payroll Phishing Campaign Investigation

## Overview

This project documents my investigation of a simulated payroll phishing campaign targeting Cloudora employees.

The investigation began after an employee reported a suspicious payroll email to the SOC. I analyzed multiple email samples and their headers, reviewed email authentication results, identified malicious infrastructure, investigated message trace data, and analyzed Microsoft 365 sign in activity using KQL in Azure Data Explorer.

The investigation identified 40 targeted employees, 6 users who clicked phishing links, and 2 users who submitted credentials and had their Microsoft 365 accounts compromised.

## Objectives

The main goals of the investigation were to:

- Determine whether the reported email was malicious
- Analyze email headers and authentication results
- Identify phishing infrastructure and indicators of compromise
- Determine the full scope of the phishing campaign
- Identify employees who interacted with the phishing emails
- Determine whether stolen credentials were successfully used
- Identify any additional compromised accounts
- Document containment and remediation actions
- Map observed attacker behavior to MITRE ATT&CK
- Map the investigation to the NIST incident response lifecycle

## Tools Used

- Azure Data Explorer
- Kusto Query Language (KQL)
- Email header analysis
- Message trace logs
- Microsoft 365 sign in logs
- VirusTotal
- AbuseIPDB
- MITRE ATT&CK
- NIST Incident Response Framework

KQL was used in Azure Data Explorer to investigate message trace and sign in data. The same query language is also used in Microsoft Sentinel and Microsoft Defender.

## Email Analysis

Six email samples were analyzed during the investigation, including malicious phishing emails, a legitimate Cloudora payroll email, a benign newsletter, and the employee forwarded report that triggered the investigation.

The analysis focused on:

- From address
- Reply-To address
- Return-Path
- Received headers
- Sending IP addresses
- SPF
- DKIM
- DMARC
- Domain alignment
- Embedded URLs
- Lookalike domains
- Social engineering indicators

The campaign contained two malicious phishing variants across multiple email samples and waves.

Variant A spoofed the legitimate `payroll@cloudora.io` address and failed SPF, DKIM, and DMARC. Analysis of the Variant A messages revealed multiple sending relays including `198.18.44.10` and `198.18.44.23`.

Variant B used the attacker controlled lookalike domain `cloudora-hr-portal.example`. SPF, DKIM, and DMARC passed because the attacker was authorized to send email for their own domain. This showed why successful email authentication alone does not prove that an email is legitimate.

A legitimate Cloudora payroll email and a legitimate Mailchimp newsletter were also analyzed to establish normal email behavior and help distinguish malicious activity from legitimate third party infrastructure.

## Key Findings

- Two malicious phishing variants were identified across multiple email samples and campaign waves
- Variant A spoofed the legitimate `payroll@cloudora.io` address
- Variant A failed SPF, DKIM, and DMARC
- Variant A used multiple sending relays including `198.18.44.10` and `198.18.44.23`
- Variant B used the lookalike domain `cloudora-hr-portal.example`
- Variant B passed SPF, DKIM, and DMARC for the attacker controlled domain
- 40 Cloudora employees were targeted
- 6 employees clicked a phishing link
- Freya Lynn and Ryan Boyd submitted credentials
- Both compromised accounts were later accessed from `198.18.7.200` in Amsterdam
- Pivoting on the attacker IP revealed the second compromised account
- The Cloudora Monthly Mailchimp newsletter was investigated and cleared as legitimate

## Investigation Process

1. Reviewed the employee reported phishing email
2. Analyzed the email headers
3. Compared suspicious emails with legitimate Cloudora email
4. Reviewed SPF, DKIM, DMARC, From, Reply-To, Return-Path, Received headers, and URLs
5. Identified malicious domains, subdomains, URLs, and IP addresses
6. Used VirusTotal and AbuseIPDB to investigate identified infrastructure
7. Reviewed additional phishing samples to identify campaign similarities
8. Investigated and cleared the legitimate Mailchimp newsletter
9. Loaded message trace and sign in datasets into Azure Data Explorer
10. Used KQL to determine the full scope of the phishing campaign
11. Identified employees who clicked phishing links
12. Identified employees who submitted credentials
13. Investigated the sign in activity of compromised users
14. Confirmed unauthorized access to Freya Lynn's account
15. Pivoted on the attacker IP to search for additional victims
16. Identified Ryan Boyd as the second compromised account
17. Investigated Ryan Boyd's sign in activity and confirmed unauthorized access
18. Documented containment and remediation actions
19. Reran victim and attacker IP queries to verify no further attacker activity after containment
20. Mapped observed attacker behavior to MITRE ATT&CK
21. Mapped the investigation to the NIST incident response lifecycle
22. Created the final incident report

## Incident Response

The investigation followed the NIST incident response lifecycle.

### Detection and Analysis

The reported phishing email was reviewed and its headers were analyzed. Message trace logs and sign in data were then investigated using KQL to determine the campaign scope, identify compromised accounts, and trace attacker activity.

### Containment

The documented response included revoking active sessions and refresh tokens for the compromised accounts and blocking the identified malicious infrastructure.

### Eradication

The documented response included resetting compromised credentials, re registering MFA, and purging phishing messages from affected mailboxes.

### Recovery

The compromised accounts were returned to secure use after credential and authentication controls were addressed.

### Post Incident Activity

Victim sign in queries and attacker IP pivots were rerun using KQL in Azure Data Explorer. No additional activity from `198.18.7.200` was found after containment.

## Project Files

### Incident Report

[Cloudora Phishing Incident Report](incident-report/Cloudora-Phishing-Incident-Report.pdf)

Final SOC incident report containing the executive summary, timeline, findings, IOCs, MITRE ATT&CK mapping, scope, response actions, recommendations, and lessons learned.

### KQL Queries, Investigation & Evidence

[KQL Queries, Investigation & Evidence](KQL-Queries-Investigation-and-Evidence.md)

KQL queries used to investigate the phishing campaign, analyze account activity, and document the evidence found throughout the investigation.

### Email and Header Analysis

[Email-Header-Analysis.md](Email-Header-Analysis.md)

Documents the analysis of all six email samples including From, Reply-To, Return-Path, Received headers, sending IP addresses, SPF, DKIM, DMARC, URLs, lookalike domains, suspicious indicators, and analyst verdicts.

Supporting email and header evidence is stored in:

`evidence/email-header-evidence/`

### MITRE ATT&CK Mapping

[MITRE-ATTACK-Mapping.md](MITRE-ATTACK-Mapping.md)

Maps the attacker behavior observed during the investigation to relevant MITRE ATT&CK techniques and explains the evidence supporting each mapping.

### NIST Incident Response Mapping

[NIST-Incident-Response-Mapping.md](NIST-Incident-Response-Mapping.md)

Maps the investigation and response actions to the NIST incident response lifecycle, including detection and analysis, containment, eradication, recovery, and post incident activity.

## Outcome

The investigation confirmed that the phishing campaign successfully compromised two Microsoft 365 accounts.

Email analysis identified multiple phishing techniques, including spoofing the legitimate Cloudora domain and using an attacker controlled lookalike domain with valid email authentication.

The investigation also demonstrated the importance of continuing to pivot after identifying the first victim. Searching the attacker sign in IP revealed a second compromised account that could otherwise have been missed.

Another important lesson was that SPF, DKIM, and DMARC results must be interpreted in context. Variant B passed authentication, but it passed for the attacker's lookalike domain rather than the legitimate `cloudora.io` domain.
