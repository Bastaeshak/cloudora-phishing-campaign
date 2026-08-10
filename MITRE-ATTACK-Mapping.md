# MITRE ATT&CK Mapping

This file maps the attacker activity identified during the Cloudora payroll phishing investigation to the MITRE ATT&CK framework.

## **T1566.002 - Phishing: Spearphishing Link**

Tactic: Initial Access

The attacker sent payroll-themed phishing emails containing malicious links to Cloudora employees. The emails impersonated Cloudora HR and directed users to the lookalike `cloudora-hr-portal.example` domain.

The links were designed to convince employees to visit the fake payroll portal. Six employees clicked a phishing link during the campaign.

Evidence:
- Payroll-themed phishing emails
- `cloudora-hr-portal.example` lookalike domain
- Variant A URL: `hxxps://cloudora-hr-portal[.]example/payroll/login`
- Variant B URL: `hxxps://login.cloudora-hr-portal[.]example/verify`
- Six employees clicked a phishing link


## **T1598.003 - Phishing for Information: Spearphishing Link**

Tactic: Reconnaissance

The phishing links directed victims to a credential-harvesting page designed to collect Cloudora account credentials.

Freya Lynn and Ryan Boyd clicked the phishing links and submitted their credentials. This showed that the campaign was not only attempting to get users to click a malicious link, but was specifically designed to steal account information.

Evidence:
- Freya Lynn submitted credentials after clicking Variant A
- Ryan Boyd submitted credentials after clicking Variant B
- `CredentialsSubmitted = Yes` was recorded for both users
- Both phishing URLs were designed as credential-harvesting pages


## **T1078.004 - Valid Accounts: Cloud Accounts**

Tactic: Initial Access

The attacker used the stolen credentials to successfully access the victims' Microsoft 365 cloud accounts.

Freya Lynn's account was accessed from `198.18.7.200` in Amsterdam using Windows 11 and Chrome. The attacker then accessed Outlook Web and SharePoint.

Ryan Boyd's account was later accessed from the same attacker IP in Amsterdam, followed by access to Outlook Web.

These successful sign ins confirmed that the stolen credentials were used to access valid Cloudora cloud accounts.

Evidence:
- Attacker IP: `198.18.7.200`
- Successful sign in to Freya Lynn's Microsoft 365 account
- Outlook Web and SharePoint activity under Freya's account
- Successful sign in to Ryan Boyd's Microsoft 365 account
- Outlook Web activity under Ryan's account
- Sign ins originated from Amsterdam using Windows 11 and Chrome


## **T1583.001 - Acquire Infrastructure: Domains**

Tactic: Resource Development

The attacker used the lookalike domain `cloudora-hr-portal.example` as infrastructure supporting the phishing campaign.

The domain was designed to resemble the legitimate `cloudora.io` domain and was used for phishing email infrastructure and credential-harvesting URLs.

Variant B also authenticated successfully with SPF, DKIM, and DMARC because the attacker controlled the lookalike domain. This allowed the phishing email to appear properly authenticated even though it was not associated with the real Cloudora domain.

Evidence:
- Lookalike domain: `cloudora-hr-portal.example`
- `mail.cloudora-hr-portal.example`
- `mailer.cloudora-hr-portal.example`
- `login.cloudora-hr-portal.example`
- Domain used in both phishing variants
- Variant B authenticated successfully for the attacker-controlled domain
