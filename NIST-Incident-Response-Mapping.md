# NIST Incident Response Mapping

This file maps the Cloudora payroll phishing investigation to the NIST incident response lifecycle.

## **1. Preparation**

Before the incident, Cloudora had security controls and logging in place that provided the evidence needed to investigate the phishing campaign.

The investigation used email headers, message trace data, and Microsoft 365 sign in logs to identify the phishing infrastructure, determine which employees interacted with the emails, and investigate suspicious account activity.

Preparation also included existing email security controls such as SPF, DKIM, DMARC, and Exchange Online Protection.

Examples:
- Email authentication with SPF, DKIM, and DMARC
- Exchange Online Protection
- Message trace logging
- Microsoft 365 sign in logging
- Established SOC reporting process


## **2. Detection and Analysis**

The incident was detected after James Holt reported a suspicious payroll email to the SOC.

The email headers were analyzed and showed that the message claiming to come from Cloudora originated from attacker controlled infrastructure. SPF, DKIM, and DMARC failed on Variant A, and the Reply-To and phishing URL pointed to the lookalike `cloudora-hr-portal.example` domain.

KQL queries in Azure Data Explorer were then used to determine the scope of the campaign.

The investigation identified 40 targeted employees, 36 employees who received at least one phishing email, six employees who clicked a phishing link, and two employees who submitted credentials.

Sign in activity was then analyzed for the credential victims. Freya Lynn and Ryan Boyd were both successfully accessed from `198.18.7.200` in Amsterdam using Windows 11 and Chrome, confirming that the stolen credentials had been used.

Examples:
- Analyzed the reported phishing email and headers
- Identified the lookalike phishing domain
- Identified malicious sending IP addresses
- Scoped phishing delivery using KQL
- Identified users who clicked the phishing links
- Identified users who submitted credentials
- Reviewed victim sign in activity
- Identified attacker IP `198.18.7.200`
- Confirmed two compromised Microsoft 365 accounts
- Separated compromised, targeted, and cleared accounts


## **3. Containment, Eradication, and Recovery**

After confirming the compromised accounts, containment actions were documented to limit attacker access and protect the affected users. The investigation identified unauthorized sign-ins, MFA enrollment, mailbox manipulation, and access to additional Microsoft 365 services.

The documented response included password resets, session revocation, MFA re-registration, blocking the identified attacker infrastructure, identifying and documenting malicious mailbox rules for remediation, and quarantining any remaining phishing emails associated with the campaign.

Because this investigation was conducted in a simulated environment, the report documents the recommended response workflow and the verification steps that would be performed by a SOC or incident response team. Actions such as mailbox rule removal and email remediation would require additional validation in a live Microsoft 365 environment before they could be confirmed as completed.

Examples:
- Reset passwords for Freya Lynn and Ryan Boyd
- Revoke active Microsoft 365 sessions
- Require MFA re-registration
- Block attacker IP `198.18.7.200`
- Block the `cloudora-hr-portal.example` domain
- Remove malicious inbox rules
- Quarantine remaining phishing messages
- Perform precautionary password resets for higher risk users
- Verify no additional attacker activity occurred after containment


## **4. Post-Incident Activity**

After containment, the investigation documented the incident findings, indicators of compromise, MITRE ATT&CK mappings, affected account scope, and recommendations.

The investigation also identified improvements that could reduce the likelihood or impact of similar attacks in the future.

Recommendations included stronger phishing-resistant MFA, improved monitoring for impossible travel and unfamiliar sign ins, stronger email filtering for lookalike domains, and continued phishing awareness training.

The investigation also documented the legitimate Cloudora newsletter as a cleared false positive, demonstrating the importance of validating suspicious messages instead of assuming every reported email is malicious.

Examples:
- Completed the incident report
- Documented indicators of compromise
- Mapped attacker behavior to MITRE ATT&CK
- Documented KQL investigation queries and evidence
- Documented phishing email header analysis
- Identified lessons learned
- Developed recommendations for improving security controls
- Documented and cleared the legitimate newsletter false positive
