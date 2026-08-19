# Email Header Analysis

## **Email 1: Payroll Phishing - Variant A**

### **Email Header**

Return-Path: <payroll@cloudora[.]io>

Received: from mail.cloudora-hr-portal.example (198.18.44.23) by DB9EUR03FT034.mail.protection.outlook.com

Authentication-Results: spf=fail (sender IP is 198.18.44.23)
smtp.mailfrom=cloudora.io; dkim=fail (body hash did not verify)
header.d=cloudora.io; dmarc=fail action=quarantine header.from=cloudora.io;
compauth=fail reason=001

Received-SPF: Fail
client-ip=198.18.44.23;
helo=mail.cloudora-hr-portal.example

DKIM-Signature: d=cloudora.io; signature invalid

From: "Cloudora HR" <payroll@cloudora[.]io>

Reply-To: "Cloudora HR Support" <hr-support@cloudora-hr-portal[.]example>

To: "James Holt" <james.holt@cloudora[.]io>

Subject: Payroll update: action required before 5pm

Date: Mon, 25 Aug 2026 08:39:02 +0000

Message-ID: <A-0019@mail.cloudora-hr-portal[.]example>

X-Originating-IP: [198.18.44.23]

### **Email Body**

Dear Colleague,

Our payroll system has been upgraded ahead of the August pay run. To avoid a delay to your salary payment, you must re-confirm your details before 5:00pm today.

Confirm your payroll details here:

https://cloudora-hr-portal.example/payroll/login

Failure to verify by the deadline may result in your August payment being held.

Kind regards,

Cloudora HR and Payroll Team

### **Analysis**

This email is malicious and is part of phishing Variant A.

The From address claims to be `payroll@cloudora.io`, but the message actually originated from `mail.cloudora-hr-portal.example` at `198.18.44.23`.

SPF failed because the sending IP was not authorized to send email for `cloudora.io`. DKIM failed because the Cloudora signature could not be verified. DMARC also failed and returned an action of quarantine.

The Reply-To address points to `hr-support@cloudora-hr-portal.example` instead of Cloudora's real domain.

The email also creates urgency by threatening to hold the employee's salary unless they act before 5:00 PM. The link goes to `cloudora-hr-portal.example/payroll/login`, a lookalike domain rather than Cloudora's legitimate HR portal.

Verdict: Malicious phishing email.


## **Email 2: Payroll Phishing - Variant B**

### **Email Header**

Return-Path: <payroll@cloudora-hr-portal[.]example>

Received: from mailer.cloudora-hr-portal.example (198.18.51.7) by DB9EUR03FT051.mail.protection.outlook.com

Authentication-Results: spf=pass (sender IP is 198.18.51.7)
smtp.mailfrom=cloudora-hr-portal.example;
dkim=pass (signature was verified)
header.d=cloudora-hr-portal.example;
dmarc=pass action=none header.from=cloudora-hr-portal.example;
compauth=pass reason=100

Received-SPF: Pass
client-ip=198.18.51.7;
helo=mailer.cloudora-hr-portal.example

DKIM-Signature: d=cloudora-hr-portal.example; s=k1

From: "Cloudora Payroll Services" <payroll@cloudora-hr-portal[.]example>

Reply-To: "Payroll Services" <payroll.support@cloudora-hr-portal[.]example>

To: "Ryan Boyd" <ryan.boyd@cloudora[.]io>

Subject: Action required: confirm your August payroll details

Date: Mon, 25 Aug 2026 08:36:22 +0000

Message-ID: <B-0061@mail.cloudora-hr-portal[.]example>

### **Email Body**

Hi Ryan,

As part of Cloudora's August payroll processing, all staff must confirm their bank and tax details on the new secure portal. This takes under two minutes.

Confirm now: https://login.cloudora-hr-portal.example/verify

If your details are not confirmed, your August salary may be paid to your previous account on file.

Cloudora Payroll Services

### **Analysis**

This email is malicious even though SPF, DKIM, and DMARC all passed.

The important detail is which domain passed authentication. The message authenticated successfully for `cloudora-hr-portal.example`, not Cloudora's legitimate `cloudora.io` domain.

The From address, Return-Path, Reply-To, DKIM domain, and sending server all belong to the lookalike `cloudora-hr-portal.example` domain.

The message also pressures Ryan to confirm sensitive bank and tax information and warns that his salary could be sent to an old account if he does not act.

The link points to `login.cloudora-hr-portal.example/verify`, not Cloudora's legitimate HR portal.

This email demonstrates why passing SPF, DKIM, and DMARC does not automatically mean an email is safe. The authentication passed for an attacker-controlled lookalike domain.

Verdict: Malicious phishing email.


## **Email 3: Cloudora Monthly Newsletter**

### **Email Header**

Return-Path: <bounce-mc.us17_123456.7654321-news=cloudora.io@mail105.suw16[.]mcsv.net>

Received: from mail105.suw16.mcsv.net (198.18.60.5) by DB9EUR03FT062.mail.protection.outlook.com

Authentication-Results: spf=pass (sender IP is 198.18.60.5)
smtp.mailfrom=mail105.suw16.mcsv.net;
dkim=pass (signature was verified) header.d=cloudora.io;
dkim=pass (signature was verified) header.d=mcsv.net;
dmarc=pass action=none header.from=cloudora.io;
compauth=pass reason=100

Received-SPF: Pass
client-ip=198.18.60.5

DKIM-Signature: d=cloudora.io; s=k2

DKIM-Signature: d=mcsv.net; s=k1

From: "Cloudora News" <news@cloudora[.]io>

Reply-To: "Cloudora News" <news@cloudora[.]io>

To: "Adam Clark" <adam.clark@cloudora[.]io>

Subject: Cloudora Monthly: product updates, team wins and what's next

Date: Mon, 25 Aug 2026 06:58:39 +0000

Message-ID: <20260825065839.7654321.123456@mail105.suw16.mcsv[.]net>

X-Mailer: MailChimp Mailer

List-Unsubscribe: Cloudora Mailchimp unsubscribe

List-Unsubscribe-Post: List-Unsubscribe=One-Click

### **Email Body**

CLOUDORA MONTHLY - August

Hi Adam,

A quick round-up from the Cloudora team this month: our new onboarding module shipped, the Manchester office hit its hiring target, and we previewed the autumn product roadmap at the all-hands.

Read the full update:

https://cloudora.us17.list-manage.com/track/click?u=123456&id=news-aug

You are receiving this because you are a Cloudora employee subscribed to internal news. Unsubscribe any time using the link below.

Cloudora News Team

### **Analysis**

This email is legitimate and was cleared as a false positive.

SPF passed for the Mailchimp sending infrastructure. DKIM passed and, importantly, there is a valid DKIM signature aligned with `cloudora.io`. DMARC also passed for `cloudora.io`.

The message was sent through Mailchimp, which explains the `mcsv.net` infrastructure and Mailchimp tracking URL. The message also contains legitimate one-click unsubscribe headers.

Unlike phishing Variant B, authentication is tied back to the real `cloudora.io` domain rather than a lookalike domain.

There are no indicators in the headers showing that the message is impersonating Cloudora.

Verdict: Legitimate Cloudora marketing email.


## **Email 4: Legitimate Cloudora Payroll Email**

### **Email Header**

Return-Path: <payroll@cloudora[.]io>

Authentication-Results: spf=pass (sender IP is 40.107.20.55)
smtp.mailfrom=cloudora.io;
dkim=pass (signature was verified)
header.d=cloudora.io;
dmarc=pass action=none header.from=cloudora.io;
compauth=pass reason=100

Received-SPF: Pass
client-ip=40.107.20.55

DKIM-Signature: d=cloudora.io; s=selector1

X-MS-Exchange-Organization-AuthAs: Internal

X-MS-Exchange-Organization-AuthSource: LO4P123MB6621.GBRP123.PROD.OUTLOOK.COM

From: "Cloudora Payroll" <payroll@cloudora[.]io>

Reply-To: "Cloudora Payroll" <payroll@cloudora[.]io>

To: "Cloudora Staff" <all-staff@cloudora[.]io>

Subject: August pay date and payslip availability

Date: Thu, 20 Aug 2026 09:02:12 +0000

Message-ID: <a71c9f20-2026-08-20-payroll@cloudora[.]io>

### **Email Body**

Hello everyone,

August payslips will be available in the HR portal from Wednesday 27 August. Pay date is Friday 29 August as usual.

You can view your payslip by signing in to the HR portal with your normal Cloudora single sign-on:

https://myhr.cloudora.io

We will never ask you to confirm your bank details or password by email. If you need to change your bank details, do it inside the portal after signing in, or contact the payroll team directly.

Thanks,

Tara Kemp
People and Payroll, Cloudora

### **Analysis**

This email is legitimate and provides a useful comparison against the phishing emails.

The From and Reply-To addresses both use `cloudora.io`. SPF passed for an authorized sender, DKIM successfully verified for `cloudora.io`, and DMARC passed.

The Exchange headers also identify the message as internally authenticated.

The link goes to `myhr.cloudora.io`, which is Cloudora's legitimate HR portal. The email does not ask employees to send or confirm passwords or banking information through email.

This legitimate message provides a clear baseline for comparison with the phishing emails. The malicious messages direct employees to `cloudora-hr-portal.example`, while the legitimate message directs employees to `myhr.cloudora.io`.

Verdict: Legitimate Cloudora payroll email.


## **Email 5: Employee Reported Phishing Email**

### **Email Header**

Return-Path: <james.holt@cloudora[.]io>

Authentication-Results: spf=pass smtp.mailfrom=cloudora.io;
dkim=pass header.d=cloudora.io;
dmarc=pass action=none header.from=cloudora.io

From: "James Holt" <james.holt@cloudora[.]io>

To: "Security Operations" <soc@cloudora[.]io>

Subject: FW: Payroll update: action required before 5pm [is this real?]

Date: Mon, 25 Aug 2026 09:11:45 +0000

Message-ID: <fwd-4471-2026-08-25@cloudora[.]io>

Original From: Cloudora HR <payroll@cloudora[.]io>

Original Reply-To: Cloudora HR Support <hr-support@cloudora-hr-portal[.]example>

Original Received: from mail.cloudora-hr-portal.example (198.18.44.23)

Original Authentication-Results:
spf=fail (sender IP is 198.18.44.23)
smtp.mailfrom=cloudora.io;
dkim=fail header.d=cloudora.io;
dmarc=fail action=quarantine header.from=cloudora.io;
compauth=fail reason=001

Original Message-ID: <A-0019@mail.cloudora-hr-portal[.]example>

### **Email Body**

Hi SOC team,

Got this first thing this morning. It says my salary will be held if I do not click by 5pm, which felt off, and the link is not our normal HR portal. I did not click it. Sending it over in case it matters.

Thanks,
James

-----Original Message-----

From: Cloudora HR <payroll@cloudora[.]io>

Reply-To: Cloudora HR Support <hr-support@cloudora-hr-portal[.]example>

Subject: Payroll update: action required before 5pm

Dear Colleague,

Our payroll system has been upgraded ahead of the August pay run. To avoid a delay to your salary payment, you must re-confirm your details before 5:00pm today.

Confirm your payroll details here:

https://cloudora-hr-portal.example/payroll/login

Failure to verify by the deadline may result in your August payment being held.

Kind regards,

Cloudora HR and Payroll Team

### **Analysis**

This is the employee report that brought the phishing email to the SOC.

The outer email from James Holt is legitimate. It passes SPF, DKIM, and DMARC because James is a Cloudora employee forwarding the suspicious message internally to `soc@cloudora.io`.

The important evidence is in the preserved original message headers.

The original message failed SPF, DKIM, and DMARC and originated from `198.18.44.23` using `mail.cloudora-hr-portal.example`. Its Reply-To also points to the lookalike domain.

James also identified two important warning signs himself: the threat that his salary would be held and the fact that the link did not point to Cloudora's normal HR portal. He stated that he did not click the link.

This report triggered the SOC investigation.

Verdict: Legitimate employee report containing a malicious phishing email.


## **Email 6: Payroll Phishing - Variant A First Wave**

### **Email Header**

Return-Path: <payroll@cloudora.io>

Received: from mail.cloudora-hr-portal.example (198.18.44.10) by DB9EUR03FT034.mail.protection.outlook.com

Authentication-Results: spf=fail (sender IP is 198.18.44.10)
smtp.mailfrom=cloudora.io;
dkim=fail (body hash did not verify)
header.d=cloudora.io;
dmarc=fail action=quarantine header.from=cloudora.io;
compauth=fail reason=001

Received-SPF: Fail
client-ip=198.18.44.10;
helo=mail.cloudora-hr-portal.example

From: "Cloudora HR" <payroll@cloudora[.]io>

Reply-To: "Cloudora HR Support" <hr-support@cloudora-hr-portal[.]example>

To: "Freya Lynn" <freya.lynn@cloudora[.]io>

Subject: Payroll update: action required before 5pm

Date: Mon, 25 Aug 2026 08:04:33 +0000

Message-ID: <A-0015@mail.cloudora-hr-portal[.]example>

X-Originating-IP: [198.18.44.10]

### **Email Body**

Dear Colleague,

Our payroll system has been upgraded ahead of the August pay run. To avoid a delay to your salary payment, you must re-confirm your details before 5:00pm today.

Confirm your payroll details here:

https://cloudora-hr-portal.example/payroll/login

Failure to verify by the deadline may result in your August payment being held.

Kind regards,

Cloudora HR and Payroll Team

### **Analysis**

This email is malicious and is another message from phishing Variant A.

It uses the same spoofed `payroll@cloudora.io` sender, malicious Reply-To address, subject, and credential harvesting URL as the Variant A email sent to James Holt.

SPF, DKIM, and DMARC all failed because the message was not legitimately sent by Cloudora.

The important difference is the sending IP. This message originated from `198.18.44.10`, while the later Variant A message sent to James originated from `198.18.44.23`.

Both addresses belong to the same `198.18.44.x` range and both messages came from `mail.cloudora-hr-portal.example`. This showed that Variant A used multiple sending relays during the campaign.

This email was sent to Freya Lynn, who later submitted credentials and became one of the two confirmed compromised accounts.

Verdict: Malicious phishing email.
