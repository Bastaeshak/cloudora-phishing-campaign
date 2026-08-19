# KQL Queries

This file documents the KQL queries I used in Azure Data Explorer during the Cloudora payroll phishing campaign investigation.

Each query includes its purpose, the query itself, the result, and why the result mattered to the investigation.

## Query 1: Campaign Scope

CloudoraMsgTrace_CL
| where EventType == "Delivery"
| summarize Messages=count(), Recipients=dcount(RecipientAddress)
    by Campaign, SenderAddress, SenderIP, SPFResult, DKIMResult, DMARCResult, DeliveryAction
| order by Campaign asc, SenderIP asc

<img width="1919" height="943" alt="query1" src="https://github.com/user-attachments/assets/d1dca167-aa38-4b32-856e-4a5e21276d03" />

Purpose: Determine the size of the phishing campaign and identify the sender addresses, sending IPs, authentication results, and delivery actions associated with each phishing variant.

What It Showed: The query identified two phishing variants. Variant A spoofed `payroll@cloudora.io` and was sent from `198.18.44.10` and `198.18.44.23`. SPF, DKIM, and DMARC failed. Variant B was sent from `198.18.51.7` using the lookalike `cloudora-hr-portal.example` domain and passed SPF, DKIM, and DMARC for the attacker controlled domain.

## Query 2: Delivered Recipients

CloudoraMsgTrace_CL
| where EventType == "Delivery" and DeliveryAction == "Delivered"
| distinct RecipientAddress
| order by RecipientAddress asc

<img width="1919" height="946" alt="query2" src="https://github.com/user-attachments/assets/9db164f1-6cec-41e7-ad68-0587808b6bd9" />

Purpose: Identify which employees actually received a phishing email in their inbox.

What It Showed: The query identified 36 Cloudora employees who had at least one phishing email successfully delivered to their mailbox.

## Query 3: Quarantined Recipients

let DeliveredTo = CloudoraMsgTrace_CL
| where EventType == "Delivery" and DeliveryAction == "Delivered"
| distinct RecipientAddress;

CloudoraMsgTrace_CL
| where EventType == "Delivery" and DeliveryAction == "Quarantined"
| where RecipientAddress !in (DeliveredTo)
| distinct RecipientAddress
| order by RecipientAddress asc

<img width="1919" height="942" alt="query3" src="https://github.com/user-attachments/assets/fde48538-369f-4e7e-87fa-49beeeb5c996" />

Purpose: Identify employees who were targeted by the campaign but never received the phishing email because every message sent to them was quarantined.

What It Showed: Four employees had all phishing messages quarantined by Exchange Online Protection: Emma Hayes, Maya Chen, Nina Cole, and Ruth Dean. These employees were targeted but never had the phishing email delivered to their inbox.

## Query 4: Phishing Link Clicks

CloudoraMsgTrace_CL
| where EventType == "Click"
| project TimeGenerated, RecipientAddress, Campaign, Url, ClickIP, CredentialsSubmitted
| order by TimeGenerated asc
<img width="1919" height="941" alt="query4" src="https://github.com/user-attachments/assets/bc152cd6-d7cf-4b54-888f-514020fbd5b0" />

Purpose: Identify every employee who clicked one of the phishing links and determine whether credentials were submitted.

What It Showed: Six employees clicked a phishing link: Seth Lane, Freya Lynn, Ryan Boyd, Hugo Marsh, Chloe Price, and Dina Said. The results also showed which phishing variant they interacted with, the URL clicked, their click IP, and whether credentials were submitted.

## Query 5: Credential Submissions

CloudoraMsgTrace_CL
| where EventType == "Click" and CredentialsSubmitted == "Yes"
| project TimeGenerated, RecipientAddress, Campaign, Url, ClickIP
| order by TimeGenerated asc

<img width="1912" height="933" alt="query5" src="https://github.com/user-attachments/assets/8c12676f-ebf7-49f3-92e9-df353aa329f0" />

Purpose: Narrow the click activity down to employees who actually entered their credentials into the phishing site.

What It Showed: Two employees submitted credentials: Freya Lynn and Ryan Boyd. Freya submitted credentials to Variant A at 08:47:12 UTC, while Ryan submitted credentials to Variant B at 09:05:44 UTC.

## Query 6: Compromised Account Sign Ins

CloudoraSignin_CL
| where UserPrincipalName == "freya.lynn@cloudora.io"
| project TimeGenerated, AppDisplayName, IPAddress, City, Country, DeviceOS, Browser, ResultType
| order by TimeGenerated asc

<img width="1914" height="928" alt="query6" src="https://github.com/user-attachments/assets/004f3b09-d593-4900-90b9-1dbd023b87b2" />

Purpose: Determine whether the credentials stolen from the phishing site were later used to access the victims' Microsoft 365 accounts.

What It Showed: Successful sign ins from the credential victims revealed suspicious activity from `198.18.7.200` in Amsterdam using Windows 11 and Chrome. This activity did not match the victims' normal sign in behavior and confirmed that stolen credentials were successfully used.

## Query 7: Attacker IP Pivot

CloudoraSignin_CL
| where IPAddress startswith "198.18.7." and ResultType == "0"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    Apps=make_set(AppDisplayName)
    by UserPrincipalName, IPAddress, Country
| order by FirstSeen asc

<img width="1901" height="925" alt="query7" src="https://github.com/user-attachments/assets/a57ef644-3515-41cf-a726-85ceca927049" />

Purpose: Pivot on the identified attacker IP to determine whether it had successfully accessed any other Cloudora accounts.

What It Showed: The attacker IP `198.18.7.200` successfully accessed two accounts: Freya Lynn and Ryan Boyd. This pivot was important because it revealed Ryan as the second compromised account instead of stopping the investigation after finding Freya.

## Query 8: Ryan Credential Submission

CloudoraMsgTrace_CL
| where RecipientAddress == "ryan.boyd@cloudora.io" and EventType == "Click"
| project TimeGenerated, Campaign, Url, ClickIP, CredentialsSubmitted

<img width="1919" height="893" alt="query8" src="https://github.com/user-attachments/assets/16c7f9bb-e067-490c-ab51-5513ea6c3892" />

Purpose: Confirm that Ryan Boyd interacted with the phishing campaign and submitted his credentials before the suspicious sign in occurred.

What It Showed: Ryan clicked the Variant B phishing link at 09:05:44 UTC from his normal London IP and `CredentialsSubmitted` was recorded as `Yes`. This confirmed that his password had been exposed before the attacker accessed his account.

## Query 9: Ryan Sign In Timeline

CloudoraSignin_CL
| where UserPrincipalName == "ryan.boyd@cloudora.io"
| project TimeGenerated, AppDisplayName, IPAddress, City, Country, DeviceOS, Browser, ResultType
| order by TimeGenerated asc

<img width="1910" height="882" alt="query9" src="https://github.com/user-attachments/assets/8eca0e58-b5cd-4e6d-8278-86cfc4c95976" />

Purpose: Build a complete timeline of Ryan Boyd's sign in activity and compare his normal activity with the suspected attacker activity.

What It Showed: Ryan normally accessed his account from London using an iOS device. At 13:22:05 UTC, his account was successfully accessed from `198.18.7.200` in Amsterdam using Windows 11 and Chrome. Outlook Web was then accessed from the same attacker IP at 13:25:33 UTC. Ryan later returned to his normal London activity, creating an impossible travel pattern.

## Query 10: Ryan Account Baseline

CloudoraSignin_CL
| where UserPrincipalName == "ryan.boyd@cloudora.io"
| summarize SignIns=count() by Country, City, IPAddress, DeviceOS
| order by SignIns desc

<img width="1919" height="888" alt="query10" src="https://github.com/user-attachments/assets/33aedab9-e2ac-4b47-afd4-8a426dfeff00" />


Purpose: Compare Ryan's normal sign in locations, IP addresses, and devices against the suspicious Amsterdam activity.

What It Showed: Ryan's normal activity came from London using his iOS device. The Amsterdam activity from `198.18.7.200` using Windows was outside his normal sign in pattern, providing additional evidence that the Amsterdam session was unauthorized.


## **Query 11: Freya Credential Submission**

CloudoraMsgTrace_CL
| where RecipientAddress == "freya.lynn@cloudora.io" and EventType == "Click"
| project TimeGenerated, Campaign, Url, ClickIP, CredentialsSubmitted

<img width="1912" height="901" alt="freya11" src="https://github.com/user-attachments/assets/35047bde-14d0-426d-a823-9deb643060b5" />

Purpose: Confirm that Freya Lynn interacted with the phishing campaign and submitted her credentials before the suspicious sign in occurred.

## **Query 12: Freya Sign In Timeline**

CloudoraSignin_CL
| where UserPrincipalName == "freya.lynn@cloudora.io"
| project TimeGenerated, AppDisplayName, IPAddress, City, Country, DeviceOS, Browser, ResultType
| order by TimeGenerated asc

<img width="1919" height="901" alt="freya12" src="https://github.com/user-attachments/assets/769c4f94-e4e8-4cd6-ac84-9958d40dc925" />

Purpose: Build a complete timeline of Freya Lynn's sign in activity and compare her normal activity with the suspected attacker activity, including the suspicious Amsterdam sign in and the Microsoft 365 services accessed afterward.

## **Query 13: Freya Account Baseline**ec9" 

CloudoraSignin_CL
| where UserPrincipalName == "freya.lynn@cloudora.io"
| summarize SignIns=count() by Country, City, IPAddress, DeviceOS
| order by SignIns desc

<img width="1919" height="887" alt="freya13" src="https://github.com/user-attachments/assets/daa6ea3d-40d3-4012-8c81-eb09a89c6989" />

Purpose: Compare Freya's normal sign in locations, IP addresses, devices, and operating systems against the suspicious Amsterdam activity to determine whether the attacker session was outside her normal behavior and provide additional evidence of account compromise.


## Query 14: Received But Did Not Click

let Clickers = CloudoraMsgTrace_CL
| where EventType == "Click"
| distinct RecipientAddress;

CloudoraMsgTrace_CL
| where EventType == "Delivery" and DeliveryAction == "Delivered"
| distinct RecipientAddress
| where RecipientAddress !in (Clickers)
| order by RecipientAddress asc

<img width="1914" height="894" alt="query11" src="https://github.com/user-attachments/assets/2b8660b7-2e43-4e5e-9b47-556eccbe3aba" />

Purpose: Identify employees who received a phishing email but did not click the malicious link.

What It Showed: Thirty employees received at least one phishing email but never clicked the link. These users were considered near miss recipients and required awareness communication rather than account compromise response.

## Query 15: Clicked Without Submitting Credentials

CloudoraMsgTrace_CL
| where EventType == "Click" and CredentialsSubmitted == "No"
| distinct RecipientAddress

<img width="1918" height="895" alt="query12" src="https://github.com/user-attachments/assets/9655a53e-94c3-4899-9e94-10d8633cea5b" />

Purpose: Separate employees who clicked a phishing link but did not enter their credentials from the users whose credentials were actually stolen.

What It Showed: Seth Lane, Chloe Price, Hugo Marsh, and Dina Said clicked a phishing link but did not submit credentials. No account compromise was confirmed for these four employees.

## Query 16: Post Containment Verification

CloudoraSignin_CL
| where IPAddress startswith "198.18.7." and ResultType == "0"
| summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated),
    Apps=make_set(AppDisplayName)
    by UserPrincipalName, IPAddress, Country
| order by FirstSeen asc

<img width="1917" height="895" alt="query13" src="https://github.com/user-attachments/assets/62844fd8-53cf-4c8a-8e1c-2693d15a0df6" />

Purpose: Verify that the attacker no longer had access after containment actions were completed.

What It Showed: The victim sign in and attacker IP pivot queries were rerun after containment. No additional activity from `198.18.7.200` was identified after containment.
