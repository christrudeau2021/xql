// ─── PLATFORM-SPECIFIC CORPUS ────────────────────────────────────────────────
// Field mappings, syntax rules, datasets, and examples for each platform

export const KQL_CORPUS = `
## KQL (Kusto Query Language) — Microsoft Sentinel & Defender XDR

KQL uses a pipe-based syntax similar to XQL. Data flows left to right through transformation operators.

### BASIC STRUCTURE
\`\`\`kql
TableName
| where Condition
| project Field1, Field2
| order by Timestamp desc
| take 200
\`\`\`

### KEY OPERATORS
- where — filter rows (equivalent to XQL filter)
- project — select columns (equivalent to XQL fields)
- extend — add computed columns (equivalent to XQL alter)
- summarize — aggregate (equivalent to XQL comp)
- order by — sort
- take / limit — limit rows
- join kind=inner/left/right/full — join tables
- union — combine tables
- parse — extract fields from strings
- mv-expand — expand arrays
- distinct — deduplicate
- count — count rows
- render — visualize (charts, timecharts)

### FILTER OPERATORS
- == , != , < , > , <= , >=
- in~ (case-insensitive), !in
- contains, !contains, startswith, endswith
- matches regex, =~ (case-insensitive equals)
- has, has_all, has_any (token search)
- isnotempty(), isnull(), isnotnull()
- between (low .. high)

### TIME FILTERING
\`\`\`kql
| where TimeGenerated >= ago(24h)
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-01-31))
| where TimeGenerated >= startofday(ago(7d))
\`\`\`
Time units: s, m, h, d, w (e.g. ago(30m), ago(7d))

### AGGREGATION
\`\`\`kql
| summarize count() by Computer
| summarize count(), dcount(TargetUserName) by Computer
| summarize make_set(TargetIP) by SourceIP
| summarize arg_max(TimeGenerated, *) by DeviceId
| summarize countif(EventID == 4625) by TargetUserName
\`\`\`

### STRING FUNCTIONS
- tostring(), toint(), tolong(), todatetime()
- tolower(), toupper()
- strlen(), substring(), split(), strcat()
- extract(regex, captureGroup, text)
- parse_json(), bag_keys()
- replace_string(), trim()
- base64_decode_tostring()

### CORE SENTINEL TABLES
#### Identity & Authentication
- SigninLogs — Azure AD sign-ins
- AADNonInteractiveUserSignInLogs — non-interactive sign-ins
- AuditLogs — Azure AD audit events
- IdentityLogonEvents — Defender identity logon
- IdentityDirectoryEvents — AD directory changes

#### Endpoint (Defender for Endpoint / MDE)
- DeviceProcessEvents — process creation
- DeviceNetworkEvents — network connections
- DeviceFileEvents — file operations
- DeviceRegistryEvents — registry changes
- DeviceLogonEvents — logon events
- DeviceImageLoadEvents — DLL/module loads
- DeviceEvents — misc device events
- DeviceAlertEvents — MDE alerts

#### Email (Defender for Office)
- EmailEvents — email flow
- EmailAttachmentInfo — attachments
- EmailUrlInfo — URLs in email
- EmailPostDeliveryEvents — post-delivery actions

#### Cloud
- AzureActivity — Azure control plane
- AWSCloudTrail — AWS events
- GCPAuditLogs — GCP events
- CloudAppEvents — MCAS/Defender for Cloud Apps
- OfficeActivity — M365 audit log

#### Network / Firewall
- CommonSecurityLog — CEF/syslog (firewalls, proxies)
- DnsEvents — DNS queries
- NetworkAccessTraffic — network traffic
- AzureFirewallApplicationRule — Azure Firewall

#### Security Events
- SecurityEvent — Windows Security event log
- WindowsEvent — Windows event log (new schema)
- Syslog — Linux syslog
- SecurityAlert — all alerts
- SecurityIncident — incidents

### KEY FIELD NAMES (Defender XDR / MDE)
- Timestamp — event time
- DeviceName — hostname
- AccountName, AccountDomain — user
- InitiatingProcessFileName — parent process
- InitiatingProcessCommandLine — parent cmdline
- FileName — process filename
- ProcessCommandLine — full command line
- SHA256, MD5 — file hashes
- RemoteIP, RemotePort, RemoteUrl — network destination
- LocalIP, LocalPort — source
- ActionType — type of action taken
- FolderPath — file path
- RegistryKey, RegistryValueName, RegistryValueData



### KQL EXTENDED COVERAGE

#### Registry Persistence
\`\`\`kql
// Registry Run key persistence
DeviceRegistryEvents
| where TimeGenerated >= ago(7d)
| where RegistryKey contains "CurrentVersion\\Run"
    or RegistryKey contains "CurrentVersion\\RunOnce"
| where InitiatingProcessFileName !in~ ("msiexec.exe","setup.exe","install.exe","trustedinstaller.exe")
| project TimeGenerated, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| order by TimeGenerated desc
\`\`\`

#### Shadow Copy Deletion
\`\`\`kql
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where FileName =~ "vssadmin.exe" and ProcessCommandLine has_any ("delete","resize")
    or FileName =~ "wmic.exe" and ProcessCommandLine has "shadowcopy"
    or FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine
\`\`\`

#### Conditional Access & MFA Events (SigninLogs)
\`\`\`kql
// SigninLogs key fields for identity hunting
// ConditionalAccessStatus: success, failure, notApplied, unknownFutureValue
// AuthenticationRequirement: singleFactorAuthentication / multiFactorAuthentication
SigninLogs
| where TimeGenerated >= ago(24h)
| where ConditionalAccessStatus != "success"
| extend MFARequired = AuthenticationRequirement
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend City = tostring(LocationDetails.city)
| project TimeGenerated, UserPrincipalName, IPAddress, Country, City,
          ConditionalAccessStatus, MFARequired, AppDisplayName, ResultType
| order by TimeGenerated desc
\`\`\`

#### Impossible Travel
\`\`\`kql
// Impossible travel — same user from multiple countries in short window
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| extend Country = tostring(LocationDetails.countryOrRegion)
| summarize Countries=make_set(Country), IPs=make_set(IPAddress), Count=count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1
| order by TimeGenerated desc
\`\`\`

#### Scheduled Task via schtasks
\`\`\`kql
DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| where InitiatingProcessFileName !in~ ("taskeng.exe","taskhostw.exe","svchost.exe")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
\`\`\`

#### New Admin Account (SecurityEvent)
\`\`\`kql
// EventID 4720 = account created, 4732 = added to security group (Administrators)
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID in (4720, 4728, 4732, 4756)
| extend AccountCreated = TargetUserName
| project TimeGenerated, Computer, EventID, AccountCreated, SubjectUserName, SubjectLogonId
| order by TimeGenerated desc
\`\`\`

#### WMI Event Subscriptions
\`\`\`kql
// WMI persistence via DeviceEvents
DeviceEvents
| where TimeGenerated >= ago(7d)
| where ActionType in ("WmiBindingCreated","WmiConsumerCreated","WmiFilterCreated")
    or (ActionType == "ProcessCreated" and InitiatingProcessFileName =~ "wmiprvse.exe")
| project TimeGenerated, DeviceName, AccountName, ActionType, AdditionalFields
\`\`\`

#### PsExec Detection
\`\`\`kql
// PsExec via service creation or named pipe
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where FileName =~ "psexesvc.exe"
    or (FileName =~ "services.exe" and ProcessCommandLine has "PSEXESVC")
    or InitiatingProcessFileName =~ "psexec.exe"
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine

// Alternative — via DeviceEvents (named pipe)
DeviceEvents
| where TimeGenerated >= ago(24h)
| where ActionType == "NamedPipeEvent"
| where AdditionalFields has "psexec" or AdditionalFields has "PSEXESVC"
\`\`\`

#### SigninLogs — Key Fields Reference
- UserPrincipalName — UPN e.g. user@domain.com
- UserDisplayName — display name
- IPAddress — source IP
- LocationDetails — nested: city, state, countryOrRegion, geoCoordinates
- DeviceDetail — nested: deviceId, operatingSystem, browser
- ConditionalAccessStatus — success, failure, notApplied
- AuthenticationRequirement — singleFactorAuthentication, multiFactorAuthentication
- ResultType — 0=success, non-zero=failure code
- ResultDescription — human readable failure reason
- AppDisplayName — application being accessed
- ClientAppUsed — Browser, Mobile Apps and Desktop Clients, etc
- RiskLevelDuringSignIn — none, low, medium, high
- RiskState — none, confirmedSafe, remediated, dismissed, atRisk, confirmedCompromised

### COMMON KQL MISTAKES TO AVOID

| WRONG | CORRECT | Reason |
|-------|---------|--------|
| \`where FileName = "powershell.exe"\` | \`where FileName =~ "powershell.exe"\` | Use =~ for case-insensitive filename matching |
| \`where FileName in ("cmd.exe","PS.exe")\` | \`where FileName in~ ("cmd.exe","PS.exe")\` | in~ for case-insensitive list match |
| \`summarize count by DeviceName\` | \`summarize count() by DeviceName\` | count requires parentheses |
| \`where TimeGenerated > ago("24h")\` | \`where TimeGenerated >= ago(24h)\` | ago() takes timespan, not string |
| \`project-away *\` to select all | \`project Field1, Field2\` | Explicit projection required |
| \`where ProcessCommandLine contains "base64"\` | \`where ProcessCommandLine has "base64"\` | has is faster for token search |
| Joining without kind= | \`join kind=inner\` | Always specify join kind |
| \`DeviceNetworkEvents\n| where...\` (no newline after table) | \`DeviceNetworkEvents\n| where ...\` | Table name on own line then pipe |

### KERBEROASTING IN KQL (T1558.003)
\`\`\`kql
// Kerberoasting via IdentityDirectoryEvents (Defender for Identity)
IdentityDirectoryEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "LDAP query"
| where AdditionalFields has "servicePrincipalName"
| where AdditionalFields !has "krbtgt"
| summarize QueryCount=count(), FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated)
    by AccountUpn, DeviceName, IPAddress
| where QueryCount > 5
| order by QueryCount desc

// Alternative via SecurityEvent (Windows event log)
SecurityEvent
| where TimeGenerated >= ago(7d)
| where EventID == 4769
| where TicketOptions == "0x40810010"
| where TicketEncryptionType == "0x17"  // RC4 — weak encryption used in Kerberoasting
| where ServiceName !endswith "$"
| summarize count() by AccountName, ServiceName, IPAddress
| order by count_ desc
\`\`\`

### SENTINEL HUNT EXAMPLES

#### PowerShell encoded commands
\`\`\`kql
DeviceProcessEvents
| where TimeGenerated >= ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc ", "-e ")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated desc
| take 200
\`\`\`

#### Suspicious Office child processes
\`\`\`kql
DeviceProcessEvents
| where TimeGenerated >= ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","outlook.exe","powerpnt.exe")
| where FileName in~ ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","certutil.exe","regsvr32.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| order by TimeGenerated desc
\`\`\`

#### Failed authentication brute force
\`\`\`kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType != "0"
| summarize FailCount = count(), AppList = make_set(AppDisplayName) by UserPrincipalName, IPAddress
| where FailCount > 20
| order by FailCount desc
\`\`\`

#### C2 beaconing detection
\`\`\`kql
DeviceNetworkEvents
| where TimeGenerated >= ago(24h)
| where RemoteIPType == "Public"
| summarize BeaconCount = count(), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
    by DeviceName, InitiatingProcessFileName, RemoteIP
| where BeaconCount > 50
| order by BeaconCount desc
\`\`\`

#### LSASS access
\`\`\`kql
DeviceEvents
| where TimeGenerated >= ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","werfault.exe","taskmgr.exe")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
\`\`\`
`;

// ─── SPL CORPUS ───────────────────────────────────────────────────────────────

export const SPL_CORPUS = `
## SPL (Search Processing Language) — Splunk Enterprise / Splunk Cloud / ES

SPL uses pipe-based syntax where commands transform search results left to right.
Key difference from XQL/KQL: search terms come first, then pipes refine.

### BASIC STRUCTURE
\`\`\`spl
index=<index> sourcetype=<sourcetype> [search terms]
| stats count by field
| sort -count
| head 200
\`\`\`

### CORE SEARCH COMMANDS
- search / where — filter events
- stats — aggregate (count, sum, avg, dc, values, list, min, max, range)
- table — select fields to display
- fields — include/exclude fields
- rename — rename fields
- eval — compute new fields
- rex — regex extraction
- dedup — deduplicate
- transaction — group events into sessions by field or time gap
- sort — sort results
- head / tail — limit results
- join — join datasets
- union / append — combine results
- lookup — enrich with lookup table
- inputlookup — read lookup as dataset
- tstats — fast stats over indexed fields
- datamodel — query data models

### FILTER SYNTAX
\`\`\`spl
index=windows sourcetype=WinEventLog:Security EventCode=4625
| search AccountName!="*$" AND IpAddress!="::1"
| where like(CommandLine, "%powershell%")
| where len(CommandLine) > 500
\`\`\`

Operators: =, !=, <, >, <=, >=, IN, NOT IN, LIKE, AND, OR, NOT

### TIME FILTERING
\`\`\`spl
earliest=-24h latest=now
earliest=-7d@d latest=@d
earliest="01/01/2024:00:00:00" latest="01/31/2024:23:59:59"
\`\`\`

### AGGREGATION (stats)
\`\`\`spl
| stats count by host, user
| stats dc(dest_ip) as unique_ips, values(dest_port) as ports by src_ip
| stats sum(bytes) as total_bytes by src_ip
| stats earliest(_time) as first_seen, latest(_time) as last_seen by process
| stats count as failures by user | where failures > 20
\`\`\`

### EVAL / COMPUTED FIELDS
\`\`\`spl
| eval cmd_length=len(CommandLine)
| eval is_encoded=if(match(CommandLine,"(?i)encodedcommand"),"YES","NO")
| eval hour=strftime(_time,"%H")
| eval domain=lower(replace(dest,"\\..*",""))
\`\`\`

### COMMON SPLUNK INDEXES & SOURCETYPES
#### Windows / Endpoint
- index=windows sourcetype=WinEventLog:Security — Windows Security events
- index=windows sourcetype=WinEventLog:System — Windows System events
- index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
- index=endpoint sourcetype=cylance:* — Cylance/BlackBerry
- index=endpoint sourcetype=crowdstrike:* — CrowdStrike Falcon (if forwarded)
- index=endpoint sourcetype=carbonblack:* — VMware Carbon Black

#### Sysmon Event IDs
- EventCode=1 — Process Create
- EventCode=3 — Network Connection
- EventCode=7 — Image Load (DLL)
- EventCode=8 — CreateRemoteThread
- EventCode=11 — File Create
- EventCode=12/13 — Registry

#### Windows Security Event IDs
- EventCode=4624 — Successful logon
- EventCode=4625 — Failed logon
- EventCode=4648 — Explicit credential logon
- EventCode=4662 — Object access (AD)
- EventCode=4672 — Special privilege logon
- EventCode=4688 — Process creation (with cmdline)
- EventCode=4697 — Service installation
- EventCode=4698/4702 — Scheduled task
- EventCode=4776 — NTLM authentication
- EventCode=7045 — New service installed

#### Network / Proxy
- index=network sourcetype=cisco:asa — Cisco ASA
- index=network sourcetype=pan:traffic — Palo Alto firewall
- index=network sourcetype=stream:http — HTTP stream
- index=network sourcetype=stream:dns — DNS stream
- index=proxy sourcetype=bluecoat:* — BlueCoat proxy
- index=zeek sourcetype=bro:* — Zeek/Bro IDS

#### Authentication / Identity
- index=auth sourcetype=ldap:* — LDAP
- index=auth sourcetype=okta:* — Okta
- index=o365 sourcetype=o365:management:activity — M365 audit



### SPL EXTENDED COVERAGE

#### Scheduled Task Creation (EventCode=4698)
\`\`\`spl
index=windows sourcetype=WinEventLog:Security EventCode=4698 earliest=-7d
| rename TaskName as scheduled_task_name
| table _time, ComputerName, SubjectUserName, TaskName, TaskContent
| sort -_time
\`\`\`

#### Shadow Copy Deletion (SPL)
\`\`\`spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1 earliest=-24h
| search (Image="*vssadmin.exe" CommandLine="*delete*") OR (Image="*wmic.exe" CommandLine="*shadowcopy*delete*")
| table _time, ComputerName, User, Image, CommandLine
| sort -_time
\`\`\`

#### Registry Run Key Persistence (Sysmon EventCode 12/13)
- EventCode=12 — RegistryEvent (Object create/delete)
- EventCode=13 — RegistryEvent (Value Set)
- EventCode=14 — RegistryEvent (Key/Value Rename)
- TargetObject — full registry path e.g. HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware
- Details — value data written
- Image — process making the change

\`\`\`spl
index=sysmon EventCode=13 earliest=-7d
| search TargetObject="*CurrentVersion\\Run*" OR TargetObject="*CurrentVersion\\RunOnce*"
| search NOT Image IN ("*msiexec.exe","*trustedinstaller.exe","*setup.exe")
| table _time, ComputerName, User, Image, TargetObject, Details
| sort -_time
\`\`\`

#### WMI Event Subscriptions (Sysmon EventCode 19/20/21)
- EventCode=19 — WmiEvent (WmiEventFilter activity detected)
- EventCode=20 — WmiEvent (WmiEventConsumer activity detected)
- EventCode=21 — WmiEvent (WmiEventConsumerToFilter activity detected)

\`\`\`spl
index=sysmon (EventCode=19 OR EventCode=20 OR EventCode=21) earliest=-7d
| table _time, ComputerName, User, EventCode, Name, Type, Destination, Consumer, Filter
| sort -_time
\`\`\`

#### New Admin Account (Security Events)
- EventCode=4720 — user account created
- EventCode=4722 — user account enabled
- EventCode=4728 — member added to global security group
- EventCode=4732 — member added to local security group (Administrators)
- EventCode=4756 — member added to universal security group

\`\`\`spl
index=windows sourcetype=WinEventLog:Security (EventCode=4720 OR EventCode=4732) earliest=-7d
| eval event_type=case(EventCode=4720,"Account Created",EventCode=4732,"Added to Admins",true(),"Other")
| table _time, ComputerName, SubjectUserName, TargetUserName, event_type
| sort -_time
\`\`\`

#### Remote Execution (EventCode=4688 with ParentProcessName)
- EventCode=4688 — process creation (requires audit process creation + command line logging)
- ParentProcessName — parent process path (available when command line auditing enabled)
- NewProcessName — spawned process full path
- CommandLine — command line if auditing enabled

\`\`\`spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 earliest=-24h
| search (ParentProcessName="*winword.exe" OR ParentProcessName="*excel.exe" OR ParentProcessName="*outlook.exe")
| search (NewProcessName="*cmd.exe" OR NewProcessName="*powershell.exe" OR NewProcessName="*wscript.exe")
| table _time, ComputerName, SubjectUserName, ParentProcessName, NewProcessName, CommandLine
| sort -_time
\`\`\`

#### Email Forwarding Rules (O365)
\`\`\`spl
index=o365 sourcetype=o365:management:activity earliest=-30d
| search (Operation="New-InboxRule" OR Operation="Set-InboxRule" OR Operation="Set-Mailbox")
| search (Parameters="*ForwardTo*" OR Parameters="*RedirectTo*" OR Parameters="*ForwardingSmtpAddress*")
| eval forwarding_dest=mvindex(split(Parameters,"ForwardTo"),1)
| table _time, UserId, ClientIP, Operation, Parameters, Name
| sort -_time
\`\`\`

#### Threat Intel IOC Lookup
\`\`\`spl
// Using | lookup for threat intel enrichment
index=network earliest=-24h
| stats count by dest_ip
| lookup threat_intel_ips ip as dest_ip OUTPUT threat_category, confidence
| where threat_category!=""
| sort -confidence

// Using | inputlookup to load IOC list
| inputlookup malicious_ips.csv
| rename ip as dest_ip
| join dest_ip [search index=network earliest=-24h | stats count by dest_ip]
\`\`\`

#### TaskName field reference
- TaskName — scheduled task name from EventCode=4698/4699/4700/4701/4702
- TaskContent — XML definition of the task
- SubjectUserName — user who created the task
\`\`\`spl
index=windows sourcetype=WinEventLog:Security (EventCode=4698 OR EventCode=4702) earliest=-7d
| table _time, ComputerName, SubjectUserName, TaskName
| sort -_time
\`\`\`

### COMMON SPL MISTAKES TO AVOID

| WRONG | CORRECT | Reason |
|-------|---------|--------|
| \`search Image=*powershell*\` | \`Image="*powershell*"\` | Quotes required for wildcard values |
| \`stats count\` | \`stats count() as count\` | count requires parens and alias |
| \`where count > 10\` after stats | \`where count > 10\` ✓ or \`having count > 10\` | where works after stats but must reference alias |
| \`sort -_time\` | \`sort -_time\` ✓ or \`sort 0 -_time\` | 0 means no limit on sort; omitting limits to 10000 |
| \`index=windows EventCode=4769\` | \`index=windows EventCode=4769\` ✓ | This is correct — EventCode without quotes |
| \`| rex field=CommandLine "(?P<encoded>-[eE][nN][cC].*)"\` | Same | rex uses named groups with (?P<name>) |
| \`earliest=-24h\` in search string | \`earliest=-24h latest=now\` | Always pair with latest |

### KERBEROASTING IN SPL (T1558.003)
\`\`\`spl
// Kerberoasting via Windows Security Event 4769
index=windows sourcetype=WinEventLog:Security EventCode=4769 earliest=-7d
TicketEncryptionType=0x17
| search ServiceName!="*$" AND ServiceName!="krbtgt"
| stats count as requests, values(ServiceName) as services, dc(ServiceName) as unique_spns
    by AccountName, IpAddress
| where requests > 3
| sort -requests

// Alternative via Sysmon LDAP query detection
index=sysmon EventCode=1 earliest=-7d
| search (CommandLine="*ldap*" OR CommandLine="*ADSI*") AND (CommandLine="*servicePrincipalName*" OR CommandLine="*SPN*")
| table _time, ComputerName, User, CommandLine
| sort -_time
\`\`\`


### O365 / AZURE AD FIELD REFERENCE (for BEC, identity, cloud investigations)

#### index=o365 sourcetype=o365:management:activity — Key fields (VERIFIED)
- UserId — UPN of user performing action e.g. user@domain.com (string)
- ClientIP — source IP of the action (string)
- Operation — action performed: UserLoggedIn, New-InboxRule, Send, Set-Mailbox etc (string)
- Workload — service: Exchange, AzureActiveDirectory, SharePoint, OneDrive (string)
- RecordType — log category: ExchangeAdmin, ExchangeItem, AzureActiveDirectory etc (string)
- ResultStatus — Success or Failed (string)
- UserAgent — browser/client user agent (string)
- Parameters — JSON array of cmdlet parameters for admin operations (string)
- Name — inbox rule name (string)
- Subject — email subject line (string)
- Recipients — email recipients (string)
- MessageId — unique message identifier (string)
- OrganizationId — tenant ID (string)
- CreationTime — event timestamp (string — use _time for SPL time filtering)
- Country — country of ClientIP (string)
- City — city of ClientIP (string)

#### Common O365 Operations for BEC Investigation
- UserLoggedIn / UserLoginFailed — authentication events
- New-InboxRule / Set-InboxRule — forwarding rule creation
- New-TransportRule / Set-TransportRule — tenant-wide transport rules
- Set-Mailbox — mailbox setting changes (ForwardingSmtpAddress)
- Send — email send events
- FileDownloaded / FileAccessed — SharePoint/OneDrive data access
- Add member to role — privilege escalation
- Reset user password — account takeover indicator
- MipLabel — sensitivity label changes

### SPL EVAL FUNCTIONS REFERENCE

\`\`\`spl
| eval duration_hours=round((last_seen-first_seen)/3600,1)
| eval avg_per_hour=round(count/if(duration_hours>0,duration_hours,1),1)
| eval is_after_hours=if(strftime(_time,"%H") < "08" OR strftime(_time,"%H") >= "18","YES","NO")
| eval domain=replace(UserId,".*@","")
| eval short_ip=replace(src_ip,"(\\d+\\.\\d+\\.\\d+)\\..*","\\1.x")
\`\`\`

#### SPL Math/String Functions
- round(num, decimals) — round to decimal places
- if(condition, true_val, false_val) — conditional
- len(field) — string length
- substr(field, start, len) — substring
- replace(field, regex, replacement) — regex replace
- lower(field) / upper(field) — case conversion
- strftime(_time, format) — format timestamp
- relative_time(now(), "-7d@d") — relative time calculation
- coalesce(field1, field2) — first non-null value
- mvcount(field) — count of multivalue field values
- mvindex(field, n) — nth value of multivalue field

### SPL COMMENT SYNTAX (VALID FORMS)

\`\`\`spl
// Single line comment — VALID and commonly used
| stats count by host  // inline comment — VALID

/* Multi-line comment
   also valid */

| stats count by host  \`backtick comments\` -- NOT standard

\`\`\`
NOTE FOR VALIDATOR: // comments in SPL are VALID syntax. Do NOT flag // as a syntax error or warning.
Multiple | search commands in sequence are VALID SPL — do not flag as consolidation error.
Chained search commands are intentional for readability in complex investigations.

### SPL HUNT EXAMPLES

#### PowerShell encoded commands (Sysmon)
\`\`\`spl
index=sysmon sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1
| search (CommandLine="*-EncodedCommand*" OR CommandLine="*-enc *" OR CommandLine="*-e *")
  Image="*powershell*"
| table _time, ComputerName, User, CommandLine, ParentImage
| sort -_time
| head 200
\`\`\`

#### Office process spawning shells
\`\`\`spl
index=sysmon EventCode=1
| search ParentImage IN ("*winword.exe","*excel.exe","*outlook.exe","*powerpnt.exe")
  Image IN ("*cmd.exe","*powershell.exe","*wscript.exe","*mshta.exe","*certutil.exe")
| table _time, ComputerName, User, ParentImage, Image, CommandLine
| sort -_time
\`\`\`

#### Failed logins brute force (Security log)
\`\`\`spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by TargetUserName, IpAddress
| where failures > 20
| sort -failures
\`\`\`

#### C2 beaconing (high frequency outbound)
\`\`\`spl
index=network sourcetype=pan:traffic earliest=-24h
| where dest_ip!="10.0.0.0/8" AND dest_ip!="172.16.0.0/12" AND dest_ip!="192.168.0.0/16"
| stats count as connections, dc(dest_port) as ports by src_ip, dest_ip, app
| where connections > 100
| sort -connections
\`\`\`

#### LSASS access via Sysmon
\`\`\`spl
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| search NOT SourceImage IN ("*MsMpEng.exe","*werfault.exe","*taskmgr.exe","*csrss.exe")
| table _time, ComputerName, SourceImage, TargetImage, GrantedAccess
| sort -_time
\`\`\`
`;

// ─── CQL CORPUS ───────────────────────────────────────────────────────────────

export const CQL_CORPUS = `
## CQL / LogScale Query Language — CrowdStrike Falcon (NG-SIEM / LogScale)

CrowdStrike Falcon NG-SIEM uses LogScale Query Language (LQL), sometimes called CQL.
It is event-driven and optimized for high-speed streaming search.

### BASIC STRUCTURE
\`\`\`cql
// Filter first, then transform
#event_simpleName=ProcessRollup2
| CommandLine=*powershell*
| groupBy([ComputerName, UserName, CommandLine], function=count())
| sort(field=_count, order=desc)
| limit(200)
\`\`\`

### CORE OPERATORS
- field=value — basic filter (implicit AND between terms)
- | filter() — programmatic filter
- | groupBy() — aggregate (equivalent to summarize/stats/comp)
- | sort() — sort results
- | limit() — limit results
- | select() — choose fields
- | rename() — rename fields
- | eval() / | := — compute new fields
- | regex() — regex filter/extract
- | format() — string formatting
- | join() — join datasets
- | match() — match against file/list
- | table() — display as table
- | timechart() — time-based aggregation
- | stats() — statistics

### FILTER SYNTAX — CRITICAL RULES

## RULE 1: Multi-condition filters — ALL on same line or use pipe stages
\`\`\`cql
// CORRECT — multiple conditions on same line (implicit AND)
#event_simpleName=ProcessRollup2 CommandLine=*ldap* FileName=*net.exe*

// CORRECT — chain with pipe stages
#event_simpleName=ProcessRollup2
| CommandLine=*ldap*
| FileName!=*svchost.exe*

// WRONG — do NOT put each condition on a new line without pipes
// #event_simpleName=ProcessRollup2
// CommandLine=*ldap*            <-- this is NOT valid
// FileName=*net.exe*            <-- this is NOT valid
\`\`\`

## RULE 2: Regex syntax — /pattern/ for inline, regex() for pipe stage
\`\`\`cql
// CORRECT — regex inline filter (case-insensitive with /i flag)
#event_simpleName=ProcessRollup2
| FileName=/powershell\.exe/i

// CORRECT — regex in pipe (for complex patterns)
#event_simpleName=ProcessRollup2
| regex("(?i)encodedcommand", field=CommandLine)

// CORRECT — regex exclusion
| FileName!=/adexplorer\.exe|ldp\.exe|dsquery\.exe/i

// WRONG — /i flag outside regex inline context
// | CommandLine=/ldap/i          <-- valid
// NOT CommandLine=/ldap/i        <-- WRONG, use | filter(NOT ...)
\`\`\`

## RULE 3: Wildcard vs Regex — use wildcards for simple matching
\`\`\`cql
// Wildcard (simpler, preferred for basic contains)
CommandLine=*ldap*
CommandLine=*kerberos*

// Regex (use for alternation, anchors, complex patterns)
| CommandLine=/ldap|kerberos|spn/i

// Negation wildcard
FileName!=*svchost.exe*

// Negation regex
| FileName!=/MsMpEng\.exe|werfault\.exe|taskmgr\.exe/i
\`\`\`

## RULE 4: Boolean operators
\`\`\`cql
// OR between event types
#event_simpleName=ProcessRollup2 OR #event_simpleName=SyntheticProcessRollup2

// AND is implicit between space-separated conditions
CommandLine=*ldap* FileName=*net.exe*

// Explicit AND
CommandLine=*ldap* AND FileName=*net.exe*

// NOT
NOT FileName=*svchost*
NOT FileName=/MsMpEng\.exe|taskmgr\.exe/i

// Parentheses for grouping
(CommandLine=*ldap* OR CommandLine=*kerberos*) FileName!=*svchost*
\`\`\`

## RULE 5: | filter() for complex programmatic conditions
\`\`\`cql
#event_simpleName=ProcessRollup2
| filter(CommandLine=*ldap* OR CommandLine=*kerb*)
| filter(NOT FileName=/MsMpEng\.exe|svchost\.exe/i)
| groupBy([ComputerName, UserName, CommandLine])
\`\`\`

### TIME FILTERING
\`\`\`cql
// Last 24 hours — set in UI time picker or:
| timechart(span=1h, function=count())

// Relative time in filter
| where(@timestamp > now() - 86400000)  // milliseconds
\`\`\`

### AGGREGATION
\`\`\`cql
| groupBy([ComputerName], function=count())
| groupBy([ComputerName, UserName], function=[count(), collect(CommandLine)])
| groupBy([SourceIP, DestinationIP], function=[count(as=connections), min(@timestamp, as=first_seen)])
\`\`\`

### KEY CROWDSTRIKE EVENT NAMES (#event_simpleName)
#### Process Events
- ProcessRollup2 — process execution (primary)
- SyntheticProcessRollup2 — synthetic process (endpoint activity)
- ProcessRollup2Bpf — eBPF process (Linux)
- UserIdentity — user context

#### Network Events
- NetworkConnectIP4 — IPv4 outbound connection
- NetworkConnectIP6 — IPv6 outbound connection
- DnsRequest — DNS query
- NetworkReceiveAcceptIP4 — inbound connection

#### File Events
- NewExecutableWritten — new executable file
- NewScriptWritten — new script file
- DocumentProgramInjection — doc spawning process

#### Registry Events
- RegKeyValueSetByProcessId — registry value set
- RegKeyCreated — registry key created
- RegKeyDeleted — registry key deleted

#### Authentication
- UserLogon — user logon
- UserLogoff — user logoff
- AuthActivityAuditEvent — auth audit

#### Detection / Alert
- DetectionSummaryEvent — detection summary
- EppDetectionSummaryEvent — EPP detection
- IncidentSummaryEvent — incident

### KEY FIELD NAMES (CrowdStrike)

#### ProcessRollup2 — Complete field reference (VERIFIED)
- ComputerName — hostname (string)
- UserName — username (string)
- UserSid — user SID (string)
- FileName — process filename only e.g. powershell.exe (string)
- FilePath — directory path of process (string)
- ImageFileName — full path e.g. \\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe (string)
- CommandLine — full command line with arguments (string)
- ParentBaseFileName — parent process filename only (string)
- ParentImageFileName — parent process full path (string)
- ParentCommandLine — parent process command line (string)
- ParentProcessId — parent PID (integer)
- ProcessId — process PID (integer)
- SHA256HashData — SHA256 hash of executable (string)
- MD5HashData — MD5 hash (string)
- IntegrityLevel — process integrity: Low/Medium/High/System (string)
- TokenType — Primary or Impersonation (string)
- SessionId — Windows session ID (integer)
- RawProcessId — raw process ID (integer)
- TargetProcessId — target process PID for injection events (integer)
- TargetProcessName — target process name for injection (string)
- EffectiveTransmissionClass — network class (integer)
- Tags — sensor tags (string)
- aid — agent ID / sensor ID (string)
- aip — agent IP address (string)
- cid — customer ID (string)
- @timestamp — event timestamp in epoch ms (integer)
- ContextTimeStamp — context timestamp (string)
- event_platform — Win/Mac/Lin (string)

#### NetworkConnectIP4 — Complete field reference (VERIFIED)
- ComputerName — hostname (string)
- UserName — username (string)
- FileName — process making connection (string)
- ImageFileName — full process path (string)
- CommandLine — process command line (string)
- LocalAddressIP4 — source IP (string)
- LocalPort — source port (integer)
- RemoteAddressIP4 — destination IP (string)
- RemotePort — destination port (integer)
- Protocol — protocol number: 6=TCP, 17=UDP (integer)
- ConnectionFlags — connection flags (integer)
- aid, aip, cid — agent identifiers

#### DnsRequest — Complete field reference (VERIFIED)
- ComputerName — hostname (string)
- UserName — username (string)
- FileName — process making DNS request (string)
- DomainName — queried domain (string)
- RequestType — DNS record type: 1=A, 28=AAAA, 16=TXT (integer)
- InterfaceIndex — network interface (integer)

#### UserLogon — Complete field reference (VERIFIED)
- ComputerName — hostname (string)
- UserName — username (string)
- UserSid — user SID (string)
- LogonType — 2=interactive, 3=network, 4=batch, 5=service, 10=remote (integer)
- UserIsAdmin — 1 if admin (integer)
- AuthenticationPackage — NTLM, Kerberos, Negotiate (string)
- LogonDomain — domain (string)
- RemoteAccount — 1 if remote (integer)

#### RegKeyValueSetByProcessId — Complete field reference (VERIFIED)
- ComputerName — hostname (string)
- UserName — username (string)
- FileName — process making registry change (string)
- RegObjectName — full registry key path (string)
- RegStringValue — string value data (string)
- RegNumericValue — numeric value data (integer)
- RegOperationType — Create/Set/Delete (string)

#### Common fields on ALL events
- aid — agent/sensor ID (string) — use for per-host filtering
- aip — agent IP address (string)
- cid — customer ID (string)
- @timestamp — epoch milliseconds (integer)
- event_platform — Win / Mac / Lin (string)
- #event_simpleName — event type name (string)



### CQL EXTENDED COVERAGE

#### Registry Events — Complete Reference
\`\`\`cql
// Registry persistence — Run key modification
#event_simpleName=RegKeyValueSetByProcessId
| RegObjectName=*CurrentVersion\\Run*
| filter(NOT FileName=/msiexec\.exe|trustedinstaller\.exe|setup\.exe/i)
| groupBy([ComputerName, UserName, FileName, RegObjectName, RegStringValue], function=count())
| sort(field=@timestamp, order=desc)
\`\`\`

#### RegKeyValueSetByProcessId — RegistryPath variants
- RegObjectName — full registry key path
  e.g. \\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\malware
- RegStringValue — string value data written
- RegNumericValue — numeric value data
- RegOperationType — type of operation

#### Certutil and LOLBin Download Patterns
\`\`\`cql
// Certutil urlcache download
#event_simpleName=ProcessRollup2
| FileName=/certutil\.exe/i
| CommandLine=*urlcache* OR CommandLine=*-decode* OR CommandLine=*-encode*
| groupBy([ComputerName, UserName, CommandLine], function=count())
| sort(field=@timestamp, order=desc)
\`\`\`

#### Wildcard Examples (CQL)
\`\`\`cql
// Wildcard contains — use * on both sides
CommandLine=*encoded*
CommandLine=*powershell*
FileName=*powershell*

// Wildcard starts with
CommandLine=powershell*

// Wildcard ends with
FileName=*.exe

// Multiple wildcards with OR
CommandLine=*EncodedCommand* OR CommandLine=*-enc * OR CommandLine=*bypass*

// Wildcard NOT equal
FileName!=*svchost*
\`\`\`

### KERBEROASTING & LDAP HUNTING (T1558.003)

Kerberoasting in CrowdStrike is observed via LDAP queries for service principal names.
The key event is LdapSearchQueryV4 — NOT ProcessRollup2.

#### LdapSearchQueryV4 — Complete field reference (VERIFIED)
- ComputerName — hostname (string)
- UserName — user performing LDAP query (string)
- DistinguishedName — LDAP search base DN (string)
- SearchFilter — LDAP filter string e.g. (servicePrincipalName=*) (string)
- AttributeList — requested attributes (string)
- Scope — search scope: Base/OneLevel/Subtree (string)
- aid, aip, cid, @timestamp — standard fields

#### Kerberoasting detection query (CORRECT CQL)
\`\`\`cql
// Hunt for LDAP queries targeting service principal names — Kerberoasting indicator
#event_simpleName=LdapSearchQueryV4
| SearchFilter=*servicePrincipalName*
| filter(NOT UserName=/krbtgt|\.\$$/i)
| groupBy([ComputerName, UserName, SearchFilter, DistinguishedName], function=[count(as=query_count), min(@timestamp, as=first_seen), max(@timestamp, as=last_seen)])
| sort(field=query_count, order=desc)
\`\`\`

#### Network-based Kerberoasting (ticket requests)
\`\`\`cql
// Kerberos TGS requests to non-standard services — may indicate Kerberoasting
#event_simpleName=KerberosTicketGranted
| TicketOptions=*forwardable*
| filter(NOT ServiceName=/krbtgt|cifs|host|rpcss|ldap/i)
| groupBy([ComputerName, UserName, ServiceName], function=count())
| sort(field=_count, order=desc)
\`\`\`

### COMMON CQL MISTAKES TO AVOID

| WRONG | CORRECT | Reason |
|-------|---------|--------|
| \`CommandLine=/ldap/i\` on its own line without pipe | \`| CommandLine=/ldap/i\` | Pipe required before field filter in chain |
| \`/adexplorer.exe/i\` | \`/adexplorer\\.exe/i\` | Dot must be escaped in regex |
| \`NOT FileName=/a.exe/i\` at start | \`| filter(NOT FileName=/a\\.exe/i)\` | NOT requires filter() wrapper in pipe stage |
| \`groupBy([f1,f2])\` | \`groupBy([f1, f2], function=count())\` | function= required in groupBy |
| \`sort(field=count)\` | \`sort(field=_count, order=desc)\` | Auto-named count field is _count |
| \`FileName=powershell.exe\` | \`FileName=powershell.exe\` OR \`FileName=/powershell\\.exe/i\` | Exact match OK, but regex needs escaped dot |
| Multiple bare field filters on separate lines | Use \`| field=value\` per line or combine with spaces | Each pipe stage is a separate operation |


### CQL HUNT EXAMPLES

#### PowerShell encoded commands
\`\`\`cql
#event_simpleName=ProcessRollup2
| FileName=/powershell\.exe/i
| CommandLine=*EncodedCommand* OR CommandLine=*-enc * OR CommandLine=*-e *
| groupBy([ComputerName, UserName, CommandLine, ParentBaseFileName], function=count())
| sort(field=_count, order=desc)
\`\`\`

#### Office apps spawning suspicious children
\`\`\`cql
#event_simpleName=ProcessRollup2
| ParentBaseFileName=/winword\.exe|excel\.exe|outlook\.exe|powerpnt\.exe/i
| FileName=/cmd\.exe|powershell\.exe|wscript\.exe|mshta\.exe|certutil\.exe/i
| groupBy([ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(field=@timestamp, order=desc)
\`\`\`

#### Failed authentications
\`\`\`cql
#event_simpleName=UserLogon
| LogonType=3
| UserIsAdmin=0
| groupBy([UserName, aip], function=[count(as=attempts)])
| where(attempts > 20)
| sort(field=attempts, order=desc)
\`\`\`

#### High-frequency outbound connections (beaconing)
\`\`\`cql
#event_simpleName=NetworkConnectIP4
| RemoteAddressIP4!=/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/
| groupBy([ComputerName, FileName, RemoteAddressIP4, RemotePort], function=[count(as=connections), min(@timestamp, as=first_seen)])
| where(connections > 100)
| sort(field=connections, order=desc)
\`\`\`

#### LSASS access patterns
\`\`\`cql
#event_simpleName=ProcessRollup2
| TargetProcessName=/lsass/i
| FileName!=/MsMpEng\.exe|werfault\.exe|taskmgr\.exe/i
| groupBy([ComputerName, UserName, FileName, CommandLine])
| sort(field=@timestamp, order=desc)
\`\`\`

### SCHEMA DISCOVERY QUERIES (CrowdStrike / LogScale)
\`\`\`cql
// List all event types in your environment
groupBy([#event_simpleName], function=count())
| sort(field=_count, order=desc)

// Fields for a specific event type
#event_simpleName=ProcessRollup2
| limit(1)
| table(*)

// Most active event types last 24h
groupBy([#event_simpleName], function=count())
| sort(field=_count, order=desc)
| limit(50)
\`\`\`
`;

// ─── PLATFORM DISCOVERY QUERIES ───────────────────────────────────────────────

export const PLATFORM_DISCOVERY_QUERIES: Record<string, {
  label: string;
  description: string;
  query: string;
}[]> = {
  xql: [
    {
      label: "All Datasets",
      description: "Lists every dataset in your XSIAM tenant with retention and storage tier.",
      query: `dataset = datasets
| fields name, retention_in_days, data_vendor, schema_fields_count
| sort asc name`,
    },
    {
      label: "All Fields (recommended)",
      description: "Full field inventory across all datasets. Export as JSON.",
      query: `dataset = dataset_fields
| fields dataset_name, field_name, field_type
| sort asc dataset_name, field_name`,
    },
  ],
  kql: [
    {
      label: "All Tables in Workspace",
      description: "Lists all tables available in your Sentinel workspace.",
      query: `union withsource=TableName *
| summarize count() by TableName
| order by TableName asc`,
    },
    {
      label: "Table Schema (single table)",
      description: "Get column names and types for a specific table. Replace TABLE_NAME.",
      query: `TABLE_NAME
| getschema
| project ColumnName, ColumnType
| order by ColumnName asc`,
    },
    {
      label: "Recent Tables with Data",
      description: "Tables that have had data in the last 24 hours.",
      query: `union withsource=TableName *
| where TimeGenerated >= ago(24h)
| summarize LastEvent=max(TimeGenerated), Count=count() by TableName
| order by Count desc`,
    },
  ],
  spl: [
    {
      label: "All Indexes",
      description: "Lists all indexes available in your Splunk environment.",
      query: `| rest /services/data/indexes
| table title, totalEventCount, currentDBSizeMB, minTime, maxTime
| sort title`,
    },
    {
      label: "Sourcetypes per Index",
      description: "Shows all sourcetypes across indexes.",
      query: `| metadata type=sourcetypes index=*
| table sourcetype, index, totalCount, recentTime
| sort index, sourcetype`,
    },
    {
      label: "Field Summary for Sourcetype",
      description: "Replace SOURCETYPE with your sourcetype name.",
      query: `index=* sourcetype=SOURCETYPE earliest=-1h
| fieldsummary
| table field, count, distinct_count, type
| sort field`,
    },
  ],
  cql: [
    {
      label: "All Event Types",
      description: "Lists all event simplenames in your Falcon environment.",
      query: `groupBy([#event_simpleName], function=count())
| sort(field=_count, order=desc)`,
    },
    {
      label: "Fields for Event Type",
      description: "Shows all fields for a specific event. Replace EVENT_NAME.",
      query: `#event_simpleName=EVENT_NAME
| limit(1)
| table(*)`,
    },
    {
      label: "Active Sensors",
      description: "Counts active sensors by platform.",
      query: `#event_simpleName=ProcessRollup2
| groupBy([event_platform], function=count(as=events))
| sort(field=events, order=desc)`,
    },
  ],
};

// ─── PLATFORM VALIDATOR DATASETS ─────────────────────────────────────────────

export const PLATFORM_KNOWN_DATASETS: Record<string, string[]> = {
  xql: [
    "xdr_data", "process_events", "network_connections", "file_events",
    "registry_events", "module_events", "auth_events", "identity_analytics",
    "directory_sync", "firewall_events", "network_story", "dns_events",
    "url_events", "cloud_audit_logs", "cloud_asset_db", "xdr_alerts",
    "incidents", "datasets", "dataset_fields",
  ],
  kql: [
    "DeviceProcessEvents", "DeviceNetworkEvents", "DeviceFileEvents",
    "DeviceRegistryEvents", "DeviceLogonEvents", "DeviceImageLoadEvents",
    "DeviceEvents", "DeviceAlertEvents", "SigninLogs", "AuditLogs",
    "AADNonInteractiveUserSignInLogs", "IdentityLogonEvents",
    "IdentityDirectoryEvents", "SecurityEvent", "WindowsEvent", "Syslog",
    "AzureActivity", "AWSCloudTrail", "GCPAuditLogs", "CloudAppEvents",
    "OfficeActivity", "EmailEvents", "EmailAttachmentInfo", "EmailUrlInfo",
    "CommonSecurityLog", "DnsEvents", "NetworkAccessTraffic",
    "SecurityAlert", "SecurityIncident", "BehaviorAnalytics",
  ],
  spl: [
    "index=windows", "index=sysmon", "index=endpoint", "index=network",
    "index=auth", "index=proxy", "index=o365", "index=zeek",
    "sourcetype=WinEventLog:Security", "sourcetype=WinEventLog:System",
    "sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "sourcetype=pan:traffic", "sourcetype=cisco:asa", "sourcetype=stream:http",
    "sourcetype=stream:dns", "sourcetype=okta:*", "sourcetype=o365:management:activity",
  ],
  cql: [
    "ProcessRollup2", "SyntheticProcessRollup2", "NetworkConnectIP4",
    "NetworkConnectIP6", "DnsRequest", "NetworkReceiveAcceptIP4",
    "NewExecutableWritten", "NewScriptWritten", "DocumentProgramInjection",
    "RegKeyValueSetByProcessId", "RegKeyCreated", "RegKeyDeleted",
    "UserLogon", "UserLogoff", "AuthActivityAuditEvent",
    "DetectionSummaryEvent", "EppDetectionSummaryEvent", "IncidentSummaryEvent",
    "UserIdentity", "ProcessRollup2Bpf",
    "#repo",
  ],
};
