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

### FILTER SYNTAX
\`\`\`cql
// Exact match
#event_simpleName=ProcessRollup2

// Wildcard
CommandLine=*encoded*

// Multiple values (OR)
#event_simpleName=ProcessRollup2 OR #event_simpleName=NetworkConnectIP4

// Negation
NOT CommandLine=*svchost*

// Regex
| regex("(?i)encodedcommand", field=CommandLine)

// Field comparison
| where(_count > 100)
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
- ComputerName — hostname
- UserName — username
- UserSid — user SID
- FileName — process filename
- CommandLine — full command line
- ImageFileName — full process path
- ParentImageFileName — parent process path
- ParentCommandLine — parent command line
- MD5HashData, SHA256HashData — file hashes
- TargetFileName — target file (for file events)
- ContextTimeStamp — event timestamp
- LocalAddressIP4, LocalPort — source network
- RemoteAddressIP4, RemotePort — destination network
- DomainName — DNS query domain
- RegistryPath, RegistryValueName, RegistryValueData
- PatternDispositionDescription — prevention action
- Tactic, Technique — ATT&CK fields (on detections)
- SensorId — unique sensor/endpoint ID
- aip — agent IP address
- aid — agent ID

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
  ],
};
