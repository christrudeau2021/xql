// XQL Corpus — Palo Alto Networks XQL Query Language
// Reference knowledge for the AI translator

export const XQL_CORPUS = `
## XQL (Extended Query Language) — Cortex XDR / XSIAM

XQL is a SQL-like query language designed for security investigations across Cortex XDR/XSIAM datasets.
It uses a pipe-based syntax where each stage filters, transforms, or aggregates data.

---

## BASIC QUERY STRUCTURE

\`\`\`
dataset = <dataset_name>
| filter <condition>
| fields <field1>, <field2>
| sort desc <field>
| limit <n>
\`\`\`

---

## CONFIG BLOCK (alternative to filter-based time range)

\`\`\`xql
// config block sets global timeframe for the query
// Use instead of | filter event_timestamp >= subtract_time(...)
config timeframe = 24h
| dataset = xdr_data
| filter event_type = "PROCESS"
| filter actor_process_image_name = "powershell.exe"
\`\`\`

Time units for config: m (minutes), h (hours), d (days), w (weeks)
Note: config block must appear BEFORE dataset declaration

---

## CORE DATASETS (most commonly used)

### Endpoint / Process Activity
- **xdr_data** — Main endpoint telemetry (process, network, file, registry)
- **process_events** — Process creation events
- **network_connections** — Network connection telemetry
- **file_events** — File create/modify/delete events
- **registry_events** — Windows registry operations
- **module_events** — DLL/module load events

### Identity & Authentication
- **auth_events** — Authentication attempts (login/logoff)
- **identity_analytics** — Identity-based analytics
- **directory_sync** — AD/LDAP directory sync data

### Network / Firewall
- **firewall_events** — Palo Alto Networks firewall logs
- **network_story** — Network analytics story
- **dns_events** — DNS query telemetry
- **url_events** — URL/HTTP traffic

### Cloud
- **cloud_audit_logs** — Cloud provider audit logs (AWS CloudTrail, Azure Activity, GCP)
- **cloud_asset_db** — Cloud asset inventory

### Alerts & Incidents
- **xdr_alerts** — All XDR alerts
- **incidents** — Incident data

---

## FILTERING — filter stage

\`\`\`
| filter actor_process_image_name = "powershell.exe"
| filter action_remote_port in (443, 80, 8080)
| filter event_timestamp >= to_epoch("2024-01-01", "yyyy-MM-dd")
| filter actor_process_command_line contains "encoded"
| filter actor_process_command_line ~= ".*base64.*" // regex
\`\`\`

### Filter Operators
- = , != , < , > , <= , >=
- in (val1, val2) — match list
- not in (val1, val2) — exclude list
- contains — substring match (case-insensitive)
- not contains
- ~= — regex match
- !~= — regex NOT match
- starts_with / ends_with
- is null / is not null

---

## FIELD SELECTION — fields stage

\`\`\`
| fields event_timestamp, actor_process_image_name, action_remote_ip, action_remote_port
| fields - unwanted_field  // exclude a field
\`\`\`

---

## SORTING — sort stage

\`\`\`
| sort desc event_timestamp
| sort asc actor_process_image_name
\`\`\`

---

## LIMITING — limit stage

\`\`\`
| limit 100
\`\`\`

---

## AGGREGATION — comp (compute) stage

\`\`\`
| comp count() as total_count
| comp count() as total_count by actor_process_image_name
| comp count_distinct(action_remote_ip) as unique_ips by actor_process_image_name
| comp sum(bytes_sent) as total_bytes by src_ip
| comp min(event_timestamp), max(event_timestamp) by actor_process_image_name
\`\`\`

### Aggregation Functions
- count() — count all rows
- count_distinct(field) — count unique values
- sum(field) — sum numeric field
- avg(field) — average
- min(field) — minimum value
- max(field) — maximum value
- values(field) — collect all values into array
- array_agg(field) — aggregate into array

---

## FIELD CREATION — alter stage (computed fields)

\`\`\`
| alter lower_process = lowercase(actor_process_image_name)
| alter cmd_length = string_length(actor_process_command_line)
| alter is_encoded = if(actor_process_command_line contains "base64", "YES", "NO")
| alter hour_of_day = extract_time(event_timestamp, "HOUR")
\`\`\`

### Useful alter functions
- lowercase(field) / uppercase(field)
- string_length(field)
- substring(field, start, length)
- split(field, delimiter)
- concat(field1, field2)
- to_string(field)
- to_integer(field)
- if(condition, true_value, false_value)
- coalesce(field1, field2) — first non-null
- trim(field)
- extract_time(timestamp, "HOUR"|"MINUTE"|"DAY"|"MONTH")
- format_timestamp(field, "yyyy-MM-dd HH:mm:ss")
- to_epoch(string, format)
- from_epoch(ms)
- json_extract_scalar(field, "$.path") — parse JSON
- array_length(field)
- array_contains(array_field, value)

---

## TIME FILTERING

\`\`\`
| filter event_timestamp >= subtract_time(now(), "24h")
| filter event_timestamp between (to_epoch("2024-01-01", "yyyy-MM-dd"), to_epoch("2024-01-31", "yyyy-MM-dd"))
\`\`\`

Time units: s (seconds), m (minutes), h (hours), d (days), w (weeks)

---

## JOINS — join stage

\`\`\`
dataset = xdr_data
| filter event_type = "PROCESS"
| join type=inner (
    dataset = network_connections
    | filter action_remote_port = 443
  ) actor_process_image_name
\`\`\`

Join types: inner, left, right, full

---

## UNION — union stage

\`\`\`
union (
  dataset = process_events | filter actor_process_image_name = "cmd.exe",
  dataset = process_events | filter actor_process_image_name = "powershell.exe"
)
\`\`\`

---

## COMMON XQL FIELD NAMES (xdr_data / endpoint telemetry)

### Process fields
- actor_process_image_name — executing process filename
- actor_process_image_path — full path
- actor_process_command_line — full command line
- actor_process_pid — process ID
- actor_process_signature_status — digital signature status (SIGNED, UNSIGNED)
- actor_process_signature_vendor — signing vendor
- actor_process_causality_id — causality chain ID
- causality_actor_process_image_name — parent/causality process
- os_actor_process_image_name — OS-level process

### Target Process fields
- action_process_image_name — spawned process
- action_process_image_path
- action_process_command_line

### Network fields
- action_remote_ip — destination IP
- action_remote_port — destination port
- action_local_ip — source IP
- action_local_port — source port
- action_network_protocol — TCP, UDP, ICMP
- dns_query_name — DNS query
- action_external_hostname — resolved hostname

### File fields
- action_file_name — file name
- action_file_path — full path
- action_file_extension — extension
- action_file_sha256 — SHA256 hash
- action_file_size — file size in bytes

### Registry fields
- action_registry_key_name — registry key
- action_registry_value_name — value name
- action_registry_data — value data

### General / Common
- event_timestamp — event time (epoch ms)
- event_type — PROCESS, NETWORK, FILE, REGISTRY, etc.
- endpoint_id — unique endpoint identifier
- host_name — hostname
- agent_hostname — hostname (alternate)
- agent_ip_addresses — endpoint IPs
- os_type — WINDOWS, MAC, LINUX
- user_name — username
- agent_domain — domain

---

## THREAT HUNTING EXAMPLES

### 1. Detect PowerShell with encoded commands
\`\`\`
dataset = xdr_data
| filter event_type = "PROCESS"
| filter actor_process_image_name ~= "(?i)powershell"
| filter actor_process_command_line ~= "(?i)(encodedcommand|-enc|-e\\s)"
| fields event_timestamp, host_name, user_name, actor_process_command_line
| sort desc event_timestamp
| limit 200
\`\`\`

### 2. Suspicious parent-child relationships (living off the land)
\`\`\`
dataset = xdr_data
| filter event_type = "PROCESS"
| filter causality_actor_process_image_name in ("word.exe","excel.exe","outlook.exe","winword.exe")
| filter actor_process_image_name in ("cmd.exe","powershell.exe","wscript.exe","mshta.exe","certutil.exe","regsvr32.exe")
| fields event_timestamp, host_name, user_name, causality_actor_process_image_name, actor_process_image_name, actor_process_command_line
| sort desc event_timestamp
\`\`\`

### 3. Lateral movement via admin shares
\`\`\`
dataset = xdr_data
| filter event_type = "NETWORK"
| filter action_remote_port in (445, 139)
| filter actor_process_image_name not in ("system", "svchost.exe")
| comp count() as connection_count, values(action_remote_ip) as destinations by actor_process_image_name, host_name
| filter connection_count > 10
| sort desc connection_count
\`\`\`

### 4. C2 beaconing — periodic outbound connections
\`\`\`
dataset = xdr_data
| filter event_type = "NETWORK"
| filter action_remote_ip not in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| comp count() as beacon_count, min(event_timestamp) as first_seen, max(event_timestamp) as last_seen by actor_process_image_name, action_remote_ip, host_name
| filter beacon_count > 100
| sort desc beacon_count
\`\`\`

### 5. Credential dumping indicators (LSASS access)
\`\`\`
dataset = xdr_data
| filter event_type = "PROCESS"
| filter action_process_image_name ~= "(?i)lsass"
| filter actor_process_image_name not in ("werfault.exe","taskmgr.exe","svchost.exe")
| fields event_timestamp, host_name, user_name, actor_process_image_name, actor_process_command_line
| sort desc event_timestamp
\`\`\`

### 6. Unusual DNS queries (DGA detection)
\`\`\`
dataset = xdr_data
| filter event_type = "NETWORK"
| filter dns_query_name is not null
| alter domain_length = string_length(dns_query_name)
| filter domain_length > 30
| comp count() as query_count, values(host_name) as hosts by dns_query_name
| sort desc query_count
| limit 100
\`\`\`

### 7. Persistence via registry run keys
\`\`\`
dataset = xdr_data
| filter event_type = "REGISTRY"
| filter action_registry_key_name ~= "(?i)(run|runonce)"
| filter actor_process_image_name not in ("msiexec.exe","setup.exe","install.exe")
| fields event_timestamp, host_name, user_name, actor_process_image_name, action_registry_key_name, action_registry_value_name, action_registry_data
| sort desc event_timestamp
\`\`\`

### 8. Ransomware indicators — mass file extension changes
\`\`\`
dataset = xdr_data
| filter event_type = "FILE"
| filter action_file_extension not in ("exe","dll","sys","log","tmp","dat")
| comp count() as file_ops, values(action_file_extension) as extensions by actor_process_image_name, host_name
| filter file_ops > 50
| sort desc file_ops
\`\`\`

### 9. Failed authentication brute force
\`\`\`
dataset = auth_events
| filter auth_outcome = "FAILED"
| comp count() as fail_count by user_name, src_ip
| filter fail_count > 20
| sort desc fail_count
\`\`\`

### 10. Unsigned processes making network connections
\`\`\`
dataset = xdr_data
| filter event_type = "NETWORK"
| filter actor_process_signature_status = "UNSIGNED"
| filter action_remote_ip not in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")
| fields event_timestamp, host_name, user_name, actor_process_image_name, actor_process_image_path, action_remote_ip, action_remote_port
| sort desc event_timestamp
\`\`\`

---

## MITRE ATT&CK MAPPING (common tactics → XQL hunting angles)

- **T1059 - Command Scripting**: Filter for powershell, cmd, wscript, cscript in process events
- **T1003 - OS Credential Dumping**: Look for LSASS access, procdump, mimikatz patterns
- **T1071 - C2 Communications**: Outbound to unusual ports/IPs, high frequency connections
- **T1021 - Lateral Movement**: SMB/RDP/WMI from non-admin processes
- **T1547 - Boot/Logon Autostart**: Registry Run keys, scheduled tasks
- **T1055 - Process Injection**: Unusual parent-child, cross-process memory access
- **T1027 - Obfuscation**: Encoded commands, long command lines
- **T1486 - Data Encryption (Ransomware)**: Mass file changes, shadow copy deletion

---

## OUTPUT FORMAT INSTRUCTIONS FOR AI

When translating natural language to XQL:
1. Always start with the appropriate dataset
2. Use filter stages to narrow data before aggregation (performance)
3. Add a comment line // explaining each major stage
4. End with limit if not using aggregation (default 200)
5. Include relevant security fields that operators need
6. Suggest alternative approaches if applicable
7. Note any assumptions made about field names
`;

export const STARTER_PROMPTS = [
  "Show me all PowerShell processes with encoded commands in the last 24 hours",
  "Find processes spawned by Office applications that look suspicious",
  "Hunt for potential C2 beaconing — repeated outbound connections to the same external IP",
  "Show me all failed login attempts grouped by user and source IP",
  "Find unsigned executables making outbound network connections",
  "Look for potential LSASS credential dumping activity",
  "Detect processes creating files with unusual extensions at scale — possible ransomware",
  "Show me DNS queries with unusually long domain names",
  "Find lateral movement indicators — admin share connections from unexpected processes",
  "Hunt for registry persistence mechanisms added in the last 7 days",
];

export interface HuntIdea {
  text: string;
  tactic: string;
  techniqueId: string;
  techniqueName: string;
  url: string;
}

export const HUNT_IDEAS: HuntIdea[] = [
  // ── Execution ──────────────────────────────────────────────────────────────
  { text: "PowerShell downloading files with Invoke-WebRequest or WebClient",
    tactic: "Execution", techniqueId: "T1059.001", techniqueName: "PowerShell",
    url: "https://attack.mitre.org/techniques/T1059/001/" },
  { text: "cmd.exe spawned directly by a browser process",
    tactic: "Execution", techniqueId: "T1059.003", techniqueName: "Windows Command Shell",
    url: "https://attack.mitre.org/techniques/T1059/003/" },
  { text: "mshta.exe executing a remote script URL",
    tactic: "Execution", techniqueId: "T1218.005", techniqueName: "Mshta",
    url: "https://attack.mitre.org/techniques/T1218/005/" },
  { text: "regsvr32.exe loading a DLL from a network path — Squiblydoo",
    tactic: "Defense Evasion", techniqueId: "T1218.010", techniqueName: "Regsvr32",
    url: "https://attack.mitre.org/techniques/T1218/010/" },
  { text: "certutil.exe used to decode or download a payload",
    tactic: "Defense Evasion", techniqueId: "T1140", techniqueName: "Deobfuscate/Decode Files",
    url: "https://attack.mitre.org/techniques/T1140/" },
  { text: "wmic.exe spawning unexpected child processes",
    tactic: "Execution", techniqueId: "T1047", techniqueName: "Windows Management Instrumentation",
    url: "https://attack.mitre.org/techniques/T1047/" },
  { text: "rundll32.exe calling an uncommon or suspicious export",
    tactic: "Defense Evasion", techniqueId: "T1218.011", techniqueName: "Rundll32",
    url: "https://attack.mitre.org/techniques/T1218/011/" },
  { text: "executables launched from user temp or download directories",
    tactic: "Defense Evasion", techniqueId: "T1036.005", techniqueName: "Match Legitimate Name or Location",
    url: "https://attack.mitre.org/techniques/T1036/005/" },
  { text: "scripts running from %APPDATA% or %LOCALAPPDATA%",
    tactic: "Execution", techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter",
    url: "https://attack.mitre.org/techniques/T1059/" },
  { text: "double-extension files — invoice.pdf.exe or report.docx.scr",
    tactic: "Defense Evasion", techniqueId: "T1036.007", techniqueName: "Double File Extension",
    url: "https://attack.mitre.org/techniques/T1036/007/" },

  // ── Credential Access ──────────────────────────────────────────────────────
  { text: "ntdsutil.exe accessing the Active Directory database",
    tactic: "Credential Access", techniqueId: "T1003.003", techniqueName: "NTDS",
    url: "https://attack.mitre.org/techniques/T1003/003/" },
  { text: "vssadmin deleting or resizing shadow copies — ransomware precursor",
    tactic: "Impact", techniqueId: "T1490", techniqueName: "Inhibit System Recovery",
    url: "https://attack.mitre.org/techniques/T1490/" },
  { text: "SAM registry hive read by a non-system process",
    tactic: "Credential Access", techniqueId: "T1003.002", techniqueName: "Security Account Manager",
    url: "https://attack.mitre.org/techniques/T1003/002/" },
  { text: "LSASS memory access from an unsigned or unexpected process",
    tactic: "Credential Access", techniqueId: "T1003.001", techniqueName: "LSASS Memory",
    url: "https://attack.mitre.org/techniques/T1003/001/" },
  { text: "procdump.exe or comsvcs.dll MiniDump targeting lsass",
    tactic: "Credential Access", techniqueId: "T1003.001", techniqueName: "LSASS Memory",
    url: "https://attack.mitre.org/techniques/T1003/001/" },
  { text: "secretsdump or impacket patterns in process command lines",
    tactic: "Credential Access", techniqueId: "T1003", techniqueName: "OS Credential Dumping",
    url: "https://attack.mitre.org/techniques/T1003/" },
  { text: "Kerberoasting — unusual LDAP queries for service principal names",
    tactic: "Credential Access", techniqueId: "T1558.003", techniqueName: "Kerberoasting",
    url: "https://attack.mitre.org/techniques/T1558/003/" },
  { text: "DCSync — AD replication requests originating from a non-DC",
    tactic: "Credential Access", techniqueId: "T1003.006", techniqueName: "DCSync",
    url: "https://attack.mitre.org/techniques/T1003/006/" },
  { text: "LaZagne or credential harvesting tool name in process list",
    tactic: "Credential Access", techniqueId: "T1555", techniqueName: "Credentials from Password Stores",
    url: "https://attack.mitre.org/techniques/T1555/" },
  { text: "Windows Credential Editor or wce.exe execution",
    tactic: "Credential Access", techniqueId: "T1003.001", techniqueName: "LSASS Memory",
    url: "https://attack.mitre.org/techniques/T1003/001/" },

  // ── Lateral Movement ───────────────────────────────────────────────────────
  { text: "PsExec or similar remote execution tool activity",
    tactic: "Lateral Movement", techniqueId: "T1570", techniqueName: "Lateral Tool Transfer",
    url: "https://attack.mitre.org/techniques/T1570/" },
  { text: "WMI remote process creation across multiple endpoints",
    tactic: "Lateral Movement", techniqueId: "T1021.006", techniqueName: "Windows Remote Management",
    url: "https://attack.mitre.org/techniques/T1021/006/" },
  { text: "RDP connections between workstations — not server to client",
    tactic: "Lateral Movement", techniqueId: "T1021.001", techniqueName: "Remote Desktop Protocol",
    url: "https://attack.mitre.org/techniques/T1021/001/" },
  { text: "DCOM lateral movement via MMC20 or ShellBrowserWindow",
    tactic: "Lateral Movement", techniqueId: "T1021.003", techniqueName: "Distributed Component Object Model",
    url: "https://attack.mitre.org/techniques/T1021/003/" },
  { text: "net use commands mounting administrative shares",
    tactic: "Lateral Movement", techniqueId: "T1021.002", techniqueName: "SMB/Windows Admin Shares",
    url: "https://attack.mitre.org/techniques/T1021/002/" },
  { text: "schtasks /s creating scheduled tasks on remote hosts",
    tactic: "Lateral Movement", techniqueId: "T1053.005", techniqueName: "Scheduled Task",
    url: "https://attack.mitre.org/techniques/T1053/005/" },
  { text: "sc.exe installing a service remotely",
    tactic: "Lateral Movement", techniqueId: "T1569.002", techniqueName: "Service Execution",
    url: "https://attack.mitre.org/techniques/T1569/002/" },
  { text: "unexpected SSH lateral movement from internal Windows hosts",
    tactic: "Lateral Movement", techniqueId: "T1021.004", techniqueName: "SSH",
    url: "https://attack.mitre.org/techniques/T1021/004/" },
  { text: "WinRM connections from non-privileged workstations",
    tactic: "Lateral Movement", techniqueId: "T1021.006", techniqueName: "Windows Remote Management",
    url: "https://attack.mitre.org/techniques/T1021/006/" },
  { text: "NTLM authentication with mismatched source hostname — pass-the-hash",
    tactic: "Lateral Movement", techniqueId: "T1550.002", techniqueName: "Pass the Hash",
    url: "https://attack.mitre.org/techniques/T1550/002/" },

  // ── Persistence ────────────────────────────────────────────────────────────
  { text: "new Windows services installed outside of known patch windows",
    tactic: "Persistence", techniqueId: "T1543.003", techniqueName: "Windows Service",
    url: "https://attack.mitre.org/techniques/T1543/003/" },
  { text: "unsigned DLLs appearing in System32 — DLL hijacking",
    tactic: "Persistence", techniqueId: "T1574.001", techniqueName: "DLL Search Order Hijacking",
    url: "https://attack.mitre.org/techniques/T1574/001/" },
  { text: "COM object hijacking entries written to HKCU hive",
    tactic: "Persistence", techniqueId: "T1546.015", techniqueName: "Component Object Model Hijacking",
    url: "https://attack.mitre.org/techniques/T1546/015/" },
  { text: "startup folder file drops by non-installer processes",
    tactic: "Persistence", techniqueId: "T1547.001", techniqueName: "Registry Run Keys / Startup Folder",
    url: "https://attack.mitre.org/techniques/T1547/001/" },
  { text: "WMI event subscriptions created or modified",
    tactic: "Persistence", techniqueId: "T1546.003", techniqueName: "Windows Management Instrumentation Event Subscription",
    url: "https://attack.mitre.org/techniques/T1546/003/" },
  { text: "AppInit_DLLs registry key written by a user process",
    tactic: "Persistence", techniqueId: "T1546.010", techniqueName: "AppInit DLLs",
    url: "https://attack.mitre.org/techniques/T1546/010/" },
  { text: "screensaver executable path changed in user registry",
    tactic: "Persistence", techniqueId: "T1546.002", techniqueName: "Screensaver",
    url: "https://attack.mitre.org/techniques/T1546/002/" },
  { text: "LSA security package or notification package modifications",
    tactic: "Persistence", techniqueId: "T1547.005", techniqueName: "Security Support Provider",
    url: "https://attack.mitre.org/techniques/T1547/005/" },
  { text: "Office template file modifications — macro persistence",
    tactic: "Persistence", techniqueId: "T1137.001", techniqueName: "Office Template Macros",
    url: "https://attack.mitre.org/techniques/T1137/001/" },
  { text: "BITS jobs created by unexpected processes",
    tactic: "Persistence", techniqueId: "T1197", techniqueName: "BITS Jobs",
    url: "https://attack.mitre.org/techniques/T1197/" },

  // ── Discovery & Exfiltration ───────────────────────────────────────────────
  { text: "DNS TXT record queries — potential DNS tunneling or exfiltration",
    tactic: "Exfiltration", techniqueId: "T1048.003", techniqueName: "Exfiltration Over Unencrypted Protocol",
    url: "https://attack.mitre.org/techniques/T1048/003/" },
  { text: "large outbound data transfer to a new external destination",
    tactic: "Exfiltration", techniqueId: "T1041", techniqueName: "Exfiltration Over C2 Channel",
    url: "https://attack.mitre.org/techniques/T1041/" },
  { text: "rclone or cloud sync tools running outside business hours",
    tactic: "Exfiltration", techniqueId: "T1567.002", techniqueName: "Exfiltration to Cloud Storage",
    url: "https://attack.mitre.org/techniques/T1567/002/" },
  { text: "adfind.exe Active Directory reconnaissance commands",
    tactic: "Discovery", techniqueId: "T1018", techniqueName: "Remote System Discovery",
    url: "https://attack.mitre.org/techniques/T1018/" },
  { text: "nltest.exe domain trust or DC enumeration",
    tactic: "Discovery", techniqueId: "T1482", techniqueName: "Domain Trust Discovery",
    url: "https://attack.mitre.org/techniques/T1482/" },
  { text: "net group domain admins enumeration from a workstation",
    tactic: "Discovery", techniqueId: "T1069.002", techniqueName: "Domain Groups",
    url: "https://attack.mitre.org/techniques/T1069/002/" },
  { text: "internal port scan or ping sweep from a user endpoint",
    tactic: "Discovery", techniqueId: "T1046", techniqueName: "Network Service Discovery",
    url: "https://attack.mitre.org/techniques/T1046/" },
  { text: "curl or wget downloading an executable to a temp path",
    tactic: "Command and Control", techniqueId: "T1105", techniqueName: "Ingress Tool Transfer",
    url: "https://attack.mitre.org/techniques/T1105/" },
  { text: "high-entropy command line arguments — obfuscation or encoding",
    tactic: "Defense Evasion", techniqueId: "T1027", techniqueName: "Obfuscated Files or Information",
    url: "https://attack.mitre.org/techniques/T1027/" },
  { text: "outbound connections on non-standard ports from Office applications",
    tactic: "Command and Control", techniqueId: "T1571", techniqueName: "Non-Standard Port",
    url: "https://attack.mitre.org/techniques/T1571/" },
];
