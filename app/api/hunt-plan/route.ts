import Anthropic from "@anthropic-ai/sdk";
import { Platform } from "../../platformTypes";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const PLATFORM_NAMES: Record<Platform, string> = {
  xql: "Palo Alto Networks Cortex XDR/XSIAM — XQL",
  kql: "Microsoft Sentinel / Defender XDR — KQL",
  spl: "Splunk Enterprise/Cloud — SPL",
  cql: "CrowdStrike Falcon NG-SIEM — LogScale CQL",
};

const HUNT_PLAN_PROMPT = `You are a senior threat hunting methodologist and SOC analyst coach with deep expertise in structured threat hunting using the PEAK methodology (Prepare, Execute, Act with Knowledge).

Produce a complete hypothesis-based hunt plan in markdown. Use this exact structure:

---

# Hunt Plan: [Short descriptive title]

**Platform:** [platform name]
**Classification:** Threat Hunt
**Methodology:** PEAK
**ATT&CK Technique:** [techniqueId] — [techniqueName] ([tactic])
**ATT&CK Reference:** [url]
**Hunt ID:** HUNT-[YYYYMMDD]-[TECHNIQUE_ID]
**Priority:** [CRITICAL/HIGH/MEDIUM]
**Status:** Open

---

## Hypothesis

> [Single precise falsifiable statement: "I hypothesize that [actor/malware] is [action] on [scope] using [mechanism], which would be observable as [artifact] in [data source]."]

---

## Hunt Scope

| Parameter | Value |
|-----------|-------|
| **Platform** | [full platform name] |
| **Time Window** | Recommended: last 30 days |
| **Asset Scope** | [all endpoints / Windows / cloud / etc] |
| **Data Sources** | [specific tables/datasets/indexes being queried] |
| **Priority** | [CRITICAL/HIGH/MEDIUM] |

---

## Baseline — What Normal Looks Like

- [3-4 bullet points describing legitimate baseline activity for this behavior]
- [Include process names, frequency, parent processes that are benign]

## Environmental Assumptions

- [2-3 assumptions the query makes about the environment]

---

## Detection Query

\`\`\`[platform_code_label]
[insert the provided query verbatim]
\`\`\`

**Query logic:** [2-3 sentences explaining what it detects and why]

---

## True Positive Indicators

Escalate immediately if results show:
- [4-6 specific, concrete indicators — process names, paths, argument patterns]

**Confidence factors that raise TP likelihood:**
- [3-4 contextual factors]

---

## False Positive Analysis

| Scenario | Why It Triggers | How to Distinguish |
|----------|----------------|-------------------|
| [FP scenario 1] | [reason] | [distinguishing factor] |
| [FP scenario 2] | [reason] | [distinguishing factor] |
| [FP scenario 3] | [reason] | [distinguishing factor] |

**Recommended exclusions:**
\`\`\`[platform_code_label]
// Tuning filters to reduce noise:
[1-2 specific filter suggestions]
\`\`\`

---

## Investigation Runbook

1. **Triage** — [First check: is this process/connection expected on this host?]
2. **Scope** — [How to determine if isolated or widespread]
3. **Timeline** — [What to look before and after the event]
4. **Enrich** — [Additional queries or data sources to pull]
5. **Validate** — [Specific check to confirm TP vs FP]

**Follow-on enrichment query:**
\`\`\`[platform_code_label]
[Platform-appropriate enrichment query for the specific hit]
\`\`\`

---

## Escalation Criteria

**Escalate to IR if:**
- [3-4 specific conditions warranting escalation]

**Monitor and log if:**
- [2-3 conditions for watch-and-wait]

**Close as false positive if:**
- [2-3 clear FP disposition criteria]

---

## Hunt Record

\`\`\`
Hunt ID:         HUNT-[YYYYMMDD]-[TECHNIQUE_ID]
Platform:        [platform]
Analyst:         ___________________
Date Started:    ___________________
Date Closed:     ___________________
Findings:        [ ] No findings  [ ] FP  [ ] TP escalated
Hosts Reviewed:  ___________________
Notes:
_______________________________________________
Disposition:     ___________________
\`\`\`

---

## Related Hunts

[3 related ATT&CK techniques worth co-hunting — include T-numbers and one-line descriptions]

---
*AXIOM · PEAK Methodology · ATT&CK-aligned*

---
STYLE: Write for experienced operators — specific, actionable, no generic filler. Use real process names, real paths, real field names throughout.`;

export async function POST(req: Request) {
  const { userQuery, xqlQuery, attackRef, tenantSchemaContext, platform = "xql" } = await req.json();
  const activePlatform = platform as Platform;
  const platformName = PLATFORM_NAMES[activePlatform];

  const codeLabel = activePlatform;

  const tenantNote = tenantSchemaContext
    ? `\nTENANT CONTEXT: Operator has imported custom schema. Reference their actual dataset/table names.\n${tenantSchemaContext}`
    : "";

  const userMessage = `Generate a complete hypothesis-based hunt plan for the following:

**Platform:** ${platformName}
**Code label for queries:** ${codeLabel}
**Operator's hunt query:** ${userQuery}

**Generated ${activePlatform.toUpperCase()} Query:**
\`\`\`${codeLabel}
${xqlQuery}
\`\`\`

${attackRef ? `**ATT&CK Mapping:**
- Technique: ${attackRef.techniqueId} — ${attackRef.techniqueName}
- Tactic: ${attackRef.tactic}
- Reference: ${attackRef.url}` : "**ATT&CK Mapping:** Infer the most relevant technique from context."}

${tenantNote}

Use [platform_code_label] = "${codeLabel}" for all code blocks. Make every section specific to this exact hunt. No generic filler.`;

  const stream = await client.messages.stream({
    model: "claude-sonnet-4-20250514",
    max_tokens: 3500,
    system: HUNT_PLAN_PROMPT,
    messages: [{ role: "user", content: userMessage }],
  });

  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    async start(controller) {
      for await (const chunk of stream) {
        if (chunk.type === "content_block_delta" && chunk.delta.type === "text_delta") {
          controller.enqueue(encoder.encode(chunk.delta.text));
        }
      }
      controller.close();
    },
  });

  return new Response(readable, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Transfer-Encoding": "chunked" },
  });
}
