import Anthropic from "@anthropic-ai/sdk";
import { XQL_CORPUS } from "../../corpus";
import { KQL_CORPUS, SPL_CORPUS, CQL_CORPUS, PLATFORM_KNOWN_DATASETS } from "../../platformCorpus";
import { Platform } from "../../platformTypes";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ─── PER-PLATFORM CORPUS ─────────────────────────────────────────────────────

const PLATFORM_CORPUS: Record<Platform, string> = {
  xql: XQL_CORPUS,
  kql: KQL_CORPUS,
  spl: SPL_CORPUS,
  cql: CQL_CORPUS,
};

const PLATFORM_NAMES: Record<Platform, string> = {
  xql: "Palo Alto Networks Cortex XDR/XSIAM — XQL",
  kql: "Microsoft Sentinel / Defender XDR — KQL (Kusto Query Language)",
  spl: "Splunk Enterprise/Cloud — SPL (Search Processing Language)",
  cql: "CrowdStrike Falcon NG-SIEM — LogScale Query Language (CQL)",
};

// ─── SYSTEM PROMPT BUILDER ────────────────────────────────────────────────────

function buildSystemPrompt(platform: Platform, tenantBlock: string): string {
  const platformName = PLATFORM_NAMES[platform];
  const corpus = PLATFORM_CORPUS[platform];

  return `You are AXIOM — an expert cross-platform threat hunting assistant for security operators, incident responders, and detection engineers.

The operator has selected: **${platformName}**

You MUST generate all queries in the correct syntax for this platform. Do not output queries in any other language.

${corpus}

## YOUR RESPONSE FORMAT

Always respond with:

1. **Brief tactical assessment** (1-2 sentences): What threat or behavior this query hunts for
2. **Query** in a code block labeled with the platform language (xql/kql/spl/cql)
3. **Key fields to review** — what to look for in the results
4. **Tuning tips** — how to adjust for environment-specific needs (optional, brief)

## RESPONSE STYLE
- You are talking to security operators and threat hunters — use SOC/IR terminology
- Be direct and tactical, not verbose
- If a request is ambiguous, make a reasonable security assumption and state it
- Always add inline comments explaining non-obvious query logic
- If multiple approaches work, pick the best one and mention the alternative
- For complex hunts, provide a primary query + follow-on enrichment query

## PLATFORM NOTES
${platform === "xql" ? "- Use pipe-based XQL syntax with dataset = at the start\n- Use filter, fields, comp, alter, sort, limit stages" : ""}
${platform === "kql" ? "- Use KQL pipe syntax starting with table name\n- Use where, project, extend, summarize, order by, take\n- Prefer DeviceProcessEvents, DeviceNetworkEvents for endpoint hunting" : ""}
${platform === "spl" ? "- Start with index= and sourcetype= where known\n- Use | stats for aggregation, | table for field selection\n- Include relevant EventCode filters for Windows events" : ""}
${platform === "cql" ? "- Start with #event_simpleName= filter\n- Use | groupBy() for aggregation, | limit() for results\n- Use field=value syntax before pipes for initial filtering" : ""}
${tenantBlock}`;
}

// ─── VALIDATOR PROMPT BUILDER ─────────────────────────────────────────────────

function buildValidatorPrompt(platform: Platform, tenantBlock: string): string {
  const knownDatasets = PLATFORM_KNOWN_DATASETS[platform].join(", ");
  const platformName = PLATFORM_NAMES[platform];

  return `You are a senior query validator for ${platformName}.

Validate the provided query and return ONLY a JSON object — no preamble, no markdown.

## VALIDATION CRITERIA

**Syntax checks:**
- Query uses correct syntax for ${platform.toUpperCase()}
- Operators, functions, and keywords are valid for this platform
- Strings properly quoted, numeric values unquoted
- Pipeline structure is valid

**Semantic checks:**
- Field names are plausible for the chosen dataset/table
- Query logically answers the user's question
- No contradictory filters
- Time filter syntax is correct

**Security logic checks:**
- Query targets the right dataset/table for the threat described
- Would likely produce actionable results

## KNOWN VALID DATASETS/TABLES FOR ${platform.toUpperCase()}:
${knownDatasets}

${tenantBlock ? `## TENANT SCHEMA (treat these as valid):\n${tenantBlock}` : `NOTE: No tenant schema loaded. Flag unknown datasets as INFO only.`}

## RESPONSE FORMAT — ONLY this JSON:
{
  "score": <0-100>,
  "confidence": "<VERIFIED|LIKELY_VALID|REVIEW_ADVISED|FLAGGED>",
  "issues": [{"severity": "<ERROR|WARNING|INFO>", "category": "<SYNTAX|FIELD_NAME|LOGIC|DATASET|PERFORMANCE>", "description": "<one sentence>"}],
  "corrections": "<corrected query if FLAGGED, else empty string>",
  "summary": "<one sentence operator-facing assessment>"
}`;
}

// ─── HELPERS ─────────────────────────────────────────────────────────────────

function extractQueries(text: string, platform: Platform): string[] {
  const matches: string[] = [];
  const regex = /```(?:xql|kql|spl|cql)?\n?([\s\S]*?)```/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const code = match[1].trim();
    const isQuery =
      platform === "xql" ? (code.includes("dataset") || code.includes("| filter")) :
      platform === "kql" ? (code.includes("|") || code.includes("where")) :
      platform === "spl" ? (code.includes("index=") || code.includes("| stats") || code.includes("| search")) :
      platform === "cql" ? (code.includes("#event_simpleName") || code.includes("| groupBy") || code.includes("| limit")) :
      false;
    if (isQuery) matches.push(code);
  }
  return matches;
}

// ─── ROUTE HANDLER ───────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const { messages, tenantSchemaContext, platform = "xql" } = await req.json();
  const activePlatform = platform as Platform;

  const tenantBlock = tenantSchemaContext
    ? `\n\n---\nTENANT SCHEMA (imported this session — in memory only):\n${tenantSchemaContext}\n---`
    : "";

  const activeSystemPrompt = buildSystemPrompt(activePlatform, tenantBlock);
  const activeValidatorPrompt = buildValidatorPrompt(activePlatform, tenantBlock);

  // ── STAGE 1: Generate ────────────────────────────────────────────────────────
  const generatedResponse = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1800,
    system: activeSystemPrompt,
    messages,
  });

  const generatedText =
    generatedResponse.content[0].type === "text"
      ? generatedResponse.content[0].text : "";

  // ── STAGE 2: Validate ────────────────────────────────────────────────────────
  const queries = extractQueries(generatedText, activePlatform);
  const userQuestion = messages[messages.length - 1]?.content || "";
  let validationMeta = null;
  let finalText = generatedText;

  if (queries.length > 0) {
    try {
      const validationResponse = await client.messages.create({
        model: "claude-sonnet-4-20250514",
        max_tokens: 800,
        system: activeValidatorPrompt,
        messages: [{
          role: "user",
          content: `USER REQUEST: ${userQuestion}\n\nGENERATED QUERY (${activePlatform.toUpperCase()}):\n\`\`\`${activePlatform}\n${queries[0]}\n\`\`\``,
        }],
      });

      const validationText = validationResponse.content[0].type === "text"
        ? validationResponse.content[0].text : "{}";

      const cleanJson = validationText.replace(/```json\n?/g, "").replace(/```\n?/g, "").trim();
      const parsed = JSON.parse(cleanJson);

      validationMeta = {
        score: parsed.score,
        confidence: parsed.confidence,
        issues: parsed.issues || [],
        summary: parsed.summary || "",
        autoCorrected: false,
        platform: activePlatform,
      };

      if (parsed.confidence === "FLAGGED" && parsed.corrections?.trim().length > 0) {
        finalText = generatedText.replace(
          /```(?:xql|kql|spl|cql)?\n?[\s\S]*?```/,
          "```" + activePlatform + "\n" + parsed.corrections.trim() + "\n```"
        );
        validationMeta.autoCorrected = true;
      }
    } catch { validationMeta = null; }
  }

  // ── STREAM with validation prefix ────────────────────────────────────────────
  const encoder = new TextEncoder();
  const readable = new ReadableStream({
    async start(controller) {
      if (validationMeta) {
        controller.enqueue(encoder.encode(
          `__VALIDATION__${JSON.stringify(validationMeta)}__END_VALIDATION__\n`
        ));
      }
      const chunkSize = 24;
      for (let i = 0; i < finalText.length; i += chunkSize) {
        controller.enqueue(encoder.encode(finalText.slice(i, i + chunkSize)));
        await new Promise((r) => setTimeout(r, 6));
      }
      controller.close();
    },
  });

  return new Response(readable, {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Transfer-Encoding": "chunked" },
  });
}
