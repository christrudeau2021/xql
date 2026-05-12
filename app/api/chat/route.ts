import Anthropic from "@anthropic-ai/sdk";
import { XQL_CORPUS } from "../../corpus";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// ─── STAGE 1: GENERATOR ─────────────────────────────────────────────────────

const SYSTEM_PROMPT = `You are XQL Shield — an expert threat hunting assistant for security operators and incident responders using Palo Alto Networks Cortex XDR and XSIAM.

Your primary function is translating natural language security questions into precise, optimized XQL (Extended Query Language) queries.

${XQL_CORPUS}

## YOUR RESPONSE FORMAT

Always respond with:

1. **Brief tactical assessment** (1-2 sentences): What threat or behavior this query hunts for
2. **XQL Query** in a code block labeled \`\`\`xql
3. **Key fields to review** — what to look for in the results
4. **Tuning tips** — how to adjust the query for environment-specific needs (optional, keep brief)

## RESPONSE STYLE
- You are talking to security operators and threat hunters — use SOC/IR terminology
- Be direct and tactical, not verbose
- If a request is ambiguous, make a reasonable security assumption and state it
- Always add inline comments (//) to explain non-obvious query logic
- If multiple datasets could work, pick the best one and optionally mention the alternative
- For complex hunts, break into a primary query + a follow-on enrichment query

## CONVERSATIONAL BEHAVIOR
- Answer follow-up questions about the query you just generated
- Help tune or modify queries based on feedback ("narrow it to just Windows", "add a time filter", etc.)
- Explain XQL syntax concepts when asked
- Suggest related threat hunts after answering`;

// ─── STAGE 2: VALIDATOR ─────────────────────────────────────────────────────

const VALIDATOR_PROMPT = `You are a senior XQL syntax and logic validator for Palo Alto Networks Cortex XDR / XSIAM.

You will be given:
1. A user's natural language threat hunting request
2. An XQL query generated in response to that request

Your job is to validate the query and return ONLY a JSON object — no preamble, no markdown, no explanation outside the JSON.

## VALIDATION CRITERIA

**Syntax checks:**
- Dataset declaration is valid (dataset = <name>)
- Pipe stages are in correct order (filter before comp, etc.)
- All parentheses, brackets, and quotes are balanced
- Operators used correctly (=, !=, in, contains, ~=, is null, etc.)
- String values are quoted, numeric values are not
- Functions called with correct argument patterns

**Semantic checks:**
- Field names are plausible for the chosen dataset (flag if likely wrong)
- The query logically answers the user's question
- No contradictory filters
- Aggregation fields referenced in comp exist in prior pipeline stages
- Time filter syntax is correct if present

**Security logic checks:**
- The query targets the right dataset for the threat described
- Exclusions/inclusions make tactical sense
- Would likely produce actionable results vs. too broad or too narrow

## KNOWN VALID DATASETS
xdr_data, process_events, network_connections, file_events, registry_events, module_events,
auth_events, identity_analytics, directory_sync, firewall_events, network_story, dns_events,
url_events, cloud_audit_logs, cloud_asset_db, xdr_alerts, incidents

## RESPONSE FORMAT — Return ONLY this JSON, nothing else:

{
  "score": <integer 0-100>,
  "confidence": "<VERIFIED|LIKELY_VALID|REVIEW_ADVISED|FLAGGED>",
  "issues": [
    {
      "severity": "<ERROR|WARNING|INFO>",
      "category": "<SYNTAX|FIELD_NAME|LOGIC|DATASET|PERFORMANCE>",
      "description": "<concise technical description — one sentence>"
    }
  ],
  "corrections": "<If ERROR-level issues exist, provide the corrected XQL query here. Otherwise empty string.>",
  "summary": "<One sentence assessment for the operator — direct and tactical>"
}

Confidence levels:
- VERIFIED (90-100): No issues, syntactically correct and logically sound
- LIKELY_VALID (70-89): Minor warnings only, will likely work with possible tuning
- REVIEW_ADVISED (50-69): Warnings that could affect results — operator should review
- FLAGGED (0-49): Errors that will cause query failure or wrong results`;

// ─── HELPERS ────────────────────────────────────────────────────────────────

function extractXqlQueries(text: string): string[] {
  const matches: string[] = [];
  const regex = /```(?:xql)?\n?([\s\S]*?)```/g;
  let match;
  while ((match = regex.exec(text)) !== null) {
    const code = match[1].trim();
    if (code.includes("dataset") || code.includes("| filter") || code.includes("| comp")) {
      matches.push(code);
    }
  }
  return matches;
}

// ─── ROUTE HANDLER ──────────────────────────────────────────────────────────

export async function POST(req: Request) {
  const { messages } = await req.json();

  // ── STAGE 1: Generate ────────────────────────────────────────────────────
  const generatedResponse = await client.messages.create({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1500,
    system: SYSTEM_PROMPT,
    messages,
  });

  const generatedText =
    generatedResponse.content[0].type === "text"
      ? generatedResponse.content[0].text
      : "";

  // ── STAGE 2: Validate if an XQL query is present ─────────────────────────
  const queries = extractXqlQueries(generatedText);
  const userQuestion = messages[messages.length - 1]?.content || "";
  let validationMeta = null;
  let finalText = generatedText;

  if (queries.length > 0) {
    try {
      const validationResponse = await client.messages.create({
        model: "claude-sonnet-4-20250514",
        max_tokens: 800,
        system: VALIDATOR_PROMPT,
        messages: [
          {
            role: "user",
            content: `USER REQUEST: ${userQuestion}\n\nGENERATED XQL:\n\`\`\`xql\n${queries[0]}\n\`\`\``,
          },
        ],
      });

      const validationText =
        validationResponse.content[0].type === "text"
          ? validationResponse.content[0].text
          : "{}";

      const cleanJson = validationText
        .replace(/```json\n?/g, "")
        .replace(/```\n?/g, "")
        .trim();

      const parsed = JSON.parse(cleanJson);

      validationMeta = {
        score: parsed.score,
        confidence: parsed.confidence,
        issues: parsed.issues || [],
        summary: parsed.summary || "",
        autoCorrected: false,
      };

      // Auto-correct if FLAGGED and corrections provided
      if (
        parsed.confidence === "FLAGGED" &&
        parsed.corrections?.trim().length > 0
      ) {
        finalText = generatedText.replace(
          /```(?:xql)?\n?[\s\S]*?```/,
          "```xql\n" + parsed.corrections.trim() + "\n```"
        );
        validationMeta.autoCorrected = true;
      }
    } catch {
      // Validation failed to parse — don't block response
      validationMeta = null;
    }
  }

  // ── STREAM response with validation prefix ────────────────────────────────
  const encoder = new TextEncoder();

  const readable = new ReadableStream({
    async start(controller) {
      // Send validation metadata as a parseable prefix
      if (validationMeta) {
        controller.enqueue(
          encoder.encode(
            `__VALIDATION__${JSON.stringify(validationMeta)}__END_VALIDATION__\n`
          )
        );
      }

      // Simulate streaming by chunking the pre-generated text
      const chunkSize = 24;
      for (let i = 0; i < finalText.length; i += chunkSize) {
        controller.enqueue(encoder.encode(finalText.slice(i, i + chunkSize)));
        await new Promise((r) => setTimeout(r, 6));
      }

      controller.close();
    },
  });

  return new Response(readable, {
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Transfer-Encoding": "chunked",
    },
  });
}
