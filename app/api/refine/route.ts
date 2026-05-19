import Anthropic from "@anthropic-ai/sdk";
import { Platform } from "../../platformTypes";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const PLATFORM_NAMES: Record<Platform, string> = {
  xql: "Palo Alto Networks Cortex XDR/XSIAM — XQL",
  kql: "Microsoft Sentinel / Defender XDR — KQL",
  spl: "Splunk Enterprise/Cloud — SPL",
  cql: "CrowdStrike Falcon NG-SIEM — LogScale CQL",
};

export async function POST(req: Request) {
  const { originalQuery, userQuery, platform = "xql", issues, tenantSchemaContext } = await req.json();

  const platformName = PLATFORM_NAMES[platform as Platform];

  // Build a compact, specific list of what to fix
  const warningIssues = issues.filter((i: { severity: string }) =>
    i.severity === "WARNING" || i.severity === "ERROR"
  );

  const issueList = warningIssues
    .map((i: { severity: string; category: string; description: string }, idx: number) =>
      `${idx + 1}. [${i.severity}][${i.category}] ${i.description}`
    )
    .join("\n");

  const tenantNote = tenantSchemaContext
    ? `\nTenant schema context:\n${tenantSchemaContext}`
    : "";

  const systemPrompt = `You are an expert ${platformName} query engineer performing a targeted refinement pass.

You will be given:
1. The original hunt query
2. A list of specific WARNING and ERROR issues identified by the validator
3. The original user intent

Your job is to fix ONLY the identified issues — do not restructure, rewrite, or improve the query beyond what is listed. Preserve the operator's original logic and intent exactly. Make the minimum changes necessary to resolve each issue.

Output ONLY the corrected query in a code block labeled with the platform language (xql/kql/spl/cql). No explanation, no commentary, no tuning tips — just the corrected query.${tenantNote}`;

  const userMessage = `ORIGINAL QUERY:
\`\`\`${platform}
${originalQuery}
\`\`\`

ORIGINAL USER INTENT: ${userQuery}

ISSUES TO FIX:
${issueList}

Return ONLY the corrected query. Fix every listed issue. Change nothing else.`;

  const stream = await client.messages.stream({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1200,
    system: systemPrompt,
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
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Transfer-Encoding": "chunked",
    },
  });
}
