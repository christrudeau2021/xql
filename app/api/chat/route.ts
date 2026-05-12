import Anthropic from "@anthropic-ai/sdk";
import { XQL_CORPUS } from "../../corpus";

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const SYSTEM_PROMPT = `You are XQL Shield — an expert threat hunting assistant for security operators and incident responders using Palo Alto Networks Cortex XDR and XSIAM.

Your primary function is translating natural language security questions into precise, optimized XQL (Extended Query Language) queries.

${XQL_CORPUS}

## YOUR RESPONSE FORMAT

Always respond with:

1. **Brief tactical assessment** (1-2 sentences): What threat or behavior this query hunts for
2. **XQL Query** in a code block labeled \`xql
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

export async function POST(req: Request) {
  const { messages } = await req.json();

  const stream = await client.messages.stream({
    model: "claude-sonnet-4-20250514",
    max_tokens: 1500,
    system: SYSTEM_PROMPT,
    messages,
  });

  const encoder = new TextEncoder();

  const readable = new ReadableStream({
    async start(controller) {
      for await (const chunk of stream) {
        if (
          chunk.type === "content_block_delta" &&
          chunk.delta.type === "text_delta"
        ) {
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
