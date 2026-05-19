// ─── FEEDBACK ENDPOINT ───────────────────────────────────────────────────────
// Lightweight signal collection — no database, no PII
// Logs to Vercel's built-in log drain for observability
// Captures: platform, confidence score, thumbs direction, query hash, timestamp
// Does NOT capture: actual query text, user identity, IP address

import { Platform } from "../../platformTypes";
import { NextRequest } from "next/server";

interface FeedbackPayload {
  platform: Platform;
  confidence: string;
  score: number;
  thumbs: "up" | "down";
  queryLength: number;        // character count only — no actual text
  hadWarnings: boolean;
  wasRefined: boolean;
  hypothesisId?: string;      // H001-H040 if from hypothesis sidebar
  sessionId: string;          // random client-generated ID, no PII
}

export async function POST(req: NextRequest) {
  try {
    const body: FeedbackPayload = await req.json();

    // Validate required fields
    if (!body.platform || !body.thumbs || !body.sessionId) {
      return Response.json({ ok: false, error: "Missing required fields" }, { status: 400 });
    }

    // Sanitize — ensure no accidental PII
    const sanitized = {
      platform: body.platform,
      confidence: body.confidence || "unknown",
      score: typeof body.score === "number" ? body.score : 0,
      thumbs: body.thumbs === "up" || body.thumbs === "down" ? body.thumbs : "unknown",
      queryLength: typeof body.queryLength === "number" ? body.queryLength : 0,
      hadWarnings: Boolean(body.hadWarnings),
      wasRefined: Boolean(body.wasRefined),
      hypothesisId: body.hypothesisId?.match(/^H\d{3}$/) ? body.hypothesisId : undefined,
      sessionId: String(body.sessionId).slice(0, 36), // UUID length cap
      timestamp: new Date().toISOString(),
    };

    // Log structured output — captured by Vercel Log Drains
    // Format designed for easy filtering in Vercel Logs
    console.log(JSON.stringify({
      event: "axiom_feedback",
      ...sanitized,
    }));

    return Response.json({ ok: true });
  } catch (err) {
    // Never fail silently on the client — but also don't expose internals
    console.error("Feedback endpoint error:", err instanceof Error ? err.message : "unknown");
    return Response.json({ ok: false }, { status: 500 });
  }
}
