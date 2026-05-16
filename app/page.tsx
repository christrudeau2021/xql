"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { STARTER_PROMPTS, HUNT_IDEAS, HuntIdea } from "./corpus";
import { parseTenantSchema, schemaToPromptContext, TenantSchema, DISCOVERY_QUERIES as DQ } from "./schemaParser";

// ─── TYPES ───────────────────────────────────────────────────────────────────

interface ValidationIssue {
  severity: "ERROR" | "WARNING" | "INFO";
  category: string;
  description: string;
}

interface ValidationResult {
  score: number;
  confidence: "VERIFIED" | "LIKELY_VALID" | "REVIEW_ADVISED" | "FLAGGED";
  issues: ValidationIssue[];
  summary: string;
  autoCorrected: boolean;
}

interface AttackRef {
  techniqueId: string;
  techniqueName: string;
  tactic: string;
  url: string;
}

interface Message {
  role: "user" | "assistant";
  content: string;
  streaming?: boolean;
  validation?: ValidationResult | null;
  attack?: AttackRef | null;
  xqlQuery?: string | null;     // extracted XQL for hunt plan generation
  userQuery?: string | null;    // original user question
}

// ─── VALIDATION BADGE ────────────────────────────────────────────────────────

function ValidationBadge({ v }: { v: ValidationResult }) {
  const [expanded, setExpanded] = useState(false);
  const config = {
    VERIFIED:       { color: "#00ff9d", bg: "rgba(0,255,157,0.08)",  border: "rgba(0,255,157,0.3)",  label: "VERIFIED",        icon: "✓" },
    LIKELY_VALID:   { color: "#00c8ff", bg: "rgba(0,200,255,0.08)",  border: "rgba(0,200,255,0.3)",  label: "LIKELY VALID",    icon: "◈" },
    REVIEW_ADVISED: { color: "#ffd60a", bg: "rgba(255,214,10,0.08)", border: "rgba(255,214,10,0.3)", label: "REVIEW ADVISED",  icon: "⚠" },
    FLAGGED:        { color: "#ff2d55", bg: "rgba(255,45,85,0.08)",  border: "rgba(255,45,85,0.3)",  label: "FLAGGED",         icon: "✗" },
  }[v.confidence];
  const sevColor = { ERROR: "#ff2d55", WARNING: "#ffd60a", INFO: "#00c8ff" };

  return (
    <div style={{ marginTop: "10px", border: `1px solid ${config.border}`, background: config.bg, borderRadius: "3px", overflow: "hidden", fontFamily: "var(--font-mono)" }}>
      <div onClick={() => v.issues.length > 0 && setExpanded(!expanded)} style={{ display: "flex", alignItems: "center", gap: "10px", padding: "7px 12px", cursor: v.issues.length > 0 ? "pointer" : "default" }}>
        <div style={{ width: "32px", height: "32px", position: "relative", flexShrink: 0 }}>
          <svg viewBox="0 0 32 32" style={{ width: "100%", height: "100%", transform: "rotate(-90deg)" }}>
            <circle cx="16" cy="16" r="13" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="3"/>
            <circle cx="16" cy="16" r="13" fill="none" stroke={config.color} strokeWidth="3" strokeDasharray={`${(v.score/100)*81.7} 81.7`} strokeLinecap="round"/>
          </svg>
          <div style={{ position: "absolute", inset: 0, display: "flex", alignItems: "center", justifyContent: "center", fontSize: "9px", color: config.color, fontWeight: "bold" }}>{v.score}</div>
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "2px" }}>
            <span style={{ color: config.color, fontSize: "11px", letterSpacing: "0.12em", fontWeight: "bold" }}>{config.icon} {config.label}</span>
            {v.autoCorrected && <span style={{ fontSize: "9px", color: "#ffd60a", border: "1px solid rgba(255,214,10,0.4)", padding: "1px 5px", letterSpacing: "0.1em" }}>AUTO-CORRECTED</span>}
          </div>
          <div style={{ fontSize: "10px", color: "var(--text-secondary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{v.summary}</div>
        </div>
        {v.issues.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
            <div style={{ display: "flex", gap: "4px" }}>
              {(["ERROR","WARNING","INFO"] as const).map(sev => {
                const count = v.issues.filter(i => i.severity === sev).length;
                if (!count) return null;
                return <span key={sev} style={{ fontSize: "9px", padding: "1px 5px", color: sevColor[sev], border: `1px solid ${sevColor[sev]}44`, letterSpacing: "0.08em" }}>{count} {sev}</span>;
              })}
            </div>
            <span style={{ color: "var(--text-dim)", fontSize: "10px" }}>{expanded ? "▲" : "▼"}</span>
          </div>
        )}
      </div>
      {expanded && v.issues.length > 0 && (
        <div style={{ borderTop: `1px solid ${config.border}`, padding: "8px 12px", display: "flex", flexDirection: "column", gap: "5px" }}>
          {v.issues.map((issue, i) => (
            <div key={i} style={{ display: "flex", gap: "8px", fontSize: "10px", alignItems: "flex-start" }}>
              <span style={{ color: sevColor[issue.severity], border: `1px solid ${sevColor[issue.severity]}44`, padding: "0px 5px", letterSpacing: "0.08em", flexShrink: 0, marginTop: "1px" }}>{issue.severity}</span>
              <span style={{ color: "var(--text-dim)", letterSpacing: "0.06em" }}>[{issue.category}]</span>
              <span style={{ color: "var(--text-secondary)", lineHeight: "1.5" }}>{issue.description}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


// ─── ATT&CK BADGE ────────────────────────────────────────────────────────────

function AttackBadge({ a }: { a: AttackRef }) {
  return (
    <div className="attack-badge">
      <a
        href={a.url}
        target="_blank"
        rel="noopener noreferrer"
        className="attack-chip"
        title={"View " + a.techniqueId + " on MITRE ATT&CK"}
      >
        <span className="attack-chip-tactic">{a.tactic}</span>
        <span>{a.techniqueId}</span>
        <span style={{ opacity: 0.8 }}>·</span>
        <span>{a.techniqueName}</span>
        <span style={{ fontSize: "8px", opacity: 0.5, marginLeft: "2px" }}>↗</span>
      </a>
    </div>
  );
}


// ─── HUNT PLAN MODAL ─────────────────────────────────────────────────────────

function extractXqlFromContent(text: string): string | null {
  const match = text.match(/```(?:xql)?\n?([\s\S]*?)```/);
  if (!match) return null;
  const code = match[1].trim();
  if (code.includes("dataset") || code.includes("| filter") || code.includes("| comp")) return code;
  return null;
}

function parseHuntPlanMarkdown(text: string): string {
  let html = text;
  const codeBlocks: string[] = [];

  html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, (_: string, lang: string, code: string) => {
    const idx = codeBlocks.length;
    const escaped = code.trim()
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
    codeBlocks.push(
      `<div class="hp-code-block"><div class="hp-code-header">` +
      `<span class="hp-code-lang">${lang || "xql"}</span>` +
      `<button class="hp-copy-btn" onclick="copyHpCode(this)">&gt; COPY</button></div>` +
      `<pre><code>${escaped}</code></pre></div>`
    );
    return `__HPCODE_${idx}__`;
  });

  html = html.replace(/^> (.+)$/gm, "<blockquote>$1</blockquote>");
  html = html.replace(/^# (.+)$/gm, "<h1>$1</h1>");
  html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  html = html.replace(/^### (.+)$/gm, '<h3 style="font-family:var(--font-mono);font-size:11px;color:var(--accent-cyan);letter-spacing:0.1em;text-transform:uppercase;margin:14px 0 6px;">$1</h3>');
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/^---$/gm, "<hr/>");

  // Tables
  html = html.replace(/^\|(.+)\|$/gm, (line: string) => {
    if (/^\|[-| :]+\|$/.test(line)) return "__TABLE_SEP__";
    const cells = line.slice(1, -1).split("|").map((c: string) => c.trim());
    return "__TABLE_ROW__" + cells.join("__CELL__");
  });

  const tableLines = html.split("\n");
  let inTable = false;
  let isHeader = false;
  const processedLines: string[] = [];
  for (let i = 0; i < tableLines.length; i++) {
    const line = tableLines[i];
    if (line.startsWith("__TABLE_ROW__")) {
      const cells = line.replace("__TABLE_ROW__", "").split("__CELL__");
      if (!inTable) { processedLines.push("<table>"); inTable = true; isHeader = true; }
      if (tableLines[i + 1] === "__TABLE_SEP__") {
        processedLines.push("<tr>" + cells.map((c: string) => `<th>${c}</th>`).join("") + "</tr>");
      } else {
        processedLines.push("<tr>" + cells.map((c: string) => `<td>${c}</td>`).join("") + "</tr>");
        isHeader = false;
      }
    } else if (line === "__TABLE_SEP__") {
      // skip separator row
    } else {
      if (inTable) { processedLines.push("</table>"); inTable = false; isHeader = false; }
      processedLines.push(line);
    }
  }
  if (inTable) processedLines.push("</table>");
  html = processedLines.join("\n");

  html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
  html = html.replace(/^\d+\. (.+)$/gm, "<li>$1</li>");

  // Wrap consecutive <li> groups in <ul>
  const finalLines = html.split("\n");
  const wrappedLines: string[] = [];
  let inList = false;
  for (const line of finalLines) {
    if (line.startsWith("<li>")) {
      if (!inList) { wrappedLines.push("<ul>"); inList = true; }
      wrappedLines.push(line);
    } else {
      if (inList) { wrappedLines.push("</ul>"); inList = false; }
      wrappedLines.push(line);
    }
  }
  if (inList) wrappedLines.push("</ul>");
  html = wrappedLines.join("\n");

  html = html.split("\n").map((line: string) => {
    const t = line.trim();
    if (!t) return "";
    if (t.startsWith("<")) return line;
    if (t.startsWith("__HPCODE_")) return line;
    return `<p>${line}</p>`;
  }).join("\n");

  codeBlocks.forEach((block: string, idx: number) => {
    html = html.replace(`__HPCODE_${idx}__`, block);
    html = html.replace(`<p>__HPCODE_${idx}__</p>`, block);
  });

  return html;
}


interface HuntPlanModalProps {
  userQuery: string;
  xqlQuery: string;
  attackRef?: AttackRef | null;
  tenantSchemaContext?: string;
  onClose: () => void;
}

function HuntPlanModal({ userQuery, xqlQuery, attackRef, tenantSchemaContext, onClose }: HuntPlanModalProps) {
  const [planText, setPlanText] = useState('');
  const [streaming, setStreaming] = useState(true);
  const [copied, setCopied] = useState(false);
  const bodyRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    (window as any).copyHpCode = (btn: HTMLButtonElement) => {
      const pre = btn.closest('.hp-code-block')?.querySelector('pre code');
      if (!pre) return;
      navigator.clipboard.writeText(pre.textContent || '').then(() => {
        btn.textContent = '✓ COPIED';
        setTimeout(() => { btn.textContent = '> COPY'; }, 2000);
      });
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    async function fetchPlan() {
      try {
        const res = await fetch('/api/hunt-plan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ userQuery, xqlQuery, attackRef, tenantSchemaContext }),
        });
        if (!res.body) return;
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let full = '';
        while (true) {
          const { done, value } = await reader.read();
          if (done || cancelled) break;
          full += decoder.decode(value, { stream: true });
          setPlanText(full);
          // Auto-scroll body
          if (bodyRef.current) {
            bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
          }
        }
        if (!cancelled) setStreaming(false);
      } catch {
        if (!cancelled) { setPlanText('**ERROR** — Failed to generate hunt plan.'); setStreaming(false); }
      }
    }
    fetchPlan();
    return () => { cancelled = true; };
  }, []);

  const handleCopyAll = () => {
    navigator.clipboard.writeText(planText).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    });
  };

  const handleDownload = () => {
    const blob = new Blob([planText], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const slug = userQuery.slice(0, 40).replace(/[^a-z0-9]/gi, '-').toLowerCase();
    a.href = url;
    a.download = `hunt-plan-${slug}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="hunt-modal-overlay" onClick={onClose}>
      <div className="hunt-modal" onClick={e => e.stopPropagation()}>
        <div className="hunt-modal-header">
          <div>
            <div className="hunt-modal-title">⟴ Structured Hunt Plan</div>
            <div className="hunt-modal-sub">
              PEAK METHODOLOGY · ATT&CK ALIGNED
              {attackRef && <span style={{ color: 'rgba(255,107,53,0.8)', marginLeft: '10px' }}>{attackRef.techniqueId} · {attackRef.tactic}</span>}
              {streaming && <span style={{ color: 'var(--accent-yellow)', marginLeft: '10px', animation: 'pulse-dot 1.5s infinite' }}>GENERATING...</span>}
            </div>
          </div>
          <div className="hunt-modal-actions">
            {!streaming && (
              <>
                <button className="hunt-action-btn" onClick={handleCopyAll}>
                  {copied ? '✓ COPIED' : '⎘ COPY MD'}
                </button>
                <button className="hunt-action-btn primary" onClick={handleDownload}>
                  ↓ DOWNLOAD .MD
                </button>
              </>
            )}
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-dim)', fontSize: '18px', cursor: 'pointer', padding: '0 4px', marginLeft: '4px' }}>✕</button>
          </div>
        </div>

        <div className="hunt-modal-body" ref={bodyRef}>
          <div
            className="hunt-plan-content"
            dangerouslySetInnerHTML={{
              __html: parseHuntPlanMarkdown(planText) + (streaming ? '<span class="streaming-cursor"></span>' : ''),
            }}
          />
        </div>

        <div className="hunt-modal-footer">
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '9px', color: 'var(--text-dim)', letterSpacing: '0.1em' }}>
            {streaming ? 'GENERATING HUNT PLAN...' : `HUNT PLAN COMPLETE · ${planText.length} CHARS`}
          </span>
          <button className="hunt-action-btn" onClick={onClose}>CLOSE</button>
        </div>
      </div>
    </div>
  );
}

// ─── SCHEMA IMPORT MODAL ─────────────────────────────────────────────────────

function SchemaModal({ onClose, onImport }: { onClose: () => void; onImport: (schema: TenantSchema) => void }) {
  const [tab, setTab] = useState<"guide" | "paste" | "queries">("guide");
  const [pasteValue, setPasteValue] = useState("");
  const [parseResult, setParseResult] = useState<TenantSchema | null>(null);
  const [parseError, setParseError] = useState("");
  const [copiedKey, setCopiedKey] = useState("");

  const handleParse = () => {
    setParseError("");
    setParseResult(null);
    if (!pasteValue.trim()) { setParseError("Nothing pasted yet."); return; }
    try {
      const result = parseTenantSchema(pasteValue);
      if (result.datasetCount === 0) {
        setParseError("Parse completed but no datasets found. Check format — see the Guide tab.");
        return;
      }
      setParseResult(result);
    } catch (e) {
      setParseError(`Parse failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const handleConfirm = () => {
    if (parseResult) onImport(parseResult);
  };

  const copyQuery = (key: string, text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(""), 2000);
    });
  };

  const tabStyle = (active: boolean) => ({
    fontFamily: "var(--font-mono)" as const,
    fontSize: "10px",
    letterSpacing: "0.12em",
    textTransform: "uppercase" as const,
    padding: "6px 14px",
    background: "none",
    border: "none",
    borderBottom: active ? "2px solid var(--accent-cyan)" : "2px solid transparent",
    color: active ? "var(--accent-cyan)" : "var(--text-dim)",
    cursor: "pointer",
  });

  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(2,6,8,0.88)", zIndex: 100, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={onClose}>
      <div style={{ width: "620px", maxHeight: "82vh", background: "var(--bg-panel)", border: "1px solid var(--border-glow)", borderRadius: "4px", overflow: "hidden", display: "flex", flexDirection: "column" }} onClick={e => e.stopPropagation()}>

        {/* Modal header */}
        <div style={{ padding: "14px 18px", borderBottom: "1px solid var(--border-dim)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <div>
            <div style={{ fontFamily: "var(--font-display)", fontSize: "16px", fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--text-primary)" }}>
              Tenant Schema Import
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "9px", color: "var(--text-dim)", marginTop: "2px", letterSpacing: "0.1em" }}>
              MEMORY-ONLY · NOT PERSISTED TO DISK OR BROWSER STORAGE · CLEARED ON TAB CLOSE
            </div>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "var(--text-dim)", fontSize: "18px", cursor: "pointer", padding: "0 4px" }}>✕</button>
        </div>

        {/* Tabs */}
        <div style={{ display: "flex", borderBottom: "1px solid var(--border-dim)", padding: "0 18px" }}>
          <button style={tabStyle(tab === "guide")} onClick={() => setTab("guide")}>Guide</button>
          <button style={tabStyle(tab === "queries")} onClick={() => setTab("queries")}>Discovery Queries</button>
          <button style={tabStyle(tab === "paste")} onClick={() => setTab("paste")}>Import Data</button>
        </div>

        {/* Tab content */}
        <div style={{ flex: 1, overflowY: "auto", padding: "18px" }}>

          {tab === "guide" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--accent-cyan)", letterSpacing: "0.12em" }}>// WHY THIS EXISTS</div>
              <p style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.7 }}>
                XSIAM tenants vary significantly from out-of-box defaults. Hot/warm/cold storage tiers create differently-named dataset variants. Custom ingestion pipelines produce org-specific datasets. Without knowing your actual schema, the validator flags legitimate custom datasets as unknown.
              </p>
              <p style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.7 }}>
                Importing your schema lets XQL Shield generate queries against your real datasets and validate field names specific to your environment.
              </p>

              <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--accent-cyan)", letterSpacing: "0.12em", marginTop: "4px" }}>// SECURITY MODEL</div>
              <div style={{ background: "rgba(0,255,157,0.04)", border: "1px solid rgba(0,255,157,0.2)", padding: "10px 14px", borderRadius: "3px" }}>
                {[
                  "Schema is held in React memory only — never written to localStorage, sessionStorage, cookies, or any disk storage",
                  "Cleared automatically when you close or refresh the tab",
                  "Only dataset names, field names, and field types are used — no log values, no credentials",
                  "Import is sanitized: IPs, hashes, and tokens are redacted automatically",
                  "Schema is sent to the Anthropic API as part of your session prompt — treat it like any other query you run here"
                ].map((point, i) => (
                  <div key={i} style={{ display: "flex", gap: "8px", fontSize: "11px", color: "var(--text-secondary)", marginBottom: "6px", lineHeight: 1.5 }}>
                    <span style={{ color: "#00ff9d", flexShrink: 0 }}>✓</span>
                    {point}
                  </div>
                ))}
              </div>

              <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--accent-cyan)", letterSpacing: "0.12em" }}>// WORKFLOW</div>
              {[
                "Go to the Discovery Queries tab and copy the query that fits your needs",
                "Run it in your XSIAM XQL console",
                "Export the result as JSON or CSV",
                "Come back here → Import Data tab → paste the export",
                "Click Parse, review the summary, click Confirm Import"
              ].map((step, i) => (
                <div key={i} style={{ display: "flex", gap: "10px", fontSize: "12px", color: "var(--text-secondary)" }}>
                  <span style={{ color: "var(--accent-cyan)", fontFamily: "var(--font-mono)", fontSize: "10px", flexShrink: 0, marginTop: "2px" }}>{String(i+1).padStart(2,"0")}</span>
                  {step}
                </div>
              ))}
            </div>
          )}

          {tab === "queries" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
              <p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-dim)", letterSpacing: "0.08em" }}>
                // RUN THESE IN YOUR XSIAM XQL CONSOLE → EXPORT AS JSON OR CSV → PASTE IN IMPORT TAB
              </p>
              {[
                { key: "datasets", label: "All Datasets (start here)", desc: "Lists every dataset in your tenant with retention and storage tier. Fastest — no field detail.", query: DQ.datasets },
                { key: "allFields", label: "All Datasets + Fields (recommended)", desc: "Full field inventory across all datasets. May be large on complex tenants — export as JSON.", query: DQ.allFields },
                { key: "fields", label: "Single Dataset Fields", desc: "Deep dive on one dataset. Replace DATASET_NAME before running.", query: DQ.fields },
              ].map(({ key, label, desc, query }) => (
                <div key={key} style={{ background: "var(--bg-surface)", border: "1px solid var(--border-dim)", borderRadius: "3px", overflow: "hidden" }}>
                  <div style={{ padding: "8px 12px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid var(--border-dim)" }}>
                    <div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--accent-cyan)", letterSpacing: "0.08em" }}>{label}</div>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "2px" }}>{desc}</div>
                    </div>
                    <button onClick={() => copyQuery(key, query)} style={{ background: "none", border: "1px solid var(--border-dim)", color: copiedKey === key ? "#00ff9d" : "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "9px", padding: "3px 10px", cursor: "pointer", letterSpacing: "0.1em", flexShrink: 0 }}>
                      {copiedKey === key ? "✓ COPIED" : "> COPY"}
                    </button>
                  </div>
                  <pre style={{ margin: 0, padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-code)", lineHeight: 1.6, overflowX: "auto" }}>{query}</pre>
                </div>
              ))}
            </div>
          )}

          {tab === "paste" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              <p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-dim)", letterSpacing: "0.08em" }}>
                // PASTE YOUR XSIAM EXPORT BELOW (JSON OR CSV)
              </p>
              <textarea
                value={pasteValue}
                onChange={e => setPasteValue(e.target.value)}
                placeholder={'Paste JSON or CSV export here...\n\nJSON example:\n[{"name":"xdr_data_90d","retention_in_days":90},{"name":"okta_raw","retention_in_days":365}]\n\nCSV example:\ndataset_name,field_name,field_type\nxdr_data_90d,actor_process_image_name,string\nxdr_data_90d,event_timestamp,timestamp'}
                style={{ width: "100%", height: "200px", background: "var(--bg-void)", border: "1px solid var(--border-glow)", color: "var(--text-code)", fontFamily: "var(--font-mono)", fontSize: "11px", padding: "12px", resize: "vertical", outline: "none", borderRadius: "3px", lineHeight: 1.6 }}
              />
              <div style={{ display: "flex", gap: "8px" }}>
                <button onClick={handleParse} style={{ background: "var(--accent-cyan)", border: "none", color: "var(--bg-void)", fontFamily: "var(--font-mono)", fontSize: "11px", padding: "7px 18px", cursor: "pointer", letterSpacing: "0.1em", fontWeight: "bold" }}>
                  PARSE
                </button>
                <button onClick={() => { setPasteValue(""); setParseResult(null); setParseError(""); }} style={{ background: "none", border: "1px solid var(--border-dim)", color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "11px", padding: "7px 14px", cursor: "pointer", letterSpacing: "0.1em" }}>
                  CLEAR
                </button>
              </div>

              {parseError && (
                <div style={{ background: "rgba(255,45,85,0.08)", border: "1px solid rgba(255,45,85,0.3)", padding: "10px 14px", fontFamily: "var(--font-mono)", fontSize: "11px", color: "#ff2d55" }}>
                  ✗ {parseError}
                </div>
              )}

              {parseResult && (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  <div style={{ background: "rgba(0,255,157,0.06)", border: "1px solid rgba(0,255,157,0.25)", padding: "12px 14px", borderRadius: "3px" }}>
                    <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "#00ff9d", marginBottom: "8px" }}>✓ PARSE SUCCESSFUL</div>
                    <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px", fontSize: "11px" }}>
                      {[
                        ["Datasets found", parseResult.datasetCount],
                        ["Fields found", parseResult.fieldCount],
                        ["Format", parseResult.rawFormat.toUpperCase()],
                        ["Parsed at", new Date(parseResult.importedAt).toLocaleTimeString()],
                      ].map(([label, value]) => (
                        <div key={String(label)} style={{ display: "flex", gap: "8px" }}>
                          <span style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "10px" }}>{label}:</span>
                          <span style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)", fontSize: "10px" }}>{value}</span>
                        </div>
                      ))}
                    </div>

                    {parseResult.warnings.length > 0 && (
                      <div style={{ marginTop: "8px", display: "flex", flexDirection: "column", gap: "3px" }}>
                        {parseResult.warnings.map((w, i) => (
                          <div key={i} style={{ fontSize: "10px", color: "#ffd60a", fontFamily: "var(--font-mono)" }}>⚠ {w}</div>
                        ))}
                      </div>
                    )}

                    {/* Dataset preview */}
                    <div style={{ marginTop: "10px", maxHeight: "120px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "3px" }}>
                      {parseResult.datasets.slice(0, 20).map(ds => (
                        <div key={ds.name} style={{ display: "flex", gap: "10px", fontSize: "10px", fontFamily: "var(--font-mono)" }}>
                          <span style={{ color: "var(--accent-cyan)" }}>{ds.name}</span>
                          {ds.storageType && <span style={{ color: "var(--text-dim)" }}>[{ds.storageType}]</span>}
                          {ds.fields.length > 0 && <span style={{ color: "var(--text-dim)" }}>{ds.fields.length} fields</span>}
                        </div>
                      ))}
                      {parseResult.datasetCount > 20 && (
                        <div style={{ fontSize: "10px", color: "var(--text-dim)", fontFamily: "var(--font-mono)" }}>... and {parseResult.datasetCount - 20} more</div>
                      )}
                    </div>
                  </div>

                  <button onClick={handleConfirm} style={{ background: "#00ff9d", border: "none", color: "var(--bg-void)", fontFamily: "var(--font-mono)", fontSize: "11px", padding: "9px 20px", cursor: "pointer", letterSpacing: "0.12em", fontWeight: "bold", alignSelf: "flex-start" }}>
                    ✓ CONFIRM IMPORT — LOAD INTO SESSION
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── MARKDOWN PARSER ─────────────────────────────────────────────────────────

function parseMarkdown(text: string, isStreaming: boolean): string {
  let html = text;
  const codeBlocks: string[] = [];
  html = html.replace(/```(\w*)\n?([\s\S]*?)```/g, (_, lang, code) => {
    const idx = codeBlocks.length;
    codeBlocks.push(
      `<div class="code-block-wrapper"><div class="code-block-header"><span class="code-lang">${lang || "xql"}</span><button class="copy-btn" onclick="copyCode(this)">&gt; COPY</button></div><pre><code>${escapeHtml(code.trim())}</code></pre></div>`
    );
    return `__CODEBLOCK_${idx}__`;
  });
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/^### (.+)$/gm, "<h3>$1</h3>");
  html = html.replace(/^## (.+)$/gm, "<h2>$1</h2>");
  html = html.replace(/^- (.+)$/gm, "<li>$1</li>");
  html = html.replace(/^\d+\. (.+)$/gm, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>(\n|$))+/g, "<ul>$&</ul>");
  html = html.split("\n").map(line => {
    const t = line.trim();
    if (!t || t.startsWith("<") || t.startsWith("__CODEBLOCK_")) return line;
    return `<p>${line}</p>`;
  }).join("\n");
  codeBlocks.forEach((block, idx) => {
    html = html.replace(`__CODEBLOCK_${idx}__`, block);
    html = html.replace(`<p>__CODEBLOCK_${idx}__</p>`, block);
  });
  if (isStreaming) {
    html = html.replace(/<\/p>$/, ' <span class="streaming-cursor"></span></p>');
    if (!html.includes("streaming-cursor")) html += '<span class="streaming-cursor"></span>';
  }
  return html;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// ─── MAIN COMPONENT ───────────────────────────────────────────────────────────

export default function Home() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(false);
  const [tenantSchema, setTenantSchema] = useState<TenantSchema | null>(null);
  const [pendingAttack, setPendingAttack] = useState<AttackRef | null>(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [huntPlanTarget, setHuntPlanTarget] = useState<{
    userQuery: string;
    xqlQuery: string;
    attackRef?: AttackRef | null;
  } | null>(null);
  const [showSchemaModal, setShowSchemaModal] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    (window as any).copyCode = (btn: HTMLButtonElement) => {
      const pre = btn.closest(".code-block-wrapper")?.querySelector("pre code");
      if (!pre) return;
      navigator.clipboard.writeText(pre.textContent || "").then(() => {
        btn.textContent = "✓ COPIED";
        btn.classList.add("copied");
        setTimeout(() => { btn.textContent = "> COPY"; btn.classList.remove("copied"); }, 2000);
      });
    };
  }, []);

  const handleSchemaImport = useCallback((schema: TenantSchema) => {
    setTenantSchema(schema);
    setShowSchemaModal(false);
  }, []);

  const sendMessage = useCallback(async (text: string, attackRef?: AttackRef | null) => {
    if (!text.trim() || loading) return;
    const userMsg: Message = { role: "user", content: text.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    setValidating(true);

    setPendingAttack(attackRef || null);
    setMessages([...newMessages, { role: "assistant", content: "", streaming: true, validation: null, attack: null }]);

    try {
      const tenantSchemaContext = tenantSchema ? schemaToPromptContext(tenantSchema) : undefined;

      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
          tenantSchemaContext,
        }),
      });

      if (!res.body) throw new Error("No response body");
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      let fullText = "";
      let validation: ValidationResult | null = null;
      let headerParsed = false;

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        if (!headerParsed) {
          const endTag = "__END_VALIDATION__\n";
          const startTag = "__VALIDATION__";
          if (buffer.includes(endTag)) {
            const start = buffer.indexOf(startTag) + startTag.length;
            const end = buffer.indexOf(endTag);
            try { validation = JSON.parse(buffer.slice(start, end)); } catch { /* skip */ }
            buffer = buffer.slice(end + endTag.length);
            headerParsed = true;
            setValidating(false);
          } else { continue; }
        }

        fullText += buffer;
        buffer = "";
        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = { role: "assistant", content: fullText, streaming: true, validation };
          return updated;
        });
      }

      if (buffer) fullText += buffer;
      setMessages((prev) => {
        const updated = [...prev];
        // Extract XQL for hunt plan button
        const xqlMatch = fullText.match(/```(?:xql)?[\s\S]*?([\s\S]+?)```/);
        const extractedXql = xqlMatch ? xqlMatch[1].trim() : null;
        updated[updated.length - 1] = {
          role: "assistant",
          content: fullText,
          streaming: false,
          validation,
          attack: attackRef || null,
          xqlQuery: extractedXql,
          userQuery: text,
        };
        return updated;
      });
    } catch {
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = { role: "assistant", content: "**ERROR** — Connection to XQL Shield failed. Check API key configuration.", streaming: false, validation: null };
        return updated;
      });
    } finally {
      setLoading(false);
      setValidating(false);
    }
  }, [messages, loading, tenantSchema]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendMessage(input); }
  };

  const handleTextareaInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    const ta = e.target;
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
  };

  return (
    <>
      <div className="corner-tl" /><div className="corner-tr" /><div className="corner-bl" /><div className="corner-br" />

      {showSchemaModal && <SchemaModal onClose={() => setShowSchemaModal(false)} onImport={handleSchemaImport} />}
      {huntPlanTarget && (
        <HuntPlanModal
          userQuery={huntPlanTarget.userQuery}
          xqlQuery={huntPlanTarget.xqlQuery}
          attackRef={huntPlanTarget.attackRef}
          tenantSchemaContext={tenantSchema ? schemaToPromptContext(tenantSchema) : undefined}
          onClose={() => setHuntPlanTarget(null)}
        />
      )}

      <div className="app-shell">
        {/* Sidebar overlay for mobile */}
        <div className={`sidebar-overlay${sidebarOpen ? " open" : ""}`} onClick={() => setSidebarOpen(false)} />

        {/* Header */}
        <header className="header">
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <button className="sidebar-toggle" onClick={() => setSidebarOpen(true)} aria-label="Open menu">
              ☰
            </button>
          <div className="header-logo">
            <div className="logo-icon">
              <svg viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
                <polygon points="16,2 28,8 28,24 16,30 4,24 4,8" stroke="#00c8ff" strokeWidth="1.5" fill="rgba(0,200,255,0.05)"/>
                <polygon points="16,7 23,11 23,21 16,25 9,21 9,11" stroke="#00c8ff" strokeWidth="0.75" fill="rgba(0,200,255,0.03)" opacity="0.6"/>
                <path d="M12 14 L16 12 L20 14 L20 18 L16 20 L12 18 Z" fill="rgba(0,200,255,0.2)" stroke="#00c8ff" strokeWidth="0.5"/>
                <circle cx="16" cy="16" r="2" fill="#00c8ff" opacity="0.8"/>
              </svg>
            </div>
            <div>
              <div className="logo-text">XQL<span>Shield</span></div>
              <div className="logo-sub">Cortex XDR · XSIAM · Query Translator</div>
            </div>
          </div>
          </div>
          <div className="header-status">
            {/* Tenant schema indicator */}
            {tenantSchema ? (
              <button onClick={() => setTenantSchema(null)} title="Click to clear tenant schema" style={{ display: "flex", alignItems: "center", gap: "6px", background: "rgba(0,255,157,0.06)", border: "1px solid rgba(0,255,157,0.3)", color: "#00ff9d", fontFamily: "var(--font-mono)", fontSize: "9px", padding: "3px 10px", cursor: "pointer", letterSpacing: "0.1em" }}>
                ◈ SCHEMA · {tenantSchema.datasetCount}ds · {tenantSchema.fieldCount}f &nbsp;✕
              </button>
            ) : (
              <button onClick={() => setShowSchemaModal(true)} style={{ display: "flex", alignItems: "center", gap: "6px", background: "none", border: "1px solid var(--border-dim)", color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "9px", padding: "3px 10px", cursor: "pointer", letterSpacing: "0.1em", transition: "all 0.2s" }}
                onMouseEnter={e => { (e.target as HTMLButtonElement).style.borderColor = "var(--accent-cyan)"; (e.target as HTMLButtonElement).style.color = "var(--accent-cyan)"; }}
                onMouseLeave={e => { (e.target as HTMLButtonElement).style.borderColor = "var(--border-dim)"; (e.target as HTMLButtonElement).style.color = "var(--text-dim)"; }}>
                + TENANT SCHEMA
              </button>
            )}
            {validating ? (
              <div className="status-badge" style={{ color: "var(--accent-yellow)" }}>
                <div className="status-dot" style={{ background: "var(--accent-yellow)", boxShadow: "0 0 8px var(--accent-yellow)" }} />VALIDATING
              </div>
            ) : (
              <div className="status-badge"><div className="status-dot" />ONLINE</div>
            )}
            <div className="model-badge">SONNET 4</div>
          </div>
        </header>

        {/* Main */}
        <div className="main-layout">
          <aside className={`sidebar${sidebarOpen ? " mobile-open" : ""}`}>
            {/* Mobile close button */}
            <div className="sidebar-close">
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-dim)", letterSpacing: "0.15em" }}>// HUNT IDEAS</span>
              <button className="sidebar-close-btn" onClick={() => setSidebarOpen(false)}>✕</button>
            </div>
            {/* Marquee — hunt ideas */}
            <div className="sidebar-section">
              <div className="sidebar-label">Hunt Ideas</div>
            </div>
            <div className="hunt-marquee-wrap">
              <div className="hunt-marquee-track">
                {[...HUNT_IDEAS, ...HUNT_IDEAS].map((idea, i) => (
                  <div key={i} className="hunt-idea-row" onClick={() => { sendMessage(idea.text, { techniqueId: idea.techniqueId, techniqueName: idea.techniqueName, tactic: idea.tactic, url: idea.url }); setSidebarOpen(false); }} title={"Hunt: " + idea.techniqueId + " · " + idea.techniqueName}>
                    <span className="hunt-idea-bullet">&#9658;</span>
                    <span className="hunt-idea-text">{idea.text}</span>
                    <span className="hunt-idea-technique">{idea.techniqueId}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Clickable starter chips */}
            <div className="sidebar-section">
              <div className="sidebar-label">Quick Start</div>
            </div>
            <div className="starter-prompts">
              {STARTER_PROMPTS.map((prompt, i) => (
                <button key={i} className="prompt-chip" onClick={() => { sendMessage(prompt); setSidebarOpen(false); }} disabled={loading}>{prompt}</button>
              ))}
            </div>
          </aside>

          <div className="chat-area">
            <div className="messages-container">
              {messages.length === 0 ? (
                <div className="welcome">
                  <svg className="welcome-icon" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <polygon points="32,4 56,16 56,48 32,60 8,48 8,16" stroke="#00c8ff" strokeWidth="2" fill="rgba(0,200,255,0.04)"/>
                    <polygon points="32,14 46,22 46,42 32,50 18,42 18,22" stroke="#00c8ff" strokeWidth="1" fill="rgba(0,200,255,0.02)" opacity="0.7"/>
                    <path d="M24 28 L32 24 L40 28 L40 36 L32 40 L24 36 Z" fill="rgba(0,200,255,0.15)" stroke="#00c8ff" strokeWidth="1"/>
                    <circle cx="32" cy="32" r="4" fill="#00c8ff" opacity="0.6"/>
                  </svg>
                  <h1>XQL <span>Shield</span></h1>
                  <p>Translate natural language threat hunting queries into production-ready XQL for Cortex XDR and XSIAM. Every query is auto-validated. Import your tenant schema for environment-aware generation.</p>
                  <div className="welcome-tags">
                    <span className="tag">Cortex XDR 5.x</span>
                    <span className="tag">XSIAM</span>
                    <span className="tag">MITRE ATT&amp;CK</span>
                    <span className="tag">Auto-Validated</span>
                    <span className="tag">Tenant-Aware</span>
                  </div>
                  {!tenantSchema && (
                    <button onClick={() => setShowSchemaModal(true)} style={{ marginTop: "12px", background: "none", border: "1px solid var(--border-glow)", color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: "10px", padding: "6px 16px", cursor: "pointer", letterSpacing: "0.12em" }}>
                      + IMPORT TENANT SCHEMA (OPTIONAL)
                    </button>
                  )}
                </div>
              ) : (
                messages.map((msg, i) => (
                  <div key={i} className={`message message-${msg.role}`}>
                    <div className="message-role">{msg.role === "user" ? "// OPERATOR" : "// XQL SHIELD"}</div>
                    <div className="message-bubble">
                      {msg.role === "assistant" ? (
                        <>
                          <div dangerouslySetInnerHTML={{ __html: parseMarkdown(msg.content, msg.streaming || false) }}/>
                          {msg.attack && !msg.streaming && <AttackBadge a={msg.attack} />}
                          {msg.xqlQuery && !msg.streaming && (
                            <button
                              className="hunt-plan-btn"
                              onClick={() => setHuntPlanTarget({
                                userQuery: msg.userQuery || "",
                                xqlQuery: msg.xqlQuery || "",
                                attackRef: msg.attack,
                              })}
                            >
                              ⟴ BUILD HUNT PLAN
                            </button>
                          )}
                          {msg.validation && !msg.streaming && <ValidationBadge v={msg.validation} />}
                        </>
                      ) : msg.content}
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            <div className="input-area">
              <div className="input-wrapper">
                <span className="input-prefix">&gt;_</span>
                <textarea ref={textareaRef} className="chat-input" placeholder="Describe what you want to hunt for..." value={input} onChange={handleTextareaInput} onKeyDown={handleKeyDown} rows={1} disabled={loading}/>
                <button className="send-btn" onClick={() => sendMessage(input)} disabled={loading || !input.trim()} title="Send">↑</button>
              </div>
              <div className="input-footer">
                <span className="input-hint">ENTER to send · SHIFT+ENTER for newline</span>
                <span className="input-hint">
                  {tenantSchema && <span style={{ color: "#00ff9d", marginRight: "8px" }}>◈ TENANT SCHEMA ACTIVE</span>}
                  {messages.filter((m) => m.role === "user").length} queries
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
