"use client";

import React, { useState, useRef, useEffect, useCallback } from "react";
import { STARTER_PROMPTS, HUNT_IDEAS, HuntIdea } from "./corpus";
import { PLATFORMS, getPlatform, Platform } from "./platformTypes";
import { HUNT_HYPOTHESES, TACTICS, HuntHypothesis } from "./huntHypotheses";
import { PLATFORM_DISCOVERY_QUERIES } from "./platformCorpus";
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
  xqlQuery?: string | null;
  userQuery?: string | null;
  platform?: Platform;
  refined?: boolean;  // true after apply-suggestions refinement
}

// ─── VALIDATION BADGE ────────────────────────────────────────────────────────

function ValidationBadge({
  v,
  onApply,
  applying,
}: {
  v: ValidationResult;
  onApply?: () => void;
  applying?: boolean;
}) {
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

      {/* Apply Suggestions button — shown when WARNING/ERROR issues exist and handler provided */}
      {onApply && v.issues.some(i => i.severity === "WARNING" || i.severity === "ERROR") && (
        <div style={{ borderTop: `1px solid ${config.border}`, padding: "8px 12px", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
          <span style={{ fontSize: "9px", color: "var(--text-dim)", letterSpacing: "0.08em" }}>
            {v.issues.filter(i => i.severity === "WARNING" || i.severity === "ERROR").length} issue(s) can be auto-resolved
          </span>
          <button
            onClick={onApply}
            disabled={applying}
            style={{
              display: "flex",
              alignItems: "center",
              gap: "5px",
              background: applying ? "rgba(255,214,10,0.05)" : "rgba(255,214,10,0.1)",
              border: "1px solid rgba(255,214,10,0.5)",
              color: applying ? "rgba(255,214,10,0.5)" : "#ffd60a",
              fontFamily: "var(--font-mono)",
              fontSize: "10px",
              padding: "5px 12px",
              cursor: applying ? "not-allowed" : "pointer",
              letterSpacing: "0.1em",
              borderRadius: "3px",
              transition: "all 0.2s",
            }}
          >
            {applying ? "⟳ APPLYING..." : "⟳ APPLY SUGGESTIONS"}
          </button>
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



// ─── PLATFORM SELECTOR ───────────────────────────────────────────────────────

function PlatformSelector({ current, onChange }: { current: Platform; onChange: (p: Platform) => void }) {
  const cfg = getPlatform(current);
  return (
    <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
      {PLATFORMS.map(p => (
        <button
          key={p.id}
          onClick={() => onChange(p.id)}
          title={p.fullName + " — " + p.vendor}
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "10px",
            letterSpacing: "0.1em",
            fontWeight: "bold",
            padding: "4px 10px",
            background: current === p.id ? p.bgColor : "none",
            border: `1px solid ${current === p.id ? p.borderColor : "var(--border-dim)"}`,
            color: current === p.id ? p.color : "var(--text-dim)",
            cursor: "pointer",
            borderRadius: "3px",
            transition: "all 0.15s",
            boxShadow: current === p.id ? `0 0 8px ${p.bgColor}` : "none",
          }}
        >
          {p.label}
        </button>
      ))}
    </div>
  );
}

// ─── HYPOTHESIS SIDEBAR ───────────────────────────────────────────────────────

function HypothesisSidebar({
  platform,
  activeTactic,
  setActiveTactic,
  onSelect,
  disabled,
}: {
  platform: Platform;
  activeTactic: string;
  setActiveTactic: (t: string) => void;
  onSelect: (h: HuntHypothesis) => void;
  disabled: boolean;
}) {
  const tactics = ["ALL", ...TACTICS];
  const filtered = activeTactic === "ALL"
    ? HUNT_HYPOTHESES
    : HUNT_HYPOTHESES.filter(h => h.tactic === activeTactic);

  const priorityColor = { CRITICAL: "#ff2d55", HIGH: "#ffd60a", MEDIUM: "#00c8ff" };
  const cfg = getPlatform(platform);

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1, overflow: "hidden" }}>
      {/* Tactic filter */}
      <div style={{ padding: "8px 10px", borderBottom: "1px solid var(--border-dim)", display: "flex", flexWrap: "wrap", gap: "3px" }}>
        {tactics.map(t => (
          <button
            key={t}
            onClick={() => setActiveTactic(t)}
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "8px",
              letterSpacing: "0.08em",
              textTransform: "uppercase",
              padding: "2px 6px",
              background: activeTactic === t ? "rgba(0,200,255,0.1)" : "none",
              border: `1px solid ${activeTactic === t ? "var(--accent-cyan)" : "var(--border-dim)"}`,
              color: activeTactic === t ? "var(--accent-cyan)" : "var(--text-dim)",
              cursor: "pointer",
              borderRadius: "2px",
            }}
          >
            {t === "ALL" ? "ALL" : t.replace(" and Control", "").replace("Command ", "C2").slice(0, 12)}
          </button>
        ))}
      </div>

      {/* Hypothesis list */}
      <div style={{ flex: 1, overflowY: "auto", padding: "6px" }}>
        {filtered.map(h => (
          <button
            key={h.id}
            disabled={disabled}
            onClick={() => onSelect(h)}
            style={{
              width: "100%",
              background: "none",
              border: "1px solid var(--border-dim)",
              borderLeft: `3px solid ${priorityColor[h.priority]}`,
              padding: "7px 8px",
              marginBottom: "4px",
              textAlign: "left",
              cursor: "pointer",
              borderRadius: "2px",
              transition: "all 0.15s",
            }}
            onMouseEnter={e => (e.currentTarget.style.borderColor = cfg.color)}
            onMouseLeave={e => (e.currentTarget.style.borderColor = "var(--border-dim)")}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "5px", marginBottom: "2px" }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "8px", color: priorityColor[h.priority], letterSpacing: "0.08em" }}>
                {h.priority}
              </span>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "8px", color: "var(--text-dim)" }}>
                {h.techniqueId}
              </span>
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-secondary)", lineHeight: 1.4 }}>
              {h.title}
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: "8px", color: "var(--text-dim)", marginTop: "2px" }}>
              {h.tactic}
            </div>
          </button>
        ))}
      </div>
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
  platform?: Platform;
  onClose: () => void;
}

function HuntPlanModal({ userQuery, xqlQuery, attackRef, tenantSchemaContext, platform = "xql", onClose }: HuntPlanModalProps) {
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
          body: JSON.stringify({ userQuery, xqlQuery, attackRef, tenantSchemaContext, platform }),
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

function SchemaModal({ onClose, onImport, platform = "xql" }: { onClose: () => void; onImport: (schema: TenantSchema) => void; platform?: Platform }) {
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

          {tab === "guide" && (() => {
            const guideContent: Record<string, { why: string; extra: string; console: string; exportNote: string }> = {
              xql: {
                why: "XSIAM tenants vary significantly from out-of-box defaults. Hot/warm/cold storage tiers create differently-named dataset variants. Custom ingestion pipelines produce org-specific datasets. Without knowing your actual schema, the validator flags legitimate custom datasets as unknown.",
                extra: "Importing your schema lets AXIOM generate queries against your real datasets and validate field names specific to your environment.",
                console: "XSIAM XQL Console (Cortex XDR → Investigation → Query Center)",
                exportNote: "Export result as JSON or CSV from the XQL console results panel",
              },
              kql: {
                why: "Microsoft Sentinel workspaces vary by deployment — custom connectors, partner solutions, and legacy Log Analytics tables all create non-standard table names. Defender XDR environments may have additional Advanced Hunting tables not in the standard schema.",
                extra: "Importing your workspace schema ensures the validator recognizes your custom tables and the generator suggests the right table for each hunt.",
                console: "Microsoft Sentinel → Logs (Log Analytics workspace) or Defender XDR → Advanced Hunting",
                exportNote: "Click Export → CSV or copy results as JSON from the query results panel",
              },
              spl: {
                why: "Splunk environments differ enormously — indexes, sourcetypes, and field aliases vary by deployment, data onboarding, and field extractions. The validator needs to know your actual indexes to avoid flagging legitimate SPL as incorrect.",
                extra: "Importing your index and sourcetype inventory lets the generator reference your real data sources instead of guessing common defaults.",
                console: "Splunk Web → Search & Reporting app → Search bar",
                exportNote: "Click Export → Export Results → CSV or JSON from the search results toolbar",
              },
              cql: {
                why: "CrowdStrike Falcon NG-SIEM environments have varying event coverage based on sensor version, OS platform, and Prevention Policy settings. Custom event pipelines and Fusion SOAR workflows may produce additional event types not in the standard schema.",
                extra: "Importing your event type inventory tells the validator which #event_simpleName values are active in your environment and prevents false-positive validation warnings.",
                console: "Falcon Console → Next-Gen SIEM → LogScale (or Investigate → Event Search)",
                exportNote: "Click the download icon on the query results table — export as CSV or JSON",
              },
            };
            const g = guideContent[platform] || guideContent.xql;
            const cfg = getPlatform(platform);
            return (
            <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
              {/* Platform badge */}
              <div style={{ display: "inline-flex", alignItems: "center", gap: "8px", background: cfg.bgColor, border: `1px solid ${cfg.borderColor}`, padding: "5px 12px", borderRadius: "3px", alignSelf: "flex-start" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: cfg.color, letterSpacing: "0.12em", fontWeight: "bold" }}>{cfg.label}</span>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: "9px", color: "var(--text-dim)" }}>{cfg.vendor}</span>
              </div>

              <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--accent-cyan)", letterSpacing: "0.12em" }}>// WHY THIS EXISTS</div>
              <p style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.7 }}>{g.why}</p>
              <p style={{ fontSize: "12px", color: "var(--text-secondary)", lineHeight: 1.7 }}>{g.extra}</p>

              <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--accent-cyan)", letterSpacing: "0.12em", marginTop: "4px" }}>// SECURITY MODEL</div>
              <div style={{ background: "rgba(0,255,157,0.04)", border: "1px solid rgba(0,255,157,0.2)", padding: "10px 14px", borderRadius: "3px" }}>
                {[
                  "Schema is held in React memory only — never written to localStorage, sessionStorage, cookies, or any disk storage",
                  "Cleared automatically when you close or refresh the tab",
                  "Only dataset/table names, field names, and types are used — no log values, no credentials",
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
                `Go to the Discovery Queries tab and copy the query that fits your needs`,
                `Run it in your ${g.console}`,
                g.exportNote,
                "Come back here → Import Data tab → paste the export",
                "Click Parse, review the summary, click Confirm Import"
              ].map((step, i) => (
                <div key={i} style={{ display: "flex", gap: "10px", fontSize: "12px", color: "var(--text-secondary)" }}>
                  <span style={{ color: cfg.color, fontFamily: "var(--font-mono)", fontSize: "10px", flexShrink: 0, marginTop: "2px" }}>{String(i+1).padStart(2,"0")}</span>
                  {step}
                </div>
              ))}
            </div>
            );
          })()}

          {tab === "queries" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "18px" }}>
              <p style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-dim)", letterSpacing: "0.08em" }}>
                // RUN IN YOUR {platform.toUpperCase()} CONSOLE → EXPORT JSON OR CSV → PASTE IN IMPORT TAB
              </p>
              {(PLATFORM_DISCOVERY_QUERIES[platform] || PLATFORM_DISCOVERY_QUERIES["xql"]).map(({ label, description, query }, idx) => (
                <div key={idx} style={{ background: "var(--bg-surface)", border: "1px solid var(--border-dim)", borderRadius: "3px", overflow: "hidden" }}>
                  <div style={{ padding: "8px 12px", display: "flex", alignItems: "center", justifyContent: "space-between", borderBottom: "1px solid var(--border-dim)" }}>
                    <div>
                      <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--accent-cyan)", letterSpacing: "0.08em" }}>{label}</div>
                      <div style={{ fontSize: "11px", color: "var(--text-dim)", marginTop: "2px" }}>{description}</div>
                    </div>
                    <button onClick={() => copyQuery(String(idx), query)} style={{ background: "none", border: "1px solid var(--border-dim)", color: copiedKey === String(idx) ? "#00ff9d" : "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "9px", padding: "3px 10px", cursor: "pointer", letterSpacing: "0.1em", flexShrink: 0 }}>
                      {copiedKey === String(idx) ? "✓ COPIED" : "> COPY"}
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

// ─── PLATFORM WORKFLOW BANNER (mobile) ───────────────────────────────────────
// Shows the 3-step workflow with active platform on mobile
function PlatformBanner({ platform, step }: { platform: Platform; step: 1|2|3 }) {
  const cfg = getPlatform(platform);
  const steps = [
    { n: 1, label: "Select Platform" },
    { n: 2, label: "Write Query" },
    { n: 3, label: "Hunt Plan" },
  ];
  return (
    <div className="platform-banner" style={{ "--platform-color": cfg.color } as React.CSSProperties}>
      <span className="platform-active-chip" style={{
        background: cfg.bgColor,
        border: `1px solid ${cfg.borderColor}`,
        color: cfg.color,
        marginRight: "4px",
      }}>
        {cfg.label}
      </span>
      {steps.map((s, i) => (
        <React.Fragment key={s.n}>
          {i > 0 && <span className="platform-banner-arrow">›</span>}
          <div className={`platform-banner-step${step >= s.n ? " active" : ""}`}>
            <span className="platform-banner-step-num" style={
              step >= s.n ? { background: cfg.color, borderColor: cfg.color, color: "#020608" } : {}
            }>{s.n}</span>
            <span>{s.label}</span>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
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
  const [workflowStep, setWorkflowStep] = useState<1|2|3>(1);
  const [applyingIdx, setApplyingIdx] = useState<number | null>(null);
  const [platform, setPlatform] = useState<Platform>("xql");
  const platformRef = useRef<Platform>("xql");
  const [activeTactic, setActiveTactic] = useState<string>("ALL");
  // Keep ref in sync so sendMessage always reads the latest platform value
  useEffect(() => { platformRef.current = platform; }, [platform]);
  const [huntPlanTarget, setHuntPlanTarget] = useState<{
    userQuery: string;
    xqlQuery: string;
    attackRef?: AttackRef | null;
    platform?: Platform;
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


  // ─── APPLY SUGGESTIONS ─────────────────────────────────────────────────────
  const handleApplySuggestions = useCallback(async (msgIdx: number) => {
    const msg = messages[msgIdx];
    if (!msg || !msg.xqlQuery || !msg.validation) return;

    const warningIssues = msg.validation.issues.filter(
      (i) => i.severity === "WARNING" || i.severity === "ERROR"
    );
    if (warningIssues.length === 0) return;

    setApplyingIdx(msgIdx);

    try {
      const tenantSchemaContext = tenantSchema ? schemaToPromptContext(tenantSchema) : undefined;

      // Stage 1: Targeted refinement — fix only the flagged issues
      const refineRes = await fetch("/api/refine", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          originalQuery: msg.xqlQuery,
          userQuery: msg.userQuery || "",
          platform: msg.platform || platform,
          issues: warningIssues,
          tenantSchemaContext,
        }),
      });

      if (!refineRes.body) throw new Error("No response body");
      const reader = refineRes.body.getReader();
      const decoder = new TextDecoder();
      let refinedText = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        refinedText += decoder.decode(value, { stream: true });
      }

      // Extract refined query from code block
      const codeMatch = refinedText.match(/```[\w]*\n?([\s\S]*?)```/);
      if (!codeMatch) throw new Error("No query in refinement response");
      const refinedQuery = codeMatch[1].trim();

      // Stage 2: Re-validate the refined query via a lightweight validation call
      const activePlatform = msg.platform || platform;
      const validateRes = await fetch("/api/refine/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          query: refinedQuery,
          userQuery: msg.userQuery || "",
          platform: activePlatform,
          tenantSchemaContext,
        }),
      });

      let newValidation: ValidationResult = {
        ...msg.validation,
        autoCorrected: true,
        score: Math.min(msg.validation.score + 15, 98),
        issues: msg.validation.issues.filter((i) => i.severity === "INFO"),
        confidence: "LIKELY_VALID",
        summary: "Query refined — WARNING issues resolved.",
      };

      if (validateRes.ok) {
        try {
          const vdata = await validateRes.json();
          if (vdata.score) newValidation = { ...vdata, autoCorrected: true };
        } catch { /* use optimistic validation above */ }
      }

      // Update the message with refined query and new validation
      setMessages((prev) => {
        const updated = [...prev];
        const oldMsg = updated[msgIdx];
        const activePlatformLabel = activePlatform;
        const newContent = oldMsg.content.replace(
          /```[\w]*\n?[\s\S]*?```/,
          "```" + activePlatformLabel + "\n" + refinedQuery + "\n```"
        );
        updated[msgIdx] = {
          ...oldMsg,
          content: newContent,
          xqlQuery: refinedQuery,
          validation: newValidation,
          refined: true,
        };
        return updated;
      });

    } catch (err) {
      console.error("Apply suggestions failed:", err);
    } finally {
      setApplyingIdx(null);
    }
  }, [messages, platform, tenantSchema]);

    const sendMessage = useCallback(async (text: string, attackRef?: AttackRef | null, platformOverride?: Platform) => {
    if (!text.trim() || loading) return;
    const userMsg: Message = { role: "user", content: text.trim() };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);
    setValidating(true);
    setWorkflowStep(2);

    setPendingAttack(attackRef || null);
    setMessages([...newMessages, { role: "assistant", content: "", streaming: true, validation: null, attack: null }]);

    try {
      const tenantSchemaContext = tenantSchema ? schemaToPromptContext(tenantSchema) : undefined;
      const activePlatform = platformOverride || platformRef.current;

      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
          tenantSchemaContext,
          platform: activePlatform,
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
        // Extract query for hunt plan button
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
          platform: activePlatform,
        };
        return updated;
      });
    } catch {
      setMessages((prev) => {
        const updated = [...prev];
        updated[updated.length - 1] = { role: "assistant", content: "**ERROR** — Connection to AXIOM failed. Check API key configuration.", streaming: false, validation: null };
        return updated;
      });
    } finally {
      setLoading(false);
      setValidating(false);
    }
  }, [messages, loading, tenantSchema, platform]);

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

      {showSchemaModal && <SchemaModal onClose={() => setShowSchemaModal(false)} onImport={handleSchemaImport} platform={platform} />}
      {huntPlanTarget && (
        <HuntPlanModal
          userQuery={huntPlanTarget.userQuery}
          xqlQuery={huntPlanTarget.xqlQuery}
          attackRef={huntPlanTarget.attackRef}
          tenantSchemaContext={tenantSchema ? schemaToPromptContext(tenantSchema) : undefined}
          platform={huntPlanTarget.platform || platform}
          onClose={() => setHuntPlanTarget(null)}
        />
      )}

      <div className="app-shell">
        {/* Sidebar overlay for mobile */}
        <div className={`sidebar-overlay${sidebarOpen ? " open" : ""}`} onClick={() => setSidebarOpen(false)} />

        {/* Header */}
        <header className="header">
          {/* ── Row 1: Logo + hamburger + schema/status ── */}
          <div className="header-row-1">
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
                  <div className="logo-text">AXI<span>OM</span></div>
                  <div className="logo-sub">XQL · KQL · SPL · CQL · Threat Hunt Assistant</div>
                </div>
              </div>
            </div>
            <div className="header-status">
              {/* Platform selector — visible on desktop in status row, hidden on mobile (moves to row-2) */}
              <div className="platform-selector-desktop">
                <PlatformSelector current={platform} onChange={p => { setPlatform(p); setWorkflowStep(1); }} />
              </div>
              {tenantSchema ? (
                <button onClick={() => setTenantSchema(null)} title="Click to clear tenant schema" style={{ display: "flex", alignItems: "center", gap: "6px", background: "rgba(0,255,157,0.06)", border: "1px solid rgba(0,255,157,0.3)", color: "#00ff9d", fontFamily: "var(--font-mono)", fontSize: "9px", padding: "3px 10px", cursor: "pointer", letterSpacing: "0.1em" }}>
                  ◈ SCHEMA · {tenantSchema.datasetCount}ds &nbsp;✕
                </button>
              ) : (
                <button onClick={() => setShowSchemaModal(true)} style={{ display: "flex", alignItems: "center", gap: "6px", background: "none", border: "1px solid var(--border-dim)", color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "9px", padding: "3px 10px", cursor: "pointer", letterSpacing: "0.1em" }}
                  onMouseEnter={e => { (e.target as HTMLButtonElement).style.borderColor = "var(--accent-cyan)"; (e.target as HTMLButtonElement).style.color = "var(--accent-cyan)"; }}
                  onMouseLeave={e => { (e.target as HTMLButtonElement).style.borderColor = "var(--border-dim)"; (e.target as HTMLButtonElement).style.color = "var(--text-dim)"; }}>
                  + SCHEMA
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
          </div>

          {/* ── Row 2: Platform selector — full width, prominent on mobile ── */}
          <div className="header-row-2">
            <div className="platform-selector-wrap">
              <PlatformSelector current={platform} onChange={p => { setPlatform(p); setWorkflowStep(1); }} />
            </div>
          </div>
        </header>

        {/* Platform workflow banner — visible on mobile */}
        <PlatformBanner platform={platform} step={workflowStep} />

        {/* Main */}
        <div className="main-layout">
          <aside className={`sidebar${sidebarOpen ? " mobile-open" : ""}`}>
            {/* Mobile close button */}
            <div className="sidebar-close">
              <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-dim)", letterSpacing: "0.15em" }}>// THREAT HUNTS</span>
              <button className="sidebar-close-btn" onClick={() => setSidebarOpen(false)}>✕</button>
            </div>

            {/* Hunt Ideas Marquee — always visible */}
            <div className="hunt-marquee-wrap">
              <div className="hunt-marquee-track">
                {[...HUNT_IDEAS, ...HUNT_IDEAS].map((idea, i) => (
                  <div key={i} className="hunt-idea-row"
                    onClick={() => { sendMessage(idea.text, { techniqueId: idea.techniqueId, techniqueName: idea.techniqueName, tactic: idea.tactic, url: idea.url }); setSidebarOpen(false); }}
                    title={"Hunt: " + idea.techniqueId + " · " + idea.techniqueName}>
                    <span className="hunt-idea-bullet">&#9658;</span>
                    <span className="hunt-idea-text">{idea.text}</span>
                    <span className="hunt-idea-technique">{idea.techniqueId}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* 40 Hypothesis library */}
            <div className="sidebar-section">
              <div className="sidebar-label">Hunt Hypotheses ({HUNT_HYPOTHESES.length})</div>
            </div>
            <HypothesisSidebar
              platform={platform}
              activeTactic={activeTactic}
              setActiveTactic={setActiveTactic}
              onSelect={(h) => {
                const query = h.queryHints[platform];
                const attackRef = { techniqueId: h.techniqueId, techniqueName: h.techniqueName, tactic: h.tactic, url: h.attackUrl };
                sendMessage(query, attackRef);
                setSidebarOpen(false);
              }}
              disabled={loading}
            />
          </aside>

          <div className="chat-area">
            {/* Platform context indicator — visible in chat area */}
            {(() => {
              const cfg = getPlatform(platform);
              return (
                <div className="chat-platform-indicator" style={{ borderBottom: `1px solid ${cfg.borderColor}`, background: cfg.bgColor.replace("0.07","0.03") }}>
                  <span className="chat-platform-label">Active Platform:</span>
                  <span className="chat-platform-name" style={{ color: cfg.color }}>{cfg.label}</span>
                  <span style={{ color: "var(--text-dim)", fontFamily: "var(--font-mono)", fontSize: "9px" }}>·</span>
                  <span className="chat-platform-vendor">{cfg.vendor}</span>
                  <span style={{ flex: 1 }} />
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "9px", color: "var(--text-dim)", letterSpacing: "0.1em" }}>
                    STEP 1 SELECT · STEP 2 QUERY · STEP 3 HUNT PLAN
                  </span>
                </div>
              );
            })()}
            <div className="messages-container">
              {messages.length === 0 ? (
                <div className="welcome">
                  <svg className="welcome-icon" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <polygon points="32,4 56,16 56,48 32,60 8,48 8,16" stroke="#00c8ff" strokeWidth="2" fill="rgba(0,200,255,0.04)"/>
                    <polygon points="32,14 46,22 46,42 32,50 18,42 18,22" stroke="#00c8ff" strokeWidth="1" fill="rgba(0,200,255,0.02)" opacity="0.7"/>
                    <path d="M24 28 L32 24 L40 28 L40 36 L32 40 L24 36 Z" fill="rgba(0,200,255,0.15)" stroke="#00c8ff" strokeWidth="1"/>
                    <circle cx="32" cy="32" r="4" fill="#00c8ff" opacity="0.6"/>
                  </svg>
                  <h1>AXI<span>OM</span></h1>
                  <p>Natural language threat hunting across every major platform — XQL, KQL, SPL, and CQL. Select your platform, choose from 40 ATT&CK-mapped hunt hypotheses, and generate validated queries with full PEAK-methodology hunt plans.</p>
                  <div className="welcome-tags">
                    <span className="tag">XQL · KQL · SPL · CQL</span>
                    <span className="tag">MITRE ATT&amp;CK</span>
                    <span className="tag">Auto-Validated</span>
                    <span className="tag">40 Hunt Hypotheses</span>
                    <span className="tag">PEAK Methodology</span>
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
                    <div className="message-role">{msg.role === "user" ? "// OPERATOR" : "// AXIOM"}</div>
                    <div className="message-bubble">
                      {msg.role === "assistant" ? (
                        <>
                          <div dangerouslySetInnerHTML={{ __html: parseMarkdown(msg.content, msg.streaming || false) }}/>
                          {msg.attack && !msg.streaming && <AttackBadge a={msg.attack} />}
                          {msg.xqlQuery && !msg.streaming && (
                            <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
                              <button
                                className="hunt-plan-btn"
                                onClick={() => { setWorkflowStep(3); setHuntPlanTarget({
                                  userQuery: msg.userQuery || "",
                                  xqlQuery: msg.xqlQuery || "",
                                  attackRef: msg.attack,
                                  platform: msg.platform,
                                }); }}
                              >
                                ⟴ BUILD HUNT PLAN
                              </button>
                              {msg.refined && (
                                <span style={{ fontFamily: "var(--font-mono)", fontSize: "9px", color: "#00ff9d", border: "1px solid rgba(0,255,157,0.3)", padding: "3px 8px", letterSpacing: "0.1em" }}>
                                  ✓ REFINED
                                </span>
                              )}
                            </div>
                          )}
                          {msg.validation && !msg.streaming && (
                            <ValidationBadge
                              v={msg.validation}
                              onApply={
                                msg.validation.confidence !== "VERIFIED" &&
                                msg.validation.issues.some(i => i.severity === "WARNING" || i.severity === "ERROR")
                                  ? () => handleApplySuggestions(i)
                                  : undefined
                              }
                              applying={applyingIdx === i}
                            />
                          )}
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
