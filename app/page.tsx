"use client";

import { useState, useRef, useEffect, useCallback } from "react";
import { STARTER_PROMPTS } from "./corpus";

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

interface Message {
  role: "user" | "assistant";
  content: string;
  streaming?: boolean;
  validation?: ValidationResult | null;
}

// ─── VALIDATION BADGE ────────────────────────────────────────────────────────

function ValidationBadge({ v }: { v: ValidationResult }) {
  const [expanded, setExpanded] = useState(false);

  const config = {
    VERIFIED:      { color: "#00ff9d", bg: "rgba(0,255,157,0.08)",  border: "rgba(0,255,157,0.3)",  label: "VERIFIED",       icon: "✓" },
    LIKELY_VALID:  { color: "#00c8ff", bg: "rgba(0,200,255,0.08)",  border: "rgba(0,200,255,0.3)",  label: "LIKELY VALID",   icon: "◈" },
    REVIEW_ADVISED:{ color: "#ffd60a", bg: "rgba(255,214,10,0.08)", border: "rgba(255,214,10,0.3)", label: "REVIEW ADVISED", icon: "⚠" },
    FLAGGED:       { color: "#ff2d55", bg: "rgba(255,45,85,0.08)",  border: "rgba(255,45,85,0.3)",  label: "FLAGGED",        icon: "✗" },
  }[v.confidence];

  const severityColor = { ERROR: "#ff2d55", WARNING: "#ffd60a", INFO: "#00c8ff" };

  return (
    <div style={{
      marginTop: "10px",
      border: `1px solid ${config.border}`,
      background: config.bg,
      borderRadius: "3px",
      overflow: "hidden",
      fontFamily: "var(--font-mono)",
    }}>
      {/* Badge header — always visible */}
      <div
        onClick={() => v.issues.length > 0 && setExpanded(!expanded)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: "10px",
          padding: "7px 12px",
          cursor: v.issues.length > 0 ? "pointer" : "default",
        }}
      >
        {/* Score ring */}
        <div style={{
          width: "32px", height: "32px", position: "relative", flexShrink: 0,
        }}>
          <svg viewBox="0 0 32 32" style={{ width: "100%", height: "100%", transform: "rotate(-90deg)" }}>
            <circle cx="16" cy="16" r="13" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="3"/>
            <circle cx="16" cy="16" r="13" fill="none" stroke={config.color} strokeWidth="3"
              strokeDasharray={`${(v.score / 100) * 81.7} 81.7`}
              strokeLinecap="round"
            />
          </svg>
          <div style={{
            position: "absolute", inset: 0, display: "flex", alignItems: "center",
            justifyContent: "center", fontSize: "9px", color: config.color, fontWeight: "bold",
          }}>
            {v.score}
          </div>
        </div>

        {/* Label + summary */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "2px" }}>
            <span style={{ color: config.color, fontSize: "11px", letterSpacing: "0.12em", fontWeight: "bold" }}>
              {config.icon} {config.label}
            </span>
            {v.autoCorrected && (
              <span style={{
                fontSize: "9px", color: "#ffd60a", border: "1px solid rgba(255,214,10,0.4)",
                padding: "1px 5px", letterSpacing: "0.1em",
              }}>AUTO-CORRECTED</span>
            )}
          </div>
          <div style={{ fontSize: "10px", color: "var(--text-secondary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            {v.summary}
          </div>
        </div>

        {/* Issue count + toggle */}
        {v.issues.length > 0 && (
          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexShrink: 0 }}>
            <div style={{ display: "flex", gap: "4px" }}>
              {["ERROR","WARNING","INFO"].map(sev => {
                const count = v.issues.filter(i => i.severity === sev).length;
                if (!count) return null;
                return (
                  <span key={sev} style={{
                    fontSize: "9px", padding: "1px 5px",
                    color: severityColor[sev as keyof typeof severityColor],
                    border: `1px solid ${severityColor[sev as keyof typeof severityColor]}44`,
                    letterSpacing: "0.08em",
                  }}>
                    {count} {sev}
                  </span>
                );
              })}
            </div>
            <span style={{ color: "var(--text-dim)", fontSize: "10px" }}>
              {expanded ? "▲" : "▼"}
            </span>
          </div>
        )}
      </div>

      {/* Expanded issues */}
      {expanded && v.issues.length > 0 && (
        <div style={{ borderTop: `1px solid ${config.border}`, padding: "8px 12px", display: "flex", flexDirection: "column", gap: "5px" }}>
          {v.issues.map((issue, i) => (
            <div key={i} style={{ display: "flex", gap: "8px", fontSize: "10px", alignItems: "flex-start" }}>
              <span style={{
                color: severityColor[issue.severity],
                border: `1px solid ${severityColor[issue.severity]}44`,
                padding: "0px 5px", letterSpacing: "0.08em", flexShrink: 0, marginTop: "1px",
              }}>
                {issue.severity}
              </span>
              <span style={{ color: "var(--text-dim)", letterSpacing: "0.06em" }}>
                [{issue.category}]
              </span>
              <span style={{ color: "var(--text-secondary)", lineHeight: "1.5" }}>
                {issue.description}
              </span>
            </div>
          ))}
        </div>
      )}
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
      `<div class="code-block-wrapper">
        <div class="code-block-header">
          <span class="code-lang">${lang || "xql"}</span>
          <button class="copy-btn" onclick="copyCode(this)">&gt; COPY</button>
        </div>
        <pre><code>${escapeHtml(code.trim())}</code></pre>
      </div>`
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

  html = html
    .split("\n")
    .map((line) => {
      const trimmed = line.trim();
      if (!trimmed) return "";
      if (trimmed.startsWith("<")) return line;
      if (trimmed.startsWith("__CODEBLOCK_")) return line;
      return `<p>${line}</p>`;
    })
    .join("\n");

  codeBlocks.forEach((block, idx) => {
    html = html.replace(`__CODEBLOCK_${idx}__`, block);
    html = html.replace(`<p>__CODEBLOCK_${idx}__</p>`, block);
  });

  if (isStreaming) {
    html = html.replace(/<\/p>$/, ' <span class="streaming-cursor"></span></p>');
    if (!html.includes("streaming-cursor")) {
      html += '<span class="streaming-cursor"></span>';
    }
  }

  return html;
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ─── MAIN COMPONENT ───────────────────────────────────────────────────────────

export default function Home() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(false);
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
        setTimeout(() => {
          btn.textContent = "> COPY";
          btn.classList.remove("copied");
        }, 2000);
      });
    };
  }, []);

  const sendMessage = useCallback(
    async (text: string) => {
      if (!text.trim() || loading) return;
      const userMsg: Message = { role: "user", content: text.trim() };
      const newMessages = [...messages, userMsg];
      setMessages(newMessages);
      setInput("");
      setLoading(true);
      setValidating(true);

      const assistantMsg: Message = { role: "assistant", content: "", streaming: true, validation: null };
      setMessages([...newMessages, assistantMsg]);

      try {
        const res = await fetch("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            messages: newMessages.map((m) => ({ role: m.role, content: m.content })),
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

          // Parse validation prefix once it arrives
          if (!headerParsed) {
            const endTag = "__END_VALIDATION__\n";
            const startTag = "__VALIDATION__";
            if (buffer.includes(endTag)) {
              const start = buffer.indexOf(startTag) + startTag.length;
              const end = buffer.indexOf(endTag);
              try {
                validation = JSON.parse(buffer.slice(start, end));
              } catch { /* skip */ }
              buffer = buffer.slice(end + endTag.length);
              headerParsed = true;
              setValidating(false);
            } else {
              continue; // Wait for full header
            }
          }

          fullText += buffer;
          buffer = "";

          setMessages((prev) => {
            const updated = [...prev];
            updated[updated.length - 1] = {
              role: "assistant",
              content: fullText,
              streaming: true,
              validation,
            };
            return updated;
          });
        }

        // Flush any remaining buffer
        if (buffer) fullText += buffer;

        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: "assistant",
            content: fullText,
            streaming: false,
            validation,
          };
          return updated;
        });
      } catch {
        setMessages((prev) => {
          const updated = [...prev];
          updated[updated.length - 1] = {
            role: "assistant",
            content: "**ERROR** — Connection to XQL Shield failed. Check API key configuration.",
            streaming: false,
            validation: null,
          };
          return updated;
        });
      } finally {
        setLoading(false);
        setValidating(false);
      }
    },
    [messages, loading]
  );

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      sendMessage(input);
    }
  };

  const handleTextareaInput = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    const ta = e.target;
    ta.style.height = "auto";
    ta.style.height = Math.min(ta.scrollHeight, 120) + "px";
  };

  return (
    <>
      <div className="corner-tl" />
      <div className="corner-tr" />
      <div className="corner-bl" />
      <div className="corner-br" />

      <div className="app-shell">
        {/* Header */}
        <header className="header">
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
          <div className="header-status">
            {validating && (
              <div className="status-badge" style={{ color: "var(--accent-yellow)" }}>
                <div className="status-dot" style={{ background: "var(--accent-yellow)", boxShadow: "0 0 8px var(--accent-yellow)" }} />
                VALIDATING
              </div>
            )}
            {!validating && (
              <div className="status-badge">
                <div className="status-dot" />
                ONLINE
              </div>
            )}
            <div className="model-badge">SONNET 4</div>
          </div>
        </header>

        {/* Main */}
        <div className="main-layout">
          {/* Sidebar */}
          <aside className="sidebar">
            <div className="sidebar-section">
              <div className="sidebar-label">Hunt Starters</div>
            </div>
            <div className="starter-prompts">
              {STARTER_PROMPTS.map((prompt, i) => (
                <button key={i} className="prompt-chip" onClick={() => sendMessage(prompt)} disabled={loading}>
                  {prompt}
                </button>
              ))}
            </div>
          </aside>

          {/* Chat */}
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
                  <p>Translate natural language threat hunting queries into production-ready XQL for Cortex XDR and XSIAM. Every query is validated before delivery.</p>
                  <div className="welcome-tags">
                    <span className="tag">Cortex XDR 5.x</span>
                    <span className="tag">XSIAM</span>
                    <span className="tag">MITRE ATT&amp;CK</span>
                    <span className="tag">Auto-Validated</span>
                  </div>
                </div>
              ) : (
                messages.map((msg, i) => (
                  <div key={i} className={`message message-${msg.role}`}>
                    <div className="message-role">
                      {msg.role === "user" ? "// OPERATOR" : "// XQL SHIELD"}
                    </div>
                    <div className="message-bubble">
                      {msg.role === "assistant" ? (
                        <>
                          <div dangerouslySetInnerHTML={{
                            __html: parseMarkdown(msg.content, msg.streaming || false),
                          }}/>
                          {msg.validation && !msg.streaming && (
                            <ValidationBadge v={msg.validation} />
                          )}
                        </>
                      ) : (
                        msg.content
                      )}
                    </div>
                  </div>
                ))
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="input-area">
              <div className="input-wrapper">
                <span className="input-prefix">&gt;_</span>
                <textarea
                  ref={textareaRef}
                  className="chat-input"
                  placeholder="Describe what you want to hunt for..."
                  value={input}
                  onChange={handleTextareaInput}
                  onKeyDown={handleKeyDown}
                  rows={1}
                  disabled={loading}
                />
                <button
                  className="send-btn"
                  onClick={() => sendMessage(input)}
                  disabled={loading || !input.trim()}
                  title="Send"
                >
                  ↑
                </button>
              </div>
              <div className="input-footer">
                <span className="input-hint">ENTER to send · SHIFT+ENTER for newline</span>
                <span className="input-hint">{messages.filter((m) => m.role === "user").length} queries</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
