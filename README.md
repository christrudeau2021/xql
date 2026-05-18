# AXIOM

**Cross-platform natural language threat hunt assistant — XQL · KQL · SPL · CQL**

AXIOM translates natural language into production-ready, validated queries across Palo Alto Cortex XDR/XSIAM, Microsoft Sentinel/Defender, Splunk, and CrowdStrike Falcon NG-SIEM. Built for security operators, threat hunters, and detection engineers.

## Features

- **Natural language → query** across XQL, KQL, SPL, and CQL
- **Platform selector** — switch between SIEM/XDR platforms in one click
- **40 structured hunt hypotheses** mapped to MITRE ATT&CK, filterable by tactic
- **Two-stage AI validation** — every query validated for syntax, field names, and hunt logic before delivery
- **PEAK methodology hunt plans** — generate a full structured hunt plan for any query
- **Tenant schema import** — import your real dataset/table inventory for environment-aware generation
- **Scrolling threat hunt feed** — 50 curated hunt ideas with ATT&CK technique IDs
- **Mobile responsive** — full sidebar drawer on mobile

## Stack

- Next.js 14 (App Router)
- Anthropic Claude Sonnet 4 (streaming + validation)
- TypeScript throughout
- Zero UI framework dependencies

## Local Development

```bash
npm install
cp .env.local.example .env.local
# Add ANTHROPIC_API_KEY to .env.local
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

## Deploy to Vercel

1. Push to GitHub
2. Import repo in Vercel → add `ANTHROPIC_API_KEY` environment variable
3. Deploy

## Extending the Corpus

- `app/corpus.ts` — XQL syntax, HUNT_IDEAS (50 scrolling ideas), STARTER_PROMPTS
- `app/platformCorpus.ts` — KQL, SPL, CQL syntax, field names, examples, discovery queries
- `app/huntHypotheses.ts` — 40 structured PEAK hunt hypotheses with ATT&CK mapping

## License

Apache-2.0
