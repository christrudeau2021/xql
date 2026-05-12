# XQL Shield

**Natural language → XQL query translator for Palo Alto Networks Cortex XDR / XSIAM**

Built for security operators and threat hunters who need production-ready XQL fast.

## Features

- Translate plain English threat hunting questions into valid XQL
- Cybershield dark UI designed for SOC environments
- Streaming responses with syntax-highlighted query output
- Curated starter prompts covering common MITRE ATT&CK techniques
- Corpus-backed knowledge of XQL datasets, operators, and field names
- Tuning tips and key field guidance with every generated query

## Stack

- Next.js 14 (App Router)
- Anthropic Claude Sonnet 4 (streaming)
- Zero dependencies beyond Next + Anthropic SDK

## Local Development

```bash
npm install
cp .env.local.example .env.local
# Add your ANTHROPIC_API_KEY to .env.local
npm run dev
```

Open [http://localhost:3000](http://localhost:3000)

## Deploy to Vercel

1. Push to GitHub
2. Import repo in Vercel
3. Add environment variable: `ANTHROPIC_API_KEY`
4. Deploy

## Adding to the Corpus

Edit `app/corpus.ts` to add:
- New XQL datasets and field names
- Additional example queries
- MITRE ATT&CK technique mappings
- Starter prompts

## License

Apache-2.0
