// ─── PLATFORM TYPES ──────────────────────────────────────────────────────────

export type Platform = "xql" | "kql" | "spl" | "cql";

export interface PlatformConfig {
  id: Platform;
  label: string;
  fullName: string;
  vendor: string;
  queryLanguage: string;
  color: string;
  borderColor: string;
  bgColor: string;
  codeLabel: string;
}

export const PLATFORMS: PlatformConfig[] = [
  {
    id: "xql",
    label: "XQL",
    fullName: "Extended Query Language",
    vendor: "Palo Alto Networks",
    queryLanguage: "XQL",
    color: "#00c8ff",
    borderColor: "rgba(0,200,255,0.4)",
    bgColor: "rgba(0,200,255,0.07)",
    codeLabel: "xql",
  },
  {
    id: "kql",
    label: "KQL",
    fullName: "Kusto Query Language",
    vendor: "Microsoft Sentinel / Defender",
    queryLanguage: "KQL",
    color: "#00b4d8",
    borderColor: "rgba(0,180,216,0.4)",
    bgColor: "rgba(0,180,216,0.07)",
    codeLabel: "kql",
  },
  {
    id: "spl",
    label: "SPL",
    fullName: "Search Processing Language",
    vendor: "Splunk",
    queryLanguage: "SPL",
    color: "#ff6b35",
    borderColor: "rgba(255,107,53,0.4)",
    bgColor: "rgba(255,107,53,0.07)",
    codeLabel: "spl",
  },
  {
    id: "cql",
    label: "CQL",
    fullName: "LogScale Query Language",
    vendor: "CrowdStrike Falcon",
    queryLanguage: "CQL",
    color: "#cc0000",
    borderColor: "rgba(204,0,0,0.4)",
    bgColor: "rgba(204,0,0,0.07)",
    codeLabel: "cql",
  },
];

export function getPlatform(id: Platform): PlatformConfig {
  return PLATFORMS.find((p) => p.id === id) || PLATFORMS[0];
}
