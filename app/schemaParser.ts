// ─── TENANT SCHEMA TYPES ────────────────────────────────────────────────────

export interface TenantField {
  name: string;
  type?: string;        // string, integer, timestamp, boolean, etc.
  description?: string;
}

export interface TenantDataset {
  name: string;
  storageType?: string;  // HOT, WARM, COLD, CUSTOM
  retentionDays?: number;
  fields: TenantField[];
  rowCount?: number;
}

export interface TenantSchema {
  importedAt: number;       // epoch ms — for display only, never persisted
  datasetCount: number;
  fieldCount: number;
  datasets: TenantDataset[];
  rawFormat: "json" | "csv" | "unknown";
  warnings: string[];
}

// ─── DISCOVERY QUERIES ──────────────────────────────────────────────────────
// These are run by the operator in their XSIAM console and the results imported here.

export const DISCOVERY_QUERIES = {
  datasets: `// Run in XSIAM XQL console — exports all available datasets
// Export result as JSON or CSV
dataset = datasets
| fields name, retention_in_days, data_vendor, schema_fields_count
| sort asc name`,

  fields: `// Run per dataset to get field-level detail (replace DATASET_NAME)
// Export result as JSON or CSV
dataset = dataset_fields
| filter dataset_name = "DATASET_NAME"
| fields dataset_name, field_name, field_type
| sort asc field_name`,

  allFields: `// Run to get ALL fields across ALL datasets in one export
// Export result as JSON — may be large on large tenants
dataset = dataset_fields
| fields dataset_name, field_name, field_type
| sort asc dataset_name, field_name`,
};

// ─── SANITIZER ──────────────────────────────────────────────────────────────
// Strip any values that look like actual log data / credentials / IPs
// We only want structural metadata: names and types, never values

function sanitizeValue(val: string): string {
  // Remove anything that looks like an IP address
  val = val.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "[REDACTED-IP]");
  // Remove anything that looks like a hash (md5/sha256)
  val = val.replace(/\b[a-fA-F0-9]{32,64}\b/g, "[REDACTED-HASH]");
  // Remove anything that looks like a JWT or base64 token
  val = val.replace(/eyJ[A-Za-z0-9+/=]{20,}/g, "[REDACTED-TOKEN]");
  // Truncate extremely long values (log data leaked in)
  if (val.length > 200) val = val.slice(0, 200) + "...[TRUNCATED]";
  return val;
}

function sanitizeFieldName(name: string): string {
  // Field names should only be alphanumeric + underscore + dot
  return name.replace(/[^a-zA-Z0-9_.]/g, "_").slice(0, 100);
}

function sanitizeDatasetName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, "_").slice(0, 100);
}

// ─── JSON PARSER ────────────────────────────────────────────────────────────

function parseJSON(raw: string): { datasets: TenantDataset[]; warnings: string[] } {
  const warnings: string[] = [];
  const data = JSON.parse(raw); // throws on invalid JSON

  // Handle array of rows (standard XQL export format)
  const rows: Record<string, unknown>[] = Array.isArray(data)
    ? data
    : data.data ?? data.results ?? data.rows ?? [];

  if (!Array.isArray(rows) || rows.length === 0) {
    warnings.push("No rows found in JSON. Expected an array or object with data/results/rows key.");
    return { datasets: [], warnings };
  }

  // Detect format: dataset-list vs field-list
  const firstRow = rows[0] as Record<string, unknown>;
  const keys = Object.keys(firstRow).map(k => k.toLowerCase());

  const isDatasetList = keys.some(k => k.includes("name") || k.includes("dataset"));
  const isFieldList = keys.some(k => k.includes("field_name") || k.includes("field_type"));

  if (isFieldList) {
    // Format: [{dataset_name, field_name, field_type}, ...]
    return parseFieldList(rows, warnings);
  } else if (isDatasetList) {
    // Format: [{name, retention_in_days, ...}, ...]
    return parseDatasetList(rows, warnings);
  } else {
    warnings.push("Could not detect format. Expected field_name/field_type columns or name/retention columns.");
    return { datasets: [], warnings };
  }
}

function parseDatasetList(
  rows: Record<string, unknown>[],
  warnings: string[]
): { datasets: TenantDataset[]; warnings: string[] } {
  const datasets: TenantDataset[] = [];

  for (const row of rows) {
    const nameKey = Object.keys(row).find(k =>
      k.toLowerCase() === "name" || k.toLowerCase() === "dataset_name"
    );
    if (!nameKey || !row[nameKey]) continue;

    const rawName = String(row[nameKey]);
    const name = sanitizeDatasetName(rawName);

    const retKey = Object.keys(row).find(k =>
      k.toLowerCase().includes("retention") || k.toLowerCase().includes("days")
    );
    const retentionDays = retKey ? parseInt(String(row[retKey])) || undefined : undefined;

    const storageKey = Object.keys(row).find(k =>
      k.toLowerCase().includes("storage") || k.toLowerCase().includes("tier")
    );
    const storageType = storageKey ? sanitizeValue(String(row[storageKey])).toUpperCase() : undefined;

    datasets.push({ name, storageType, retentionDays, fields: [] });
  }

  if (datasets.length === 0) {
    warnings.push("Dataset list parsed but no valid dataset names found.");
  }
  return { datasets, warnings };
}

function parseFieldList(
  rows: Record<string, unknown>[],
  warnings: string[]
): { datasets: TenantDataset[]; warnings: string[] } {
  const datasetMap = new Map<string, TenantDataset>();

  for (const row of rows) {
    const dsKey = Object.keys(row).find(k =>
      k.toLowerCase().includes("dataset")
    );
    const fnKey = Object.keys(row).find(k =>
      k.toLowerCase().includes("field_name") || k.toLowerCase() === "field"
    );
    const ftKey = Object.keys(row).find(k =>
      k.toLowerCase().includes("field_type") || k.toLowerCase() === "type"
    );

    if (!dsKey || !fnKey || !row[dsKey] || !row[fnKey]) continue;

    const dsName = sanitizeDatasetName(String(row[dsKey]));
    const fieldName = sanitizeFieldName(String(row[fnKey]));
    const fieldType = ftKey && row[ftKey] ? sanitizeValue(String(row[ftKey])) : undefined;

    if (!datasetMap.has(dsName)) {
      datasetMap.set(dsName, { name: dsName, fields: [] });
    }
    datasetMap.get(dsName)!.fields.push({ name: fieldName, type: fieldType });
  }

  const datasets = Array.from(datasetMap.values());
  if (datasets.length === 0) {
    warnings.push("Field list parsed but no valid dataset/field pairs found.");
  }
  return { datasets, warnings };
}

// ─── CSV PARSER ─────────────────────────────────────────────────────────────

function parseCSV(raw: string): { datasets: TenantDataset[]; warnings: string[] } {
  const warnings: string[] = [];
  const lines = raw.trim().split("\n").filter(l => l.trim());

  if (lines.length < 2) {
    warnings.push("CSV appears empty or has only a header row.");
    return { datasets: [], warnings };
  }

  // Parse header
  const header = lines[0].split(",").map(h => h.trim().replace(/^"|"$/g, "").toLowerCase());

  const rows: Record<string, string>[] = lines.slice(1).map(line => {
    // Simple CSV parse — handles quoted fields
    const values: string[] = [];
    let current = "";
    let inQuotes = false;
    for (const char of line) {
      if (char === '"') { inQuotes = !inQuotes; continue; }
      if (char === "," && !inQuotes) { values.push(current.trim()); current = ""; continue; }
      current += char;
    }
    values.push(current.trim());

    const row: Record<string, string> = {};
    header.forEach((h, i) => { row[h] = values[i] ?? ""; });
    return row;
  });

  return parseJSON(JSON.stringify(rows)); // Reuse JSON logic after converting
}

// ─── MAIN PARSE ENTRY POINT ─────────────────────────────────────────────────

export function parseTenantSchema(raw: string): TenantSchema {
  const warnings: string[] = [];
  let datasets: TenantDataset[] = [];
  let rawFormat: TenantSchema["rawFormat"] = "unknown";

  // Size guard — 5MB max
  if (raw.length > 5 * 1024 * 1024) {
    return {
      importedAt: Date.now(),
      datasetCount: 0,
      fieldCount: 0,
      datasets: [],
      rawFormat: "unknown",
      warnings: ["Import exceeds 5MB limit. Please export a smaller dataset or field list."],
    };
  }

  const trimmed = raw.trim();

  try {
    if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
      rawFormat = "json";
      const result = parseJSON(trimmed);
      datasets = result.datasets;
      warnings.push(...result.warnings);
    } else {
      rawFormat = "csv";
      const result = parseCSV(trimmed);
      datasets = result.datasets;
      warnings.push(...result.warnings);
    }
  } catch (err) {
    warnings.push(`Parse error: ${err instanceof Error ? err.message : String(err)}`);
  }

  const fieldCount = datasets.reduce((sum, ds) => sum + ds.fields.length, 0);

  return {
    importedAt: Date.now(),
    datasetCount: datasets.length,
    fieldCount,
    datasets,
    rawFormat,
    warnings,
  };
}

// ─── SCHEMA → PROMPT INJECTION ──────────────────────────────────────────────
// Converts tenant schema into a compact text block for system prompt injection

export function schemaToPromptContext(schema: TenantSchema): string {
  if (!schema || schema.datasetCount === 0) return "";

  const lines: string[] = [
    "## TENANT-SPECIFIC SCHEMA (imported this session — in-memory only)",
    `Imported: ${schema.datasetCount} datasets, ${schema.fieldCount} fields`,
    "When generating or validating queries, prefer these tenant-specific datasets and fields over generic guesses.",
    "",
  ];

  for (const ds of schema.datasets) {
    const meta: string[] = [];
    if (ds.storageType) meta.push(`storage=${ds.storageType}`);
    if (ds.retentionDays) meta.push(`retention=${ds.retentionDays}d`);
    const metaStr = meta.length ? ` [${meta.join(", ")}]` : "";
    lines.push(`### Dataset: ${ds.name}${metaStr}`);

    if (ds.fields.length > 0) {
      // Group fields in compact format — don't blow up the context window
      const fieldList = ds.fields
        .slice(0, 150) // cap at 150 fields per dataset
        .map(f => f.type ? `${f.name}(${f.type})` : f.name)
        .join(", ");
      lines.push(`Fields: ${fieldList}`);
      if (ds.fields.length > 150) {
        lines.push(`  ... and ${ds.fields.length - 150} more fields`);
      }
    } else {
      lines.push("Fields: (dataset-list import — run field query for details)");
    }
    lines.push("");
  }

  return lines.join("\n");
}
