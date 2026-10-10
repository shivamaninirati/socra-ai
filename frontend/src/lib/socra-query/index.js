// SOCRA Query Language (SQL/SPL/KQL-inspired) Parser
// Converts raw query strings into a structured AST for safe backend execution.
// Designed for SOCRA security telemetry analysis.

import { useState, useEffect, useRef, useCallback } from "react";

// ───────────────────────────────────────────────────────────────
// Token types
// ───────────────────────────────────────────────────────────────
const TOKEN = {
  FIELD: "FIELD",
  OPERATOR: "OPERATOR",
  VALUE: "VALUE",
  QUOTED: "QUOTED",
  AND: "AND",
  OR: "OR",
  NOT: "NOT",
  LBRACKET: "LBRACKET",
  RBRACKET: "RBRACKET",
  TO: "TO",
  TIME_RANGE: "TIME_RANGE",
  EOF: "EOF",
};

// ───────────────────────────────────────────────────────────────
// Supported operators
// ───────────────────────────────────────────────────────────────
const OPERATORS = [":", "=", "!=", ">", "<", ">=", "<=", "IN", "CONTAINS", "EXISTS"];

// ───────────────────────────────────────────────────────────────
// SOCRA Event Schema — defines all known fields, their types,
// descriptions, and example values for autocomplete and validation.
// This mirrors the actual telemetry the backend ingests.
// ───────────────────────────────────────────────────────────────
export const SOCRA_FIELDS = {
  // Authentication / Account Events
  event_id: {
    type: "integer",
    label: "Event ID",
    description: "Windows security event identifier",
    examples: ["4624", "4625", "4634", "4647", "4648", "4672", "4720", "4722", "4723", "4724", "4725", "4726", "4732", "4733", "4756", "4767", "4768", "4769", "4770", "4771", "4776", "4778", "4779", "4798", "4799", "4688", "4689"],
    category: "authentication",
  },
  status: {
    type: "enum",
    label: "Status",
    description: "Event status or outcome",
    values: ["success", "failed", "error", "warning", "info"],
    category: "authentication",
  },
  username: {
    type: "string",
    label: "Username",
    description: "Account name from authentication event",
    examples: ["admin", "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "Administrator", "guest"],
    category: "authentication",
  },
  user: {
    type: "string",
    label: "User",
    description: "User account name",
    examples: ["admin", "SYSTEM"],
    category: "authentication",
  },
  logon_type: {
    type: "enum",
    label: "Logon Type",
    description: "Type of user logon",
    values: ["2", "3", "7", "10"],
    category: "authentication",
  },
  process: {
    type: "string",
    label: "Process",
    description: "Process name",
    examples: ["powershell.exe", "cmd.exe", "svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe", "spoolsv.exe", "smss.exe"],
    category: "process",
  },
  process_name: {
    type: "string",
    label: "Process Name",
    description: "Name of the process",
    examples: ["powershell.exe", "cmd.exe", "svchost.exe"],
    category: "process",
  },
  pid: {
    type: "integer",
    label: "Process ID",
    description: "Process identifier",
    category: "process",
  },
  parent_process: {
    type: "string",
    label: "Parent Process",
    description: "Parent process name",
    examples: ["svchost.exe", "explorer.exe", "winlogon.exe"],
    category: "process",
  },

  // Network / Source / Destination
  source_ip: {
    type: "ip",
    label: "Source IP",
    description: "Source network address",
    examples: ["192.168.1.10", "10.0.0.5", "172.16.0.1"],
    category: "network",
  },
  source_port: {
    type: "integer",
    label: "Source Port",
    description: "Source port number",
    category: "network",
  },
  source_hostname: {
    type: "string",
    label: "Source Hostname",
    description: "Source host name",
    category: "network",
  },
  destination_ip: {
    type: "ip",
    label: "Destination IP",
    description: "Destination network address",
    examples: ["192.168.1.10", "10.0.0.5", "172.16.0.1"],
    category: "network",
  },
  destination_port: {
    type: "integer",
    label: "Destination Port",
    description: "Destination port number",
    category: "network",
  },
  destination_hostname: {
    type: "string",
    label: "Destination Hostname",
    description: "Destination host name",
    category: "network",
  },
  protocol: {
    type: "enum",
    label: "Protocol",
    description: "Network protocol",
    values: ["TCP", "UDP", "ICMP", "HTTP", "HTTPS", "DNS", "SMB", "LDAP", "RDP", "SSH", "FTP"],
    category: "network",
  },

  // Host / System
  host: {
    type: "string",
    label: "Host",
    description: "Hostname or computer name",
    examples: ["WORKSTATION01", "SERVER01", "DC01", "WIN10-PC", "SRV-APPS"],
    category: "system",
  },
  hostname: {
    type: "string",
    label: "Hostname",
    description: "Computer hostname",
    examples: ["WORKSTATION01", "SERVER01"],
    category: "system",
  },
  computer: {
    type: "string",
    label: "Computer",
    description: "Computer name",
    examples: ["WORKSTATION01", "SERVER01"],
    category: "system",
  },
  operating_system: {
    type: "string",
    label: "Operating System",
    description: "OS version",
    examples: ["Windows 10", "Windows Server 2019", "Windows 11"],
    category: "system",
  },

  // Detection / Alert
  severity: {
    type: "enum",
    label: "Severity",
    description: "Alert severity level",
    values: ["critical", "high", "medium", "low", "informational"],
    category: "detection",
  },
  detection: {
    type: "string",
    label: "Detection",
    description: "Detection rule or name",
    examples: ["Suspicious PowerShell", "Brute Force", "Lateral Movement"],
    category: "detection",
  },
  detection_name: {
    type: "string",
    label: "Detection Name",
    description: "Name of the detection rule",
    examples: ["PowerShell Encoded Command", "Anomalous Logon", "Suspicious Process"],
    category: "detection",
  },
  rule_id: {
    type: "string",
    label: "Rule ID",
    description: "Detection rule identifier",
    category: "detection",
  },
  category: {
    type: "string",
    label: "Category",
    description: "Detection category",
    examples: ["lateral_movement", "execution", "persistence", "exfiltration", "credential_access", "discovery", "collection", "command_and_control"],
    category: "detection",
  },

  // MITRE ATT&CK
  mitre: {
    type: "mitre",
    label: "MITRE ATT&CK",
    description: "MITRE ATT&CK technique identifier",
    examples: ["T1059.001", "T1059", "T1003", "T1082", "T1110", "T1071", "T1041"],
    category: "mitre",
  },
  mitre_id: {
    type: "mitre",
    label: "MITRE ID",
    description: "MITRE ATT&CK technique ID",
    examples: ["T1059.001", "T1059", "T1003", "T1082"],
    category: "mitre",
  },
  tactic: {
    type: "string",
    label: "Tactic",
    description: "MITRE ATT&CK tactic",
    examples: ["execution", "persistence", "credential_access", "lateral_movement", "discovery", "collection", "exfiltration", "command_and_control", "defense_evasion", "initial_access"],
    category: "mitre",
  },

  // File / Hash
  file_name: {
    type: "string",
    label: "File Name",
    description: "File name",
    examples: ["malware.exe", "suspicious.dll", "evil.ps1"],
    category: "file",
  },
  file_path: {
    type: "string",
    label: "File Path",
    description: "Full file path",
    examples: ["C:\\Windows\\Temp\\evil.exe", "C:\\Users\\admin\\malware.dll"],
    category: "file",
  },
  file_hash: {
    type: "hash",
    label: "File Hash",
    description: "File hash (MD5/SHA1/SHA256)",
    category: "file",
  },
  hash_md5: {
    type: "string",
    label: "MD5 Hash",
    description: "MD5 file hash",
    category: "file",
  },
  hash_sha1: {
    type: "string",
    label: "SHA-1 Hash",
    description: "SHA-1 file hash",
    category: "file",
  },
  hash_sha256: {
    type: "string",
    label: "SHA-256 Hash",
    description: "SHA-256 file hash",
    category: "file",
  },

  // Registry
  registry_key: {
    type: "string",
    label: "Registry Key",
    description: "Registry key path",
    examples: ["HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"],
    category: "registry",
  },
  registry_value: {
    type: "string",
    label: "Registry Value",
    description: "Registry value name",
    category: "registry",
  },

  // Network Connection / IOC
  ioc: {
    type: "string",
    label: "IOC",
    description: "Indicator of Compromise (IP, domain, URL, hash)",
    examples: ["192.168.1.10", "evil.com", "http://malware/c2", "d41d8cd98f00b204e9800998ecf8427e"],
    category: "network",
  },
  ip: {
    type: "ip",
    label: "IP Address",
    description: "IP address",
    examples: ["192.168.1.10", "10.0.0.5"],
    category: "network",
  },
  domain: {
    type: "string",
    label: "Domain",
    description: "Domain name",
    examples: ["example.com", "evil.com", "malicious-domain.org"],
    category: "network",
  },
  url: {
    type: "string",
    label: "URL",
    description: "URL",
    examples: ["http://evil.com/payload", "https://c2.example.com/beacon"],
    category: "network",
  },

  // Event metadata
  timestamp: {
    type: "datetime",
    label: "Timestamp",
    description: "Event timestamp",
    category: "metadata",
  },
  record_number: {
    type: "integer",
    label: "Record Number",
    description: "Event record number",
    category: "metadata",
  },
  event_type: {
    type: "string",
    label: "Event Type",
    description: "Type of event",
    examples: ["winlog", "sysmon", "security", "system", "application"],
    category: "metadata",
  },
  source: {
    type: "enum",
    label: "Source",
    description: "Event source",
    values: ["live", "history", "sysmon", "security", "system"],
    category: "metadata",
  },
  channel: {
    type: "string",
    label: "Channel",
    description: "Windows event log channel",
    examples: ["Security", "System", "Application", "Microsoft-Windows-Sysmon/Operational"],
    category: "metadata",
  },

  // Alert / Case
  alert_id: {
    type: "string",
    label: "Alert ID",
    description: "Alert identifier",
    category: "alert",
  },
  case_id: {
    type: "string",
    label: "Case ID",
    description: "Case identifier",
    category: "case",
  },
  priority: {
    type: "enum",
    label: "Priority",
    description: "Priority level",
    values: ["critical", "high", "medium", "low", "informational"],
    category: "alert",
  },
};

// Field aliases (alternative names that map to the canonical field)
export const FIELD_ALIASES = {
  eventid: "event_id",
  event_id: "event_id",
  event: "event_id",
  sev: "severity",
  level: "severity",
  host: "host",
  hostname: "host",
  computer: "host",
  machine: "host",
  src: "source_ip",
  src_ip: "source_ip",
  source: "source_ip",
  sourceip: "source_ip",
  source_hostname: "source_hostname",
  dst: "destination_ip",
  dst_ip: "destination_ip",
  dest: "destination_ip",
  dest_ip: "destination_ip",
  destination_hostname: "destination_hostname",
  user: "username",
  username: "username",
  user_name: "username",
  account: "username",
  actor: "username",
  proc: "process",
  process_name: "process_name",
  image: "process_name",
  exe: "process_name",
  pid: "pid",
  process_id: "pid",
  parent: "parent_process",
  parent_process: "parent_process",
  ppid: "parent_process",
  protocol: "protocol",
  proto: "protocol",
  ioc: "ioc",
  indicator: "ioc",
  ip: "ip",
  ip_address: "ip",
  srcip: "source_ip",
  dstip: "destination_ip",
  src_ip: "source_ip",
  dst_ip: "destination_ip",
  domain: "domain",
  url: "url",
  file: "file_name",
  file_name: "file_name",
  file_path: "file_path",
  hash: "file_hash",
  md5: "hash_md5",
  sha1: "hash_sha1",
  sha256: "hash_sha256",
  regkey: "registry_key",
  registry_key: "registry_key",
  regvalue: "registry_value",
  registry_value: "registry_value",
  channel: "channel",
  logon_type: "logon_type",
  logon: "logon_type",
  detection: "detection",
  detection_name: "detection_name",
  rule: "rule_id",
  rule_id: "rule_id",
  category: "category",
  tactic: "tactic",
  technique: "mitre",
  mitre: "mitre",
  mitre_id: "mitre",
  mitre_tactic: "tactic",
  alert_id: "alert_id",
  case_id: "case_id",
  timestamp: "timestamp",
  time: "timestamp",
  date: "timestamp",
  record_number: "record_number",
  event_type: "event_type",
  source: "source",
  status: "status",
  priority: "priority",
  os: "operating_system",
  operating_system: "operating_system",
  os_version: "operating_system",
};

// Known fields for quick lookup
export const KNOWN_FIELDS = Object.keys(SOCRA_FIELDS);

// ───────────────────────────────────────────────────────────────
// Lexer — tokenizes the raw query string
// ───────────────────────────────────────────────────────────────
function tokenize(input) {
  const tokens = [];
  let i = 0;
  const n = input.length;

  while (i < n) {
    const ch = input[i];

    // Skip whitespace
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      i++;
      continue;
    }

    // Quoted value: "..."
    if (ch === '"') {
      let val = "";
      i++;
      while (i < n && input[i] !== '"') {
        val += input[i];
        i++;
      }
      if (i < n) i++; // skip closing quote
      tokens.push({ type: TOKEN.QUOTED, value: val });
      continue;
    }

    // Bracket range: [value TO value]
    if (ch === "[") {
      tokens.push({ type: TOKEN.LBRACKET, value: "[" });
      i++;
      continue;
    }
    if (ch === "]") {
      tokens.push({ type: TOKEN.RBRACKET, value: "]" });
      i++;
      continue;
    }

    // Multi-char operators: !=, >=, <=, IN, CONTAINS, EXISTS, AND, OR, NOT, TO
    const remaining = input.slice(i);
    const multiCharOps = ["!=", ">=", "<=", "IN", "CONTAINS", "EXISTS", "AND", "OR", "NOT", "TO"];
    let matchedMulti = false;
    for (const op of multiCharOps) {
      if (remaining.toUpperCase().startsWith(op) && (remaining.length === op.length || /[\s\]()]/.test(remaining[op.length]))) {
        tokens.push({ type: TOKEN.OPERATOR, value: op.toUpperCase() });
        i += op.length;
        matchedMulti = true;
        break;
      }
    }
    if (matchedMulti) continue;

    // Single-char operators: : = > <
    if (ch === ":" || ch === "=" || ch === ">" || ch === "<") {
      tokens.push({ type: TOKEN.OPERATOR, value: ch });
      i++;
      continue;
    }

    // Field:value pattern: word followed by :
    const fieldMatch = remaining.match(/^(\w+):/);
    if (fieldMatch) {
      tokens.push({ type: TOKEN.FIELD, value: fieldMatch[1].toLowerCase() });
      tokens.push({ type: TOKEN.OPERATOR, value: ":" });
      i += fieldMatch[0].length;
      continue;
    }

    // word
    const wordMatch = remaining.match(/^([^\s:<>=\[\]()]+)/);
    if (wordMatch) {
      tokens.push({ type: TOKEN.VALUE, value: wordMatch[1] });
      i += wordMatch[1].length;
      continue;
    }

    // Unknown char — skip
    i++;
  }

  tokens.push({ type: TOKEN.EOF });
  return tokens;
}

// ───────────────────────────────────────────────────────────────
// Parser — builds AST from tokens
// ───────────────────────────────────────────────────────────────
function parseTokens(tokens) {
  let pos = 0;

  function peek() {
    return tokens[pos] || { type: TOKEN.EOF };
  }

  function consume(expectedType) {
    const tok = tokens[pos];
    if (expectedType && tok.type !== expectedType) return null;
    pos++;
    return tok;
  }

  function parsePrimary() {
    const tok = peek();

    if (tok.type === TOKEN.FIELD) {
      const fieldTok = consume(TOKEN.FIELD);
      const opTok = consume(TOKEN.OPERATOR);
      const field = normalizeField(fieldTok.value);
      const operator = opTok ? opTok.value : ":";

      // [value TO value] range
      if (peek().type === TOKEN.LBRACKET) {
        consume(TOKEN.LBRACKET);
        const fromTok = consume(TOKEN.VALUE);
        const toTok = consume(); // TO
        const toValTok = consume(TOKEN.VALUE);
        consume(TOKEN.RBRACKET);
        return {
          type: "FieldOp",
          field,
          operator: "[]",
          value: { from: fromTok?.value || "", to: toValTok?.value || "" },
        };
      }

      // Value
      let valueTok = null;
      if (peek().type === TOKEN.QUOTED) {
        valueTok = consume(TOKEN.QUOTED);
      } else if (peek().type === TOKEN.VALUE) {
        valueTok = consume(TOKEN.VALUE);
      }

      return {
        type: "FieldOp",
        field,
        operator,
        value: valueTok ? valueTok.value : "",
      };
    }

    if (tok.type === TOKEN.VALUE) {
      const val = consume(TOKEN.VALUE);
      return { type: "Value", raw: val.value };
    }

    if (tok.type === TOKEN.QUOTED) {
      const val = consume(TOKEN.QUOTED);
      return { type: "Value", raw: val.value, quoted: true };
    }

    return null;
  }

  function parseNot() {
    if (peek().type === TOKEN.OPERATOR && peek().value === "NOT") {
      consume(TOKEN.OPERATOR);
      const operand = parseNot() || parsePrimary();
      return { type: "UnaryOp", op: "NOT", operand };
    }
    return parsePrimary();
  }

  function parseAnd() {
    let left = parseNot();
    while (peek().type === TOKEN.OPERATOR && peek().value === "AND") {
      consume(TOKEN.OPERATOR);
      const right = parseNot();
      left = { type: "BinaryOp", op: "AND", left, right };
    }
    return left;
  }

  function parseOr() {
    let left = parseAnd();
    while (peek().type === TOKEN.OPERATOR && peek().value === "OR") {
      consume(TOKEN.OPERATOR);
      const right = parseAnd();
      left = { type: "BinaryOp", op: "OR", left, right };
    }
    return left;
  }

  const ast = parseOr();
  return ast;
}

function normalizeField(field) {
  return FIELD_ALIASES[field.toLowerCase()] || field.toLowerCase();
}

// ───────────────────────────────────────────────────────────────
// Public API: parse(query) → AST
// ───────────────────────────────────────────────────────────────
export function parseQuery(query) {
  if (!query || typeof query !== "string" || !query.trim()) {
    return { type: "Value", raw: "" };
  }
  const tokens = tokenize(query.trim());
  const ast = parseTokens(tokens);
  return ast || { type: "Value", raw: query.trim() };
}

// ───────────────────────────────────────────────────────────────
// Public API: validate(ast) → { valid, errors[] }
// ───────────────────────────────────────────────────────────────
export function validateQuery(ast) {
  const errors = [];

  function walk(node) {
    if (!node) return;
    if (node.type === "FieldOp") {
      const field = node.field;
      if (!KNOWN_FIELDS.includes(field)) {
        const suggestion = findClosestField(field);
        errors.push({
          type: "unknown_field",
          field: node.field,
          message: `Unknown field "${node.field}"`,
          suggestion: suggestion ? `Did you mean "${suggestion}"?` : null,
        });
      }
      if (node.operator === ">" || node.operator === "<" || node.operator === ">=" || node.operator === "<=") {
        if (SOCRA_FIELDS[field] && !["integer", "datetime"].includes(SOCRA_FIELDS[field].type)) {
          errors.push({
            type: "invalid_operator",
            field: node.field,
            operator: node.operator,
            message: `Operator "${node.operator}" not valid for field "${field}" (type: ${SOCRA_FIELDS[field].type})`,
          });
        }
      }
    }
    if (node.type === "BinaryOp") {
      walk(node.left);
      walk(node.right);
    }
    if (node.type === "UnaryOp") {
      walk(node.operand);
    }
  }

  walk(ast);
  return { valid: errors.length === 0, errors };
}

function findClosestField(field) {
  let best = null;
  let bestDist = Infinity;
  for (const f of KNOWN_FIELDS) {
    const dist = levenshtein(field.toLowerCase(), f);
    if (dist < bestDist && dist <= 2) {
      bestDist = dist;
      best = f;
    }
  }
  return best;
}

function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

// ───────────────────────────────────────────────────────────────
// Public API: getAutocompleteSuggestions(query, cursorPos)
// Returns context-aware suggestions based on what the user is typing
// ───────────────────────────────────────────────────────────────
export function getAutocompleteSuggestions(query, cursorPos) {
  if (!query || cursorPos === 0) {
    return {
      type: "fields",
      items: Object.entries(SOCRA_FIELDS).map(([key, def]) => ({
        value: `${key}:`,
        label: key,
        type: def.type,
        description: def.description,
        category: def.category,
      })),
    };
  }

  const prefix = query.slice(0, cursorPos);
  const lastSpace = prefix.lastIndexOf(" ");
  const lastColon = prefix.lastIndexOf(":");
  const lastBracket = prefix.lastIndexOf("[");

  // If cursor is inside a bracket range [value TO
  if (lastBracket > lastSpace && lastBracket > lastColon) {
    return { type: "range", items: [] };
  }

  // Field:value context
  if (lastColon > lastSpace) {
    const fieldPart = prefix.slice(lastSpace + 1, lastColon).trim();
    const valuePart = prefix.slice(lastColon + 1);
    const canonicalField = normalizeField(fieldPart);

    if (valuePart.trim() === "") {
      // Show all values for this field
      const fieldDef = SOCRA_FIELDS[canonicalField];
      if (fieldDef && fieldDef.values) {
        return {
          type: "values",
          field: canonicalField,
          items: fieldDef.values.map((v) => ({ value: v, label: v, description: `${canonicalField} value` })),
        };
      }
      // Fallback to field suggestions
      return {
        type: "fields",
        items: Object.entries(SOCRA_FIELDS).map(([key, def]) => ({
          value: `${key}:`,
          label: key,
          type: def.type,
          description: def.description,
          category: def.category,
        })),
      };
    }

    // Value autocomplete with prefix matching
    const fieldDef = SOCRA_FIELDS[canonicalField];
    if (fieldDef && fieldDef.examples) {
      const matching = fieldDef.examples.filter((ex) => ex.toLowerCase().startsWith(valuePart.toLowerCase()));
      if (matching.length > 0) {
        return {
          type: "values",
          field: canonicalField,
          items: matching.map((v) => ({ value: v, label: v, description: `${canonicalField} value` })),
        };
      }
    }
    if (fieldDef && fieldDef.values) {
      const matching = fieldDef.values.filter((v) => v.startsWith(valuePart.toLowerCase()));
      if (matching.length > 0) {
        return {
          type: "values",
          field: canonicalField,
          items: matching.map((v) => ({ value: v, label: v, description: `${canonicalField} value` })),
        };
      }
    }
  }

  // Otherwise suggest fields
  const lastToken = prefix.trim().split(/\s+/).pop() || "";
  const fieldMatches = Object.entries(SOCRA_FIELDS).filter(([key]) =>
    key.toLowerCase().startsWith(lastToken.toLowerCase())
  );

  return {
    type: "fields",
    items: fieldMatches.map(([key, def]) => ({
      value: `${key}:`,
      label: key,
      type: def.type,
      description: def.description,
      category: def.category,
    })),
  };
}

// ───────────────────────────────────────────────────────────────
// Public API: formatQuery(ast) → string
// ───────────────────────────────────────────────────────────────
export function formatQuery(ast) {
  if (!ast) return "";
  if (ast.type === "Value") return ast.raw || "";
  if (ast.type === "FieldOp") {
    const val = ast.value;
    if (typeof val === "object" && val.from && val.to) {
      return `${ast.field}${ast.operator}[${val.from} TO ${val.to}]`;
    }
    return `${ast.field}${ast.operator}${val}`;
  }
  if (ast.type === "BinaryOp") {
    return `(${formatQuery(ast.left)} ${ast.op} ${formatQuery(ast.right)})`;
  }
  if (ast.type === "UnaryOp") {
    return `NOT ${formatQuery(ast.operand)}`;
  }
  return "";
}

// ───────────────────────────────────────────────────────────────
// Public API: queryToBackend(query) → structured object
// Converts raw query into a structured representation for backend
// ───────────────────────────────────────────────────────────────
export function queryToBackend(query) {
  const ast = parseQuery(query);
  const validation = validateQuery(ast);
  const tokens = extractTokens(ast);

  return {
    raw_query: query,
    parsed_query: ast,
    formatted_query: formatQuery(ast),
    tokens,
    filters: extractFilters(ast),
    validation,
  };
}

function extractTokens(ast) {
  const tokens = {};
  function walk(node) {
    if (!node) return;
    if (node.type === "FieldOp") {
      tokens[node.field] = node.value;
    }
    if (node.type === "BinaryOp") {
      walk(node.left);
      walk(node.right);
    }
    if (node.type === "UnaryOp") {
      walk(node.operand);
    }
  }
  walk(ast);
  return tokens;
}

function extractFilters(ast) {
  const filters = [];
  function walk(node) {
    if (!node) return;
    if (node.type === "FieldOp") {
      filters.push({ field: node.field, operator: node.operator, value: node.value });
    }
    if (node.type === "BinaryOp") {
      walk(node.left);
      walk(node.right);
    }
    if (node.type === "UnaryOp") {
      walk(node.operand);
    }
  }
  walk(ast);
  return filters;
}

// ───────────────────────────────────────────────────────────────
// Public API: suggestFields(prefix) → matching fields
// ───────────────────────────────────────────────────────────────
export function suggestFields(prefix) {
  if (!prefix) return Object.entries(SOCRA_FIELDS);
  const p = prefix.toLowerCase();
  return Object.entries(SOCRA_FIELDS).filter(([key]) => key.startsWith(p));
}

// ───────────────────────────────────────────────────────────────
// Public API: suggestValues(field, prefix) → matching values
// ───────────────────────────────────────────────────────────────
export function suggestValues(field, prefix) {
  const fieldDef = SOCRA_FIELDS[field];
  if (!fieldDef) return [];
  const p = prefix.toLowerCase();
  const results = [];
  if (fieldDef.values) {
    results.push(...fieldDef.values.filter((v) => v.startsWith(p)));
  }
  if (fieldDef.examples) {
    results.push(...fieldDef.examples.filter((v) => v.toLowerCase().startsWith(p)));
  }
  return [...new Set(results)];
}

// ───────────────────────────────────────────────────────────────
// Public API: useAutocomplete(query, onSelect)
// React hook for debounced autocomplete suggestions
// ───────────────────────────────────────────────────────────────
export function useAutocomplete(query, onSelect) {
  const [suggestions, setSuggestions] = useState([]);
  const [activeIndex, setActiveIndex] = useState(-1);
  const [loading, setLoading] = useState(false);
  const timerRef = useRef(null);

  const updateSuggestions = useCallback((text, cursorPos) => {
    if (!text.trim()) {
      setSuggestions([]);
      setActiveIndex(-1);
      return;
    }
    setLoading(true);
    try {
      const result = getAutocompleteSuggestions(text, cursorPos ?? text.length);
      const items = (result.items || []).slice(0, 8);
      setSuggestions(items);
      setActiveIndex(items.length > 0 ? 0 : -1);
    } catch {
      setSuggestions([]);
      setActiveIndex(-1);
    } finally {
      setLoading(false);
    }
  }, []);

  const debouncedUpdate = useCallback((text, cursorPos) => {
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => {
      updateSuggestions(text, cursorPos);
    }, 120);
  }, [updateSuggestions]);

  const clearSuggestions = useCallback(() => {
    setSuggestions([]);
    setActiveIndex(-1);
    if (timerRef.current) clearTimeout(timerRef.current);
  }, []);

  const selectSuggestion = useCallback((item) => {
    if (!item) return;
    onSelect?.(item);
    clearSuggestions();
  }, [onSelect, clearSuggestions]);

  const handleKeyDown = useCallback((e, currentQuery) => {
    if (suggestions.length === 0) return false;
    switch (e.key) {
      case "ArrowDown":
        e.preventDefault();
        setActiveIndex((prev) => Math.min(prev + 1, suggestions.length - 1));
        return true;
      case "ArrowUp":
        e.preventDefault();
        setActiveIndex((prev) => Math.max(prev - 1, 0));
        return true;
      case "Enter":
        e.preventDefault();
        if (activeIndex >= 0 && suggestions[activeIndex]) {
          selectSuggestion(suggestions[activeIndex]);
          return true;
        }
        return false;
      case "Tab":
        if (activeIndex >= 0 && suggestions[activeIndex]) {
          e.preventDefault();
          selectSuggestion(suggestions[activeIndex]);
          return true;
        }
        return false;
      case "Escape":
        clearSuggestions();
        return true;
      default:
        return false;
    }
  }, [suggestions, activeIndex, selectSuggestion, clearSuggestions]);

  return {
    suggestions,
    activeIndex,
    loading,
    setActiveIndex,
    handleKeyDown,
    debouncedUpdate,
    clearSuggestions,
    selectSuggestion,
  };
}