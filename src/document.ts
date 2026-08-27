/** Document splitting and safe formatting for OCI IAM policy editor documents. */
import { formatPolicyStatement, parsePolicyStatement, PolicyDiagnostic } from "./policy";

export interface StatementSpan { start: number; end: number; text: string; }
export interface StatementDiagnostic extends PolicyDiagnostic { code?: string; }

/** Stable internal codes for parser diagnostics that can safely be corrected. */
export function parserQuickFixCode(message: string): string | undefined {
  const codes: Record<string, string> = {
    "Invalid policy statement type; expected allow, deny, endorse, admit, or define": "oci-iam.fix.statement-type",
    "Invalid principal type; expected group, dynamic-group, tenancy, service, any-user, or any-group": "oci-iam.fix.principal-type",
    "Invalid policy verb; expected inspect, read, use, manage, or associate": "oci-iam.fix.verb",
    "Invalid location type; expected compartment or tenancy": "oci-iam.fix.location-type",
    "Invalid resource for associate; expected local-peering-gateways, dns-zones, dns-views, dns-resolver, or dns-records": "oci-iam.fix.associate-resource",
    "Invalid associated resource; expected local-peering-gateways, dns-zones, dns-views, dns-resolver, or dns-records": "oci-iam.fix.associated-resource",
    "Invalid association location; expected compartment, tenancy, or any-tenancy": "oci-iam.fix.association-location",
    "Invalid OCID for a principal specified by 'id'": "oci-iam.fix.remove-principal-id",
    "Invalid OCID for a location specified by 'id'": "oci-iam.fix.remove-location-id",
    "List values should be enclosed in single quotes": "oci-iam.fix.quote-list-member",
    "Group and dynamic-group names without an identity domain are assumed to be part of the Default identity domain. It is recommended to specify this explicitly.": "oci-iam.fix.add-default-domain",
    "Group and dynamic-group names should be enclosed in single quotes": "oci-iam.fix.quote-principal",
    "A quoted group or dynamic-group name is treated as a literal group name in the Default identity domain. Did you mean to specify a domain/group pairing?": "oci-iam.fix.split-quoted-principal",
    "Unquoted condition values are treated as variables; enclose literal values for comparison in single quotes": "oci-iam.fix.quote-comparison-value",
    "Expected a location beginning with 'in'": "oci-iam.fix.insert-in",
    "Expected an association after 'with'": "oci-iam.fix.insert-with",
    "Expected 'as' before the define OCID": "oci-iam.fix.insert-as",
  };
  return codes[message];
}

interface DocumentLine { start: number; contentEnd: number; text: string; }

/** Return lines with offsets that preserve LF and CRLF widths exactly. */
function documentLines(text: string): DocumentLine[] {
  const lines: DocumentLine[] = [];
  let start = 0;
  while (start < text.length) {
    const newline = text.indexOf("\n", start);
    const lineEnd = newline < 0 ? text.length : newline;
    const contentEnd = lineEnd > start && text[lineEnd - 1] === "\r" ? lineEnd - 1 : lineEnd;
    lines.push({ start, contentEnd, text: text.slice(start, contentEnd) });
    if (newline < 0) break;
    start = newline + 1;
  }
  return lines;
}

/** Return the last line of a standalone block comment, or the document end if it is unterminated. */
function standaloneBlockCommentEnd(lines: DocumentLine[], line: number): number | undefined {
  const first = lines[line].text.trimStart();
  if (!first.startsWith("/*")) return undefined;
  for (let index = line; index < lines.length; index += 1) {
    const from = index === line ? lines[index].text.indexOf("/*") + 2 : 0;
    const close = lines[index].text.indexOf("*/", from);
    if (close < 0) continue;
    return lines[index].text.slice(close + 2).trim() ? undefined : index;
  }
  return lines.length - 1;
}

/** Split policy documents according to the documented one-line-or-logical-block format. */
export function splitStatements(text: string): StatementSpan[] {
  const lines = documentLines(text);
  const spans: StatementSpan[] = []; let start: number | undefined; let depth = 0; let quote = false; let regex = false; let escaped = false;
  const flush = (end: number): void => { if (start === undefined) return; const source = text.slice(lines[start].start, end); if (source.trim()) spans.push({ start: lines[start].start, end, text: source }); start = undefined; depth = 0; quote = false; regex = false; escaped = false; };
  for (let line = 0; line < lines.length; line += 1) {
    const current = lines[line];
    const trimmed = current.text.trim();
    if (start === undefined) {
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//")) continue;
      const blockEnd = standaloneBlockCommentEnd(lines, line);
      if (blockEnd !== undefined) { line = blockEnd; continue; }
      start = line;
    }
    for (let column = 0; column < current.text.length; column += 1) {
      const c = current.text[column];
      if (escaped) { escaped = false; continue; }
      if (c === "\\" && (quote || regex)) { escaped = true; continue; }
      if (c === "'" && !regex) quote = !quote;
      else if (c === "/" && !quote && (regex || /[=!]/.test(current.text.slice(0, column).trimEnd().slice(-1)))) regex = !regex;
      else if (!quote && !regex) { if (c === "{") depth += 1; else if (c === "}") depth -= 1; }
    }
    if (depth <= 0 && !quote && !regex) flush(current.contentEnd);
  }
  flush(text.length); return spans;
}

/** Return the horizontal whitespace after a logical condition's closing brace. */
export function logicalTrailingWhitespace(span: StatementSpan): string | undefined {
  try {
    const diagnostic = parsePolicyStatement(span.text).diagnostics.find((item) => item.severity === "warning" && item.message === "logical condition has trailing whitespace before its line ending");
    return diagnostic ? span.text.slice(diagnostic.offset, diagnostic.offset + diagnostic.length) : undefined;
  } catch {
    return undefined;
  }
}

/** Format valid statements only, preserving all invalid source exactly. */
export function formatDocument(text: string): string {
  const spans = splitStatements(text); let result = ""; let cursor = 0;
  for (const span of spans) {
    result += text.slice(cursor, span.start);
    try {
      const parsed = parsePolicyStatement(span.text);
      result += parsed.statement ? formatPolicyStatement(parsed.statement) : span.text;
    } catch {
      result += span.text;
    }
    cursor = span.end;
  }
  return result + text.slice(cursor);
}

/** Return every parser diagnostic for a statement span. */
export function statementDiagnostics(span: StatementSpan): StatementDiagnostic[] {
  try {
    return parsePolicyStatement(span.text).diagnostics.map((diagnostic) => ({
      ...diagnostic,
      code: parserQuickFixCode(diagnostic.message),
    }));
  } catch {
    // Keep diagnostics safe even if a future parser bug escapes its normal error path.
    return [{ severity: "error", message: "unexpected parser error", offset: span.text.length, length: 0 }];
  }
}

/** Compatibility helper for callers that expect at most one diagnostic. */
export function statementDiagnostic(span: StatementSpan): StatementDiagnostic | undefined { return statementDiagnostics(span)[0]; }

/** Compatibility helper for non-diagnostic callers. */
export function statementError(span: StatementSpan): string | undefined { return statementDiagnostics(span).find((item) => item.severity === "error")?.message; }
