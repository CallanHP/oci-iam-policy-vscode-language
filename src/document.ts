/** Document splitting and safe formatting for OCI IAM policy editor documents. */
import { formatPolicyStatement, parsePolicyStatement, PolicySyntaxError } from "./policy";

export interface StatementSpan { start: number; end: number; text: string; }

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

/** Split policy documents according to the documented one-line-or-logical-block format. */
export function splitStatements(text: string): StatementSpan[] {
  const lines = documentLines(text);
  const spans: StatementSpan[] = []; let start: number | undefined; let depth = 0; let quote = false; let regex = false; let escaped = false;
  const flush = (end: number): void => { if (start === undefined) return; const source = text.slice(lines[start].start, end); if (source.trim()) spans.push({ start: lines[start].start, end, text: source }); start = undefined; depth = 0; quote = false; regex = false; escaped = false; };
  for (let line = 0; line < lines.length; line += 1) {
    const current = lines[line];
    const trimmed = current.text.trim(); if (start === undefined) { if (!trimmed) continue; start = line; }
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
    const statement = parsePolicyStatement(span.text);
    if (statement.condition?.kind !== "logical") return undefined;
  } catch {
    return undefined;
  }
  // Newlines delimit statements and blank lines are valid document layout.
  // Only spaces or tabs immediately before the line ending are suspicious.
  return /[ \t]+$/.exec(span.text)?.[0];
}

/** Format valid statements only, preserving all invalid source exactly. */
export function formatDocument(text: string): string {
  const spans = splitStatements(text); let result = ""; let cursor = 0;
  for (const span of spans) { result += text.slice(cursor, span.start); try { result += formatPolicyStatement(parsePolicyStatement(span.text)); } catch (error) { result += span.text; } cursor = span.end; }
  return result + text.slice(cursor);
}

export function statementError(span: StatementSpan): string | undefined { try { parsePolicyStatement(span.text); return undefined; } catch (error) { return error instanceof PolicySyntaxError ? error.message : "unexpected parser error"; } }
