/** Conservative parser-backed quick fixes, deliberately independent of VS Code. */
import { parsePolicyStatement } from "./policy";
import { parserQuickFixCode, statementDiagnostics, StatementDiagnostic, StatementSpan } from "./document";

export interface StatementQuickFix {
  title: string;
  offset: number;
  length: number;
  text: string;
}

const vocabularies: Record<string, readonly string[]> = {
  "oci-iam.fix.statement-type": ["allow", "deny", "endorse", "admit", "define"],
  "oci-iam.fix.principal-type": ["group", "dynamic-group", "tenancy", "service", "any-user", "any-group"],
  "oci-iam.fix.verb": ["inspect", "read", "use", "manage", "associate"],
  "oci-iam.fix.location-type": ["compartment", "tenancy"],
  "oci-iam.fix.associate-resource": ["local-peering-gateways", "dns-zones", "dns-views", "dns-resolver", "dns-records"],
  "oci-iam.fix.associated-resource": ["local-peering-gateways", "dns-zones", "dns-views", "dns-resolver", "dns-records"],
  "oci-iam.fix.association-location": ["compartment", "tenancy", "any-tenancy"],
};

function distance(left: string, right: string): number {
  let previous = Array.from({ length: right.length + 1 }, (_, index) => index);
  for (let row = 1; row <= left.length; row += 1) {
    const current = [row];
    for (let column = 1; column <= right.length; column += 1) {
      current[column] = Math.min(current[column - 1] + 1, previous[column] + 1, previous[column - 1] + (left[row - 1] === right[column - 1] ? 0 : 1));
    }
    previous = current;
  }
  return previous[right.length];
}

/** Return the sole conservative vocabulary correction, if one exists. */
export function uniqueVocabularyCorrection(value: string, candidates: readonly string[]): string | undefined {
  const normalized = value.toLowerCase();
  const ranked = candidates.map((candidate) => ({ candidate, distance: distance(normalized, candidate) })).sort((a, b) => a.distance - b.distance);
  const closest = ranked[0];
  if (!closest || closest.distance > Math.max(2, Math.floor(closest.candidate.length / 3)) || ranked[1]?.distance === closest.distance) return undefined;
  return closest.candidate;
}

function isCurrent(span: StatementSpan, diagnostic: StatementDiagnostic): boolean {
  return statementDiagnostics(span).some((current) => current.severity === diagnostic.severity && current.message === diagnostic.message && current.offset === diagnostic.offset && current.length === diagnostic.length && current.code === diagnostic.code);
}

function validEdit(span: StatementSpan, fix: StatementQuickFix): boolean {
  const revised = span.text.slice(0, fix.offset) + fix.text + span.text.slice(fix.offset + fix.length);
  try { return parsePolicyStatement(revised).statement !== undefined; } catch { return false; }
}

/** Return at most one safe action for a parser diagnostic on the current statement. */
export function statementQuickFix(span: StatementSpan, diagnostic: StatementDiagnostic): StatementQuickFix | undefined {
  const code = parserQuickFixCode(diagnostic.message);
  if (!code || diagnostic.code !== code || !isCurrent(span, diagnostic)) return undefined;
  const bad = span.text.slice(diagnostic.offset, diagnostic.offset + diagnostic.length);
  let fix: StatementQuickFix | undefined;
  const vocabulary = vocabularies[code];
  if (vocabulary) {
    const replacement = uniqueVocabularyCorrection(bad, vocabulary);
    if (replacement) fix = { title: `Change to '${replacement}'`, offset: diagnostic.offset, length: diagnostic.length, text: replacement };
  } else if (code === "oci-iam.fix.remove-principal-id" || code === "oci-iam.fix.remove-location-id") {
    const id = /^id([ \t]+)/i.exec(bad);
    if (id) fix = { title: "Remove 'id'", offset: diagnostic.offset, length: id[0].length, text: "" };
  } else if (code === "oci-iam.fix.quote-list-member" && bad && !/[\\']/.test(bad)) {
    fix = { title: "Add single quotes", offset: diagnostic.offset, length: diagnostic.length, text: `'${bad}'` };
  } else if (code === "oci-iam.fix.quote-comparison-value" && bad && !/[\\']/.test(bad)) {
    fix = { title: "Add single quotes", offset: diagnostic.offset, length: diagnostic.length, text: `'${bad}'` };
  } else if (code === "oci-iam.fix.quote-principal" && bad && !/[\\']/.test(bad)) {
    fix = { title: "Add single quotes", offset: diagnostic.offset, length: diagnostic.length, text: bad.split("/").map((part) => `'${part}'`).join("/") };
  } else if (code === "oci-iam.fix.add-default-domain" && bad) {
    const name = /^'([\s\S]*)'$/.exec(bad)?.[1] ?? bad;
    if (!/[\\']/.test(name)) fix = { title: "Specify the Default identity domain", offset: diagnostic.offset, length: diagnostic.length, text: `'Default'/'${name}'` };
  } else if (code === "oci-iam.fix.split-quoted-principal") {
    const name = /^'([^'\\]+\/[^'\\]+)'$/.exec(bad)?.[1];
    if (name) fix = { title: "Specify domain and group", offset: diagnostic.offset, length: diagnostic.length, text: name.split("/").map((part) => `'${part}'`).join("/") };
  } else if (code === "oci-iam.fix.insert-in") {
    fix = { title: "Insert 'in'", offset: diagnostic.offset, length: 0, text: "in " };
  } else if (code === "oci-iam.fix.insert-with") {
    fix = { title: "Insert 'with'", offset: diagnostic.offset, length: 0, text: "with " };
  } else if (code === "oci-iam.fix.insert-as") {
    fix = { title: "Insert 'as'", offset: diagnostic.offset, length: 0, text: "as " };
  }
  return fix && validEdit(span, fix) ? fix : undefined;
}
