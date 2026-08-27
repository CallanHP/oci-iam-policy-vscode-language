import assert from "node:assert/strict";
import test from "node:test";
import { splitStatements, statementDiagnostic, statementDiagnostics } from "../src/document";
import { parsePolicyStatement } from "../src/policy";
import { statementQuickFix, uniqueVocabularyCorrection } from "../src/quick-fixes";

function quickFix(source: string) {
  const span = splitStatements(source)[0];
  const diagnostic = statementDiagnostic(span);
  assert.ok(diagnostic, "expected parser diagnostic");
  const fix = statementQuickFix(span, diagnostic);
  assert.ok(fix, `expected quick fix for ${diagnostic.message}`);
  const result = source.slice(0, span.start + fix.offset) + fix.text + source.slice(span.start + fix.offset + fix.length);
  return { diagnostic, fix, result };
}

function assertValid(source: string): void { assert.ok(parsePolicyStatement(source).statement, source); }

test("offers conservative typo replacements for parser-enumerated vocabularies", () => {
  const cases = [
    ["allaw group admins to read buckets in tenancy", "allow"],
    ["allow grop admins to read buckets in tenancy", "group"],
    ["allow gruop admins to read buckets in tenancy", "group"],
    ["allow group admins to reed buckets in tenancy", "read"],
    ["allow group admins to read buckets in compartmnt test", "compartment"],
    ["allow group admins to associate dns-zons in compartment test with dns-zones in tenancy", "dns-zones"],
    ["allow group admins to associate dns-zones in compartment test with dns-znes in tenancy", "dns-zones"],
    ["allow group admins to associate dns-zones in compartment test with dns-zones in tenanc", "tenancy"],
  ] as const;
  for (const [source, expected] of cases) {
    const { fix, result } = quickFix(source);
    assert.equal(fix.text, expected);
    assertValid(result);
  }
});

test("removes only invalid id modifiers and quotes only diagnosed list members", () => {
  for (const source of [
    "allow group id invalid-group to read buckets in tenancy",
    "allow group admins to read buckets in compartment id invalid-compartment",
  ]) {
    const { fix, result } = quickFix(source);
    assert.equal(fix.title, "Remove 'id'");
    assert.equal(fix.text, "");
    assert.doesNotMatch(result, /\bid\b/);
    assertValid(result);
  }
  const source = "allow group 'Default'/'admins' to read buckets in tenancy where request.operation in ('list', get)";
  const { fix, result } = quickFix(source);
  assert.equal(fix.title, "Add single quotes");
  assert.match(result, /\('list', 'get'\)/);
  assertValid(result);
});

test("offers quick fixes for poor-practice warnings", () => {
  const cases = [
    ["allow group admins to read buckets in tenancy", "oci-iam.fix.add-default-domain", "allow group 'Default'/'admins' to read buckets in tenancy"],
    ["allow group admins to read buckets in tenancy", "oci-iam.fix.quote-principal", "allow group 'admins' to read buckets in tenancy"],
    ["allow group 'domain/admins' to read buckets in tenancy", "oci-iam.fix.split-quoted-principal", "allow group 'domain'/'admins' to read buckets in tenancy"],
    ["allow group 'Default'/'admins' to read buckets in tenancy where request.operation = get", "oci-iam.fix.quote-comparison-value", "allow group 'Default'/'admins' to read buckets in tenancy where request.operation = 'get'"],
  ] as const;
  for (const [source, code, expected] of cases) {
    const span = splitStatements(source)[0];
    const diagnostic = statementDiagnostics(span).find((item) => item.code === code);
    assert.ok(diagnostic, code);
    const fix = statementQuickFix(span, diagnostic);
    assert.ok(fix, code);
    const result = source.slice(0, fix.offset) + fix.text + source.slice(fix.offset + fix.length);
    assert.equal(result, expected);
    assertValid(result);
  }
});

test("inserts only explicit missing keywords at the parser insertion point", () => {
  const cases = [
    ["allow group admins to read buckets compartment test", "Insert 'in'", "allow group admins to read buckets in compartment test"],
    ["allow group admins to associate dns-zones in compartment test dns-zones in tenancy", "Insert 'with'", "allow group admins to associate dns-zones in compartment test with dns-zones in tenancy"],
    ["define group admins ocid1.group.oc1..admins", "Insert 'as'", "define group admins as ocid1.group.oc1..admins"],
  ] as const;
  for (const [source, title, expected] of cases) {
    const { fix, result } = quickFix(source);
    assert.equal(fix.title, title);
    assert.equal(result, expected);
    assertValid(result);
  }
});

test("suppresses ambiguous, distant, stale, and unrelated diagnostics", () => {
  assert.equal(uniqueVocabularyCorrection("red", ["read", "reed"]), undefined, "equally-close vocabulary values are ambiguous");
  const span = splitStatements("allow group admins to rad buckets in tenancy")[0];
  const diagnostic = statementDiagnostic(span);
  assert.ok(diagnostic);
  assert.equal(statementQuickFix(span, { ...diagnostic, code: undefined }), undefined, "diagnostics without a stable parser code are ignored");
  const distant = splitStatements("allow group admins to catalog buckets in tenancy")[0];
  const distantDiagnostic = statementDiagnostic(distant);
  assert.ok(distantDiagnostic);
  assert.equal(statementQuickFix(distant, distantDiagnostic), undefined);
  assert.equal(statementQuickFix(span, { ...diagnostic, message: "unrelated", code: "oci-iam.fix.verb" }), undefined);
  assert.equal(statementQuickFix(span, { ...diagnostic, offset: diagnostic.offset + 1 }), undefined);
  const unsafe = splitStatements("allow group id invalid-group extra to read buckets in tenancy")[0];
  const unsafeDiagnostic = statementDiagnostic(unsafe);
  assert.ok(unsafeDiagnostic);
  assert.equal(statementQuickFix(unsafe, unsafeDiagnostic), undefined, "edits that do not reparse are suppressed");
});
