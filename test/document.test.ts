import assert from "node:assert/strict";
import test from "node:test";
import { formatDocument, logicalTrailingWhitespace, splitStatements, statementDiagnostic, statementDiagnostics, statementError } from "../src/document";

test("formats logical conditions with readable nested indentation", () => {
  const source = "allow group admins to read buckets in tenancy where all { request.user.id = 'abc', any { target.bucket.name = 'logs', target.bucket.name = 'archive' } }";
  assert.equal(formatDocument(source), [
    "allow group 'admins' to read buckets in tenancy where all {",
    "  request.user.id = 'abc',",
    "  any {",
    "    target.bucket.name = 'logs',",
    "    target.bucket.name = 'archive'",
    "  }",
    "}"
  ].join("\n"));
});

test("preserves blank lines and invalid source while formatting valid statements", () => {
  const invalid = "allow group admins to audit buckets in tenancy";
  const source = `ALLOW service objectstorage to read buckets in tenancy\n\n${invalid}`;
  assert.equal(formatDocument(source), `allow service objectstorage to read buckets in tenancy\n\n${invalid}`);
});

test("ignores standalone comments between statements and preserves them while formatting", () => {
  const source = [
    "  # administrators can read buckets",
    "ALLOW group Admins to READ buckets in tenancy",
    "// object storage access",
    "/* this comment",
    "   spans multiple lines */",
    "allow service objectstorage to use objects in tenancy",
  ].join("\r\n");
  const spans = splitStatements(source);
  assert.equal(spans.length, 2);
  assert.equal(statementError(spans[0]), undefined);
  assert.equal(statementError(spans[1]), undefined);
  assert.equal(formatDocument(source), [
    "  # administrators can read buckets",
    "allow group 'Admins' to read buckets in tenancy",
    "// object storage access",
    "/* this comment",
    "   spans multiple lines */",
    "allow service objectstorage to use objects in tenancy",
  ].join("\r\n"));
});

test("does not accept trailing comments or comments within logical conditions", () => {
  const trailing = splitStatements("allow group admins to read buckets in tenancy // note")[0];
  assert.ok(statementError(trailing));
  const sharedLine = splitStatements("/* note */ allow group admins to read buckets in tenancy")[0];
  assert.ok(statementError(sharedLine));
  const logical = splitStatements([
    "allow group admins to read buckets in tenancy where any {",
    "  # only the approved request",
    "  request.user.id = 'x'",
    "}",
  ].join("\n"))[0];
  assert.ok(statementError(logical));
});

test("treats an unterminated standalone block comment as extending to end of document", () => {
  const source = "/* pending policy notes\nallow group admins to read buckets in tenancy";
  assert.deepEqual(splitStatements(source), []);
  assert.equal(formatDocument(source), source);
});

test("splits logical blocks and reports full invalid statement errors", () => {
  const source = "allow group admins to read buckets in tenancy where all {\n  request.user.id = 'a'\n}\nallow group admins to audit buckets in tenancy";
  const spans = splitStatements(source);
  assert.equal(spans.length, 2);
  assert.equal(statementError(spans[0]), undefined);
  assert.equal(statementError(spans[1]), "Invalid policy verb; expected inspect, read, use, manage, or associate");
});

test("handles CRLF after a logical condition before the next statement", () => {
  const source = [
    "allow group Administrators, automation-users to use keys in compartment onfinance where any {",
    "  target.key.id = 'ocid1.key.oc1.region.aaaaaa',",
    "  target.key.id = 'ocid1.key.oc1.region.aaaaab'",
    "}",
    "Allow dynamic-group 'domain'/'dynamic-group' to read secret-bundles in compartment id ocid1.compartment.oc1..aaaaaaaa"
  ].join("\r\n");
  const spans = splitStatements(source);
  assert.equal(spans.length, 2);
  assert.equal(statementError(spans[0]), undefined);
  assert.equal(statementError(spans[1]), undefined);
  assert.equal(logicalTrailingWhitespace(spans[0]), undefined);
});

test("does not merge a malformed logical condition with its following statement", () => {
  const source = [
    "allow group admins to read buckets in tenancy where any {",
    "  request.user.id = 'x',",
    "}",
    "allow service objectstorage to read buckets in tenancy"
  ].join("\r\n");
  const spans = splitStatements(source);
  assert.equal(spans.length, 2);
  assert.equal(statementError(spans[0]), "Logical condition members cannot be empty");
  assert.equal(statementError(spans[1]), undefined);
});

test("ignores blank lines after logical conditions", () => {
  const source = "allow group admins to read buckets in tenancy where any { request.user.id = 'x' }\r\n\r\nallow service objectstorage to read buckets in tenancy";
  const spans = splitStatements(source);
  assert.equal(logicalTrailingWhitespace(spans[0]), undefined);
});

test("warns on spaces before the logical condition's newline", () => {
  const source = "allow group 'Default'/'admins' to read buckets in tenancy where any { request.user.id = 'x' }   \r\nallow service objectstorage to read buckets in tenancy";
  const spans = splitStatements(source);
  assert.equal(logicalTrailingWhitespace(spans[0]), "   ");
  assert.deepEqual(statementDiagnostics(spans[0]), [{
    severity: "warning",
    message: "logical condition has trailing whitespace before its line ending",
    offset: spans[0].text.length - 3,
    length: 3,
    code: undefined,
  }]);
  assert.equal(formatDocument(source), "allow group 'Default'/'admins' to read buckets in tenancy where any {\n  request.user.id = 'x'\n}\r\nallow service objectstorage to read buckets in tenancy");
});

test("keeps parser diagnostic offsets relative to multiline and CRLF statement spans", () => {
  const source = [
    "allow group 'Default'/'admins' to read buckets in tenancy where any {",
    "  request.operation in ('listInstances', getInstance)",
    "}",
  ].join("\r\n");
  const span = splitStatements(source)[0];
  const diagnostic = statementDiagnostic(span);
  assert.ok(diagnostic);
  assert.equal(span.text.slice(diagnostic.offset, diagnostic.offset + diagnostic.length), "getInstance");
  assert.equal(source.slice(span.start + diagnostic.offset, span.start + diagnostic.offset + diagnostic.length), "getInstance");
});
