import assert from "node:assert/strict";
import test from "node:test";
import { formatDocument, logicalTrailingWhitespace, splitStatements, statementError } from "../src/document";
import { formatPolicyStatement, parsePolicyStatement, PolicySyntaxError } from "../src/policy";

test("parses and canonicalizes supported statement shapes", () => {
  const cases = [
    ["ALLOW group Admins to READ buckets in tenancy", "allow group 'Admins' to read buckets in tenancy"],
    ["allow dynamic-group id ocid1.dynamicgroup.oc1..workers to {object_read, object_write} in tenancy where request.name = 'Value'", "allow dynamic-group id ocid1.dynamicgroup.oc1..workers to {OBJECT_READ, OBJECT_WRITE} in tenancy where request.name = 'Value'"],
    ["deny service objectstorage to use keys in tenancy where request.key = /Prod\\/Key/", "deny service objectstorage to use keys in tenancy where request.key = /Prod\\/Key/"],
    ["endorse group admins to read buckets in tenancy remote where request.user = target.user", "endorse group 'admins' to read buckets in tenancy remote where request.user = target.user"],
    ["admit any-user to manage all-resources in tenancy where request.operation in ('Create', 'Delete')", "admit any-user to manage all-resources in tenancy where request.operation in ( 'Create', 'Delete' )"],
    ["define group admins as ocid1.group.oc1..admins", "define group 'admins' as ocid1.group.oc1..admins"],
    ["allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways in tenancy remote", "allow group 'admins' to associate local-peering-gateways in tenancy with local-peering-gateways in tenancy remote"]
  ] as const;
  for (const [source, expected] of cases) assert.equal(formatPolicyStatement(parsePolicyStatement(source)), expected);
});

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

test("accepts OCI key policies with multiline any conditions", () => {
  const source = [
    "allow group Administrators, automation-users to use keys in compartment onfinance where any {",
    "    target.key.id = 'ocid1.key.oc1.region.aaaaaa',",
    "    target.key.id = 'ocid1.key.oc1.region.aaaaab',",
    "    target.key.id = 'ocid1.key.oc1.region.aaaaac'",
    "}"
  ].join("\n");
  const parsed = parsePolicyStatement(source);
  assert.equal(parsed.condition?.kind, "logical");
  assert.equal((parsed.condition as { conditions: unknown[] }).conditions.length, 3);
  assert.equal(statementError(splitStatements(source)[0]), undefined);
});

test("preserves blank lines and invalid source while formatting valid statements", () => {
  const invalid = "allow group admins to audit buckets in tenancy";
  const source = `ALLOW service objectstorage to read buckets in tenancy\n\n${invalid}`;
  assert.equal(formatDocument(source), `allow service objectstorage to read buckets in tenancy\n\n${invalid}`);
});

test("splits logical blocks and reports full invalid statement errors", () => {
  const source = "allow group admins to read buckets in tenancy where all {\n  request.user.id = 'a'\n}\nallow group admins to audit buckets in tenancy";
  const spans = splitStatements(source);
  assert.equal(spans.length, 2);
  assert.equal(statementError(spans[0]), undefined);
  assert.equal(statementError(spans[1]), "invalid or missing verb");
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
  assert.equal(statementError(spans[0]), "empty logical condition member");
  assert.equal(statementError(spans[1]), undefined);
});

test("ignores blank lines after logical conditions", () => {
  const source = "allow group admins to read buckets in tenancy where any { request.user.id = 'x' }\r\n\r\nallow service objectstorage to read buckets in tenancy";
  const spans = splitStatements(source);
  assert.equal(logicalTrailingWhitespace(spans[0]), undefined);
});

test("warns on spaces before the logical condition's newline", () => {
  const source = "allow group admins to read buckets in tenancy where any { request.user.id = 'x' }   \r\nallow service objectstorage to read buckets in tenancy";
  const spans = splitStatements(source);
  assert.equal(logicalTrailingWhitespace(spans[0]), "   ");
});

test("rejects malformed conditions with parser errors", () => {
  assert.throws(() => parsePolicyStatement("allow group admins to read buckets in tenancy where any {}"), PolicySyntaxError);
  assert.throws(() => parsePolicyStatement("allow group admins to read buckets in tenancy where request.x in ('a', unquoted)"), PolicySyntaxError);
});

test("matches the Python parser's supported statement forms", () => {
  const valid = [
    "allow group admins to read buckets in tenancy",
    "deny group admins to read buckets in tenancy",
    "endorse group admins to read buckets in tenancy remote",
    "admit group admins to read buckets in tenancy",
    "define tenancy remote as ocid1.tenancy.oc1..remote",
    "allow dynamic-group workers to read buckets in tenancy",
    "allow service objectstorage to read buckets in tenancy",
    "allow any-user to read buckets in tenancy",
    "allow any-group to read buckets in tenancy",
    "allow group Admins, 'Identity Domain'/'Cloud/Operators' to read buckets in tenancy",
    "allow dynamic-group id ocid1.dynamicgroup.oc1..first, ocid1.dynamicgroup.oc1..second to use objects in tenancy",
    "admit group RemoteAdmins of tenancy Remote to read buckets in tenancy",
    "admit dynamic-group Workers of tenancy Remote to read buckets in tenancy",
    "admit any-user of tenancy Remote to read buckets in tenancy",
    "admit any-group of tenancy Remote to read buckets in tenancy",
    "allow group admins to {vcn_attach, VCN_DETACH} in tenancy",
    "admit group admins {bucket_read} in tenancy",
    "endorse group admins {bucket_read} in tenancy Remote",
    "allow group admins to read buckets in compartment Finance",
    "allow group admins to read buckets in compartment id ocid1.compartment.oc1..finance",
    "endorse group admins to read buckets in any-tenancy",
    "allow group admins to read buckets in tenancy where Request.User.Name != 'A\\'lice'",
    "allow group admins to read buckets in tenancy where target.bucket.name = /Prod\\/.*\\/Archive/",
    "allow service objectstorage to use keys in tenancy where target.key.id in ('Key, One', 'Key\\'Two')",
    "allow group admins to manage groups in tenancy where all { target.group.name != /A-Users-.*/, any { request.operation = 'AddUserToGroup', request.operation in ('CreateGroup', 'DeleteGroup') } }",
    "allow group admins to read buckets in tenancy where sets-intersect(request.groups, target.groups)",
    "allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways in tenancy Remote",
    "allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways in any-tenancy where request.x = 'value'",
    "admit group RemoteAdmins of tenancy Remote to associate dns-views in tenancy with dns-resolver in tenancy Remote",
    "endorse group requestorGrp to associate local-peering-gateways in compartment requestorComp with local-peering-gateways in tenancy Acceptor",
    "admit group requestorGrp of tenancy Requestor to associate local-peering-gateways in tenancy Requestor with local-peering-gateways in compartment acceptorComp",
    "define group Admins as ocid1.group.oc1..admins",
    "define dynamic-group Workers as ocid1.dynamicgroup.oc1..workers"
  ];
  for (const source of valid) assert.doesNotThrow(() => parsePolicyStatement(source), source);
});

test("matches the Python parser's rejected statement forms", () => {
  const invalid = [
    "", "permit group admins to read buckets in tenancy", "allow", "allow user alice to read buckets in tenancy",
    "allow group to read buckets in tenancy", "allow any-user id ocid1.group.oc1..abc to read buckets in tenancy",
    "allow service id ocid1.service.oc1..abc to read buckets in tenancy", "allow group id not-an-ocid to read buckets in tenancy",
    "allow group domain/name/extra to read buckets in tenancy", "allow tenancy Remote to read buckets in tenancy",
    "allow group ,admins to read buckets in tenancy", "allow group admins,,operators to read buckets in tenancy",
    "allow group 'admins' operators to read buckets in tenancy", "allow group 'admins\\ to read buckets in tenancy",
    "allow group RemoteAdmins of tenancy Remote to read buckets in tenancy", "endorse any-user of tenancy Remote to read buckets in tenancy Remote",
    "admit group id ocid1.group.oc1..admins of tenancy Remote to read buckets in tenancy", "admit service objectstorage of tenancy Remote to read buckets in tenancy",
    "allow group admins to audit buckets in tenancy", "allow group admins to read in tenancy", "allow group admins to associate buckets in tenancy",
    "deny group admins {VCN_ATTACH} in tenancy", "allow group admins { } in tenancy", "allow group admins {VCN_ATTACH,} in tenancy",
    "allow group admins {,VCN_ATTACH} in tenancy", "allow group admins {VCN_ATTACH,,VCN_DETACH} in tenancy", "allow group admins {VCN ATTACH} in tenancy",
    "allow group admins {VCN_ATTACH in tenancy", "allow group admins to read buckets", "allow group admins to read buckets in",
    "allow group admins to read buckets in bucket finance", "allow group admins to read buckets in compartment where request.x = 'x'",
    "allow group admins to read buckets in compartment id invalid", "allow group admins to read buckets in any-tenancy",
    "endorse group admins to read buckets in tenancy where request.x = 'x'", "allow group admins to read buckets in tenancy unexpected",
    "allow group admins to read buckets in tenancy where", "allow group admins to read buckets in tenancy where request.x is 'value'",
    "allow group admins to read buckets in tenancy where = 'value'", "allow group admins to read buckets in tenancy where request.x in 'value'",
    "allow group admins to read buckets in tenancy where request.x in ()", "allow group admins to read buckets in tenancy where request.x in ('value', unquoted)",
    "allow group admins to read buckets in tenancy where request.x = ''", "allow group admins to read buckets in tenancy where request.x = /",
    "allow group admins to read buckets in tenancy where request.x = /value/ trailing", "allow group admins to read buckets in tenancy where request.x = 'value' trailing",
    "allow group admins to read buckets in tenancy where request.x = target value", "allow group admins to read buckets in tenancy where request.x in (, 'value')",
    "allow group admins to read buckets in tenancy where request.x in ('value',, 'other')", "allow group admins to read buckets in tenancy where any request.x = 'value'",
    "allow group admins to read buckets in tenancy where any {}", "allow group admins to read buckets in tenancy where all { request.x = 'value', }",
    "allow group admins to read buckets in tenancy where all { request.x = 'value'", "allow group admins to read buckets in tenancy where sets-intersect(request.x, target.x, extra)",
    "allow group admins to associate local-peering-gateways in tenancy", "allow group admins to associate local-peering-gateways in tenancy with buckets in tenancy Remote",
    "allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways", "allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways in group Remote",
    "allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways in tenancy where request.x = 'value'",
    "allow group admins to associate dns-views in tenancy with local-peering-gateways in tenancy Remote", "allow group admins to associate local-peering-gateways in tenancy with dns-views in tenancy Remote",
    "define service objectstorage as ocid1.service.oc1..objectstorage", "define tenancy Remote as", "define tenancy Remote as invalid",
    "define tenancy Remote as ocid1.tenancy.oc1..one ocid1.tenancy.oc1..two", "define tenancy one,two as ocid1.tenancy.oc1..remote"
  ];
  for (const source of invalid) assert.throws(() => parsePolicyStatement(source), PolicySyntaxError, source);
});
