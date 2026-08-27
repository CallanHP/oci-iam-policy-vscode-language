import assert from "node:assert/strict";
import test from "node:test";
import { formatPolicyStatement, parseCondition, parsePolicyStatement, PolicyDiagnostic, PolicyStatement } from "../src/policy";

function valid(source: string): PolicyStatement {
  const result = parsePolicyStatement(source);
  assert.ok(result.statement, result.diagnostics.map((item) => item.message).join(", "));
  return result.statement;
}

function invalid(source: string): PolicyDiagnostic {
  const result = parsePolicyStatement(source);
  assert.equal(result.statement, undefined);
  assert.equal(result.diagnostics.length, 1);
  assert.equal(result.diagnostics[0].severity, "error");
  return result.diagnostics[0];
}

test("parses and canonicalizes supported statement shapes", () => {
  const cases = [
    ["ALLOW group Admins to READ buckets in tenancy", "allow group 'Admins' to read buckets in tenancy"],
    ["allow dynamic-group id ocid1.dynamicgroup.oc1..aaaaaa to {object_read, object_write} in tenancy where request.principal.name = 'Value'", "allow dynamic-group id ocid1.dynamicgroup.oc1..aaaaaa to {OBJECT_READ, OBJECT_WRITE} in tenancy where request.principal.name = 'Value'"],
    ["deny service objectstorage to use keys in tenancy where request.target.key = /Prod\\/Key/", "deny service objectstorage to use keys in tenancy where request.target.key = /Prod\\/Key/"],
    ["endorse group admins to read buckets in tenancy remote where request.bucket.name = request.principal.user", "endorse group 'admins' to read buckets in tenancy remote where request.bucket.name = request.principal.user"],
    ["admit any-user to manage all-resources in tenancy where request.operation in ('CreateObject', 'DeleteObject')", "admit any-user to manage all-resources in tenancy where request.operation in ( 'CreateObject', 'DeleteObject' )"],
    ["define group admins as ocid1.group.oc1..admins", "define group 'admins' as ocid1.group.oc1..admins"],
    ["allow group admins to associate local-peering-gateways in tenancy with local-peering-gateways in tenancy remote", "allow group 'admins' to associate local-peering-gateways in tenancy with local-peering-gateways in tenancy remote"]
  ] as const;
  for (const [source, expected] of cases) assert.equal(formatPolicyStatement(valid(source)), expected);
});

test("parses OCI key policies with multiline any conditions", () => {
  const source = [
    "allow group Administrators, automation-users to use keys in compartment onfinance where any {",
    "    target.key.id = 'ocid1.key.oc1.region.aaaaaa',",
    "    target.key.id = 'ocid1.key.oc1.region.aaaaab',",
    "    target.key.id = 'ocid1.key.oc1.region.aaaaac'",
    "}"
  ].join("\n");
  const parsed = valid(source);
  assert.equal(parsed.condition?.kind, "logical");
  assert.equal((parsed.condition as { conditions: unknown[] }).conditions.length, 3);
});

test("rejects malformed conditions with parser errors", () => {
  invalid("allow group admins to read buckets in tenancy where any {}");
  invalid("allow group admins to read buckets in tenancy where request.x in ('a',)");
});

test("returns condition results and only warns for top-level logical trailing whitespace", () => {
  for (const source of ["any { request.x = 'value' } \t", "any {\r\n  request.x = 'value'\r\n}  "]) {
    const result = parseCondition(source);
    assert.equal(result.condition?.kind, "logical");
    assert.deepEqual(result.diagnostics, [{
      severity: "warning",
      message: "logical condition has trailing whitespace before its line ending",
      offset: source.length - 2,
      length: 2,
    }]);
  }
  const nested = parseCondition("any { all { request.x = 'value'  } }");
  assert.deepEqual(nested.diagnostics, []);
  const unquotedMember = parseCondition("request.x in ('value', unquoted)");
  assert.deepEqual(unquotedMember.condition, { kind: "list", variable: "request.x", values: ["value", "unquoted"] });
  assert.deepEqual(unquotedMember.diagnostics, [{ severity: "warning", message: "List values should be enclosed in single quotes", offset: 23, length: 8 }]);
});

test("returns statement diagnostics with warning ranges relative to the statement source", () => {
  const source = "allow group 'Default'/'admins' to read buckets in tenancy where any { request.x = 'value' }   ";
  const result = parsePolicyStatement(source);
  assert.ok(result.statement);
  assert.deepEqual(result.diagnostics, [{
    severity: "warning",
    message: "logical condition has trailing whitespace before its line ending",
    offset: source.length - 3,
    length: 3,
  }]);
});

test("reports precise parser ranges for invalid policy constructs", () => {
  const cases = [
    ["allow group testgroup to use instances in compartment id testcompartment", "Invalid OCID for a location specified by 'id'", "id testcompartment"],
    ["allow dynamicgroup testgroup to read instances in tenancy", "Invalid principal type; expected group, dynamic-group, tenancy, service, any-user, or any-group", "dynamicgroup"],
    ["allow group id not-an-ocid to read buckets in tenancy", "Invalid OCID for a principal specified by 'id'", "id not-an-ocid"],
  ] as const;
  for (const [source, message, expected] of cases) {
    const diagnostic = invalid(source);
    assert.equal(diagnostic.message, message);
    assert.equal(source.slice(diagnostic.offset, diagnostic.offset + diagnostic.length), expected);
    assert.ok(diagnostic.offset >= 0 && diagnostic.offset + diagnostic.length <= source.length);
  }
});

test("validates literal compartment location names and paths", () => {
  const base = "allow group admins to read buckets in compartment ";
  for (const value of ["finance:accounts", "Finance_1.2-archive"]) {
    valid(base + value);
  }
  const cases = [
    ["finance/accounts", "Invalid location - compartment names can only be letters, numbers, periods, hyphens, and underscores"],
    [":finance", "Invalid compartment path."],
    ["finance:", "Invalid compartment path."],
    ["finance::accounts", "Invalid compartment path."],
  ] as const;
  for (const [value, message] of cases) {
    const diagnostic = invalid(base + value);
    assert.equal(diagnostic.message, message);
    assert.equal(diagnostic.offset, base.length);
    assert.equal(diagnostic.length, value.length);
  }
});

test("retains and warns for an unquoted nested list member", () => {
  const source = "allow group 'Default'/'admins' to read buckets in tenancy where all { request.operation in ('getInstance'), target.operation in ('getInstance', getInstance) }";
  const result = parsePolicyStatement(source);
  assert.ok(result.statement);
  const diagnostic = result.diagnostics.find((item) => item.message === "List values should be enclosed in single quotes");
  assert.ok(diagnostic);
  assert.equal(diagnostic.offset, source.lastIndexOf("getInstance"));
  assert.equal(diagnostic.length, "getInstance".length);
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
  for (const source of valid) assert.ok(parsePolicyStatement(source).statement, source);
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
    "allow group admins to read buckets in tenancy where request.x in ()",
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
  for (const source of invalid) {
    const diagnostic = parsePolicyStatement(source).diagnostics[0];
    assert.ok(diagnostic && diagnostic.severity === "error", source);
    assert.ok(Number.isInteger(diagnostic.offset) && Number.isInteger(diagnostic.length), source);
    assert.ok(diagnostic.offset >= 0 && diagnostic.offset + diagnostic.length <= source.length, source);
  }
});

test("warns about poor-practice group names only for allow and endorse", () => {
  const message = "Group and dynamic-group names without an identity domain are assumed to be part of the Default identity domain. It is recommended to specify this explicitly.";
  const quoteMessage = "Group and dynamic-group names should be enclosed in single quotes";
  for (const type of ["allow", "endorse"] as const) {
    const source = `${type} group admins to read buckets in tenancy${type === "endorse" ? " remote" : ""}`;
    const result = parsePolicyStatement(source);
    assert.ok(result.statement);
    assert.deepEqual(result.diagnostics.map((item) => item.message), [message, quoteMessage]);
    assert.deepEqual(result.diagnostics.map((item) => [item.offset, item.length]), [[source.indexOf("admins"), 6], [source.indexOf("admins"), 6]]);
  }
  for (const source of ["admit group admins to read buckets in tenancy", "define group admins as ocid1.group.oc1..admins", "allow group id ocid1.group.oc1..admins to read buckets in tenancy"]) {
    assert.deepEqual(parsePolicyStatement(source).diagnostics, []);
  }
});

test("warns about quoted literal slash names and bare comparisons", () => {
  const slash = "allow group 'domain/admins' to read buckets in tenancy";
  const slashResult = parsePolicyStatement(slash);
  assert.ok(slashResult.statement);
  assert.deepEqual(slashResult.diagnostics, [{ severity: "warning", message: "A quoted group or dynamic-group name is treated as a literal group name in the Default identity domain. Did you mean to specify a domain/group pairing?", offset: slash.indexOf("'domain/admins'"), length: 15 }]);
  assert.equal(formatPolicyStatement(slashResult.statement), slash);
  const comparison = parseCondition("request.operation = get");
  assert.deepEqual(comparison.diagnostics, [{ severity: "warning", message: "Unquoted condition values are treated as variables; enclose literal values for comparison in single quotes", offset: 20, length: 3 }]);
  assert.deepEqual(parseCondition("request.operation = request.operation").diagnostics, []);
});
