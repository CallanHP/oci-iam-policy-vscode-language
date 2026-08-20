/** Strict OCI IAM policy parser and canonical renderer shared by VS Code features. */

export class PolicySyntaxError extends Error {}

export type StatementType = "allow" | "deny" | "endorse" | "admit" | "define";
export type PrincipalType = "group" | "dynamic-group" | "tenancy" | "service" | "any-user" | "any-group";
export type Verb = "inspect" | "read" | "use" | "manage" | "associate";
export type Condition = LiteralCondition | RegexCondition | VariableCondition | ListCondition | LogicalCondition | SetsIntersectCondition;

export interface Principal { type: PrincipalType; identifiers: string[]; reference?: "literal" | "id"; }
export interface Location { type: "compartment" | "tenancy" | "any-tenancy"; value?: string; reference?: "literal" | "id"; }
export interface Association { resource: string; type: "compartment" | "tenancy" | "any-tenancy"; value?: string; }
export interface LiteralCondition { kind: "literal"; variable: string; comparator: "=" | "!="; value: string; }
export interface RegexCondition { kind: "regex"; variable: string; comparator: "=" | "!="; value: string; }
export interface VariableCondition { kind: "variable"; variable: string; comparator: "=" | "!="; value: string; }
export interface ListCondition { kind: "list"; variable: string; values: string[]; }
export interface LogicalCondition { kind: "logical"; operator: "any" | "all"; conditions: Condition[]; }
export interface SetsIntersectCondition { kind: "sets-intersect"; left: string; right: string; }
export interface PolicyStatement {
  type: StatementType; principal: Principal; verb?: Verb; resource?: string; location?: Location;
  permissions?: string[]; definition?: string; association?: Association; condition?: Condition;
}

const statementTypes = new Set<StatementType>(["allow", "deny", "endorse", "admit", "define"]);
const principalTypes = new Set<PrincipalType>(["group", "dynamic-group", "tenancy", "service", "any-user", "any-group"]);
const verbs = new Set<Verb>(["inspect", "read", "use", "manage", "associate"]);
const associatable = new Set(["local-peering-gateways", "dns-zones", "dns-views", "dns-resolver", "dns-records"]);

function fail(message: string): never { throw new PolicySyntaxError(message); }
function takeWord(text: string): [string, string] { const match = /^(\S+)(?:\s+([\s\S]*))?$/.exec(text.trim()); return match ? [match[1], match[2] ?? ""] : fail("expected token"); }
function takeKeyword(text: string, keyword: string): string | undefined { const match = new RegExp(`^${keyword}(?:\\s+|$)([\\s\\S]*)$`, "i").exec(text.trim()); return match ? match[1].trim() : undefined; }
function token(value: string, description: string, forbidden = ""): string { if (!value || /\s/.test(value) || [...forbidden].some((c) => value.includes(c))) fail(`invalid ${description}`); return value; }
function ocid(value: string): boolean { return /^ocid1\.[a-z0-9._-]+$/i.test(value); }
function escape(value: string, delimiter: string): string { return value.replace(/\\/g, "\\\\").replaceAll(delimiter, `\\${delimiter}`); }

function closing(text: string, start: number, delimiter: string): number {
  for (let index = start + 1, escaped = false; index < text.length; index += 1) {
    if (escaped) { escaped = false; continue; }
    if (text[index] === "\\") { escaped = true; continue; }
    if (text[index] === delimiter) return index;
  }
  return -1;
}
function quoted(value: string): string | undefined {
  if (!value.startsWith("'")) return undefined;
  const end = closing(value, 0, "'");
  if (end < 0 || value.slice(end + 1).trim()) fail("malformed quoted value");
  const result = decode(value.slice(1, end));
  if (!result) fail("empty value");
  return result;
}
function decode(value: string): string { let result = ""; for (let index = 0; index < value.length; index += 1) { if (value[index] !== "\\") { result += value[index]; continue; } if (index + 1 >= value.length) fail("unterminated quoted value"); result += value[index + 1]; index += 1; } return result; }
function splitList(text: string): string[] {
  const parts: string[] = []; let start = 0; let quote = false; let escaped = false;
  for (let index = 0; index < text.length; index += 1) { const c = text[index]; if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === "'") quote = !quote; else if (c === "," && !quote) { const part = text.slice(start, index).trim(); if (!part) fail("empty list item"); parts.push(part); start = index + 1; } }
  if (escaped || quote) fail("unterminated quoted value"); const part = text.slice(start).trim(); if (!part) fail("empty list item"); parts.push(part); return parts;
}
function matchingBrace(text: string, start: number): number {
  let depth = 1; let quote = false; let regex = false; let escaped = false;
  for (let index = start + 1; index < text.length; index += 1) { const c = text[index]; if (escaped) { escaped = false; continue; } if (c === "\\" && (quote || regex)) { escaped = true; continue; } if (c === "'" && !regex) quote = !quote; else if (c === "/" && !quote) regex = !regex; else if (!quote && !regex) { if (c === "{") depth += 1; else if (c === "}" && --depth === 0) return index; } }
  return -1;
}
function splitConditions(text: string): string[] {
  const parts: string[] = []; let start = 0; let braces = 0; let parens = 0; let quote = false; let regex = false; let escaped = false;
  for (let index = 0; index < text.length; index += 1) { const c = text[index]; if (escaped) { escaped = false; continue; } if (c === "\\" && (quote || regex)) { escaped = true; continue; } if (c === "'" && !regex) quote = !quote; else if (c === "/" && !quote) regex = !regex; else if (!quote && !regex) { if (c === "{") braces += 1; else if (c === "}") braces -= 1; else if (c === "(") parens += 1; else if (c === ")") parens -= 1; else if (c === "," && braces === 0 && parens === 0) { const part = text.slice(start, index).trim(); if (!part) fail("empty logical condition member"); parts.push(part); start = index + 1; } } }
  const part = text.slice(start).trim(); if (!part) fail("empty logical condition member"); parts.push(part); return parts;
}

export function parseCondition(source: string): Condition {
  const text = source.trim(); const logical = /^(any|all)\s*\{/i.exec(text);
  if (logical) { const open = text.indexOf("{"); const close = matchingBrace(text, open); if (close < 0 || text.slice(close + 1).trim()) fail("malformed logical condition"); const members = splitConditions(text.slice(open + 1, close)); if (!members.length) fail("empty logical condition"); return { kind: "logical", operator: logical[1].toLowerCase() as "any" | "all", conditions: members.map(parseCondition) }; }
  const intersect = /^sets-intersect\(\s*([^\s,()]+)\s*,\s*([^\s,()]+)\s*\)$/i.exec(text);
  if (intersect) return { kind: "sets-intersect", left: intersect[1].toLowerCase(), right: intersect[2].toLowerCase() };
  const match = /^([^\s=!]+)\s*(=|!=|in)\s*([\s\S]*)$/i.exec(text); if (!match) fail("invalid condition");
  const variable = match[1].toLowerCase(); const comparator = match[2].toLowerCase(); const rhs = match[3].trim();
  if (comparator === "in") { if (!rhs.startsWith("(") || !rhs.endsWith(")")) fail("invalid list condition"); return { kind: "list", variable, values: splitList(rhs.slice(1, -1)).map((item) => quoted(item) ?? fail("list values must be quoted")) }; }
  if (rhs.startsWith("'")) return { kind: "literal", variable, comparator: comparator as "=" | "!=", value: quoted(rhs)! };
  if (rhs.startsWith("/")) { const end = closing(rhs, 0, "/"); if (end < 0 || rhs.slice(end + 1).trim()) fail("malformed regex"); const value = decode(rhs.slice(1, end)); if (!value) fail("empty value"); return { kind: "regex", variable, comparator: comparator as "=" | "!=", value }; }
  if (!rhs || /\s|[(){}',/]/.test(rhs)) fail("invalid variable value"); return { kind: "variable", variable, comparator: comparator as "=" | "!=", value: rhs.toLowerCase() };
}

function takePrincipalTail(text: string): [string, string] {
  let quote = false; let escaped = false;
  for (let index = 0; index < text.length; index += 1) { const c = text[index]; if (escaped) escaped = false; else if (c === "\\") escaped = true; else if (c === "'") quote = !quote; else if (!quote && (index === 0 || /\s/.test(text[index - 1])) && /^(?:(?:to|as)(?:\s|$)|\{)/i.test(text.slice(index))) return [text.slice(0, index).trim(), text.slice(index).trim()]; }
  if (quote || escaped) fail("unterminated quoted value"); fail("missing statement body");
}
function groupComponents(item: string): string[] | undefined {
  if (!item.startsWith("'")) return undefined; const parts: string[] = []; let rest = item;
  while (rest) { if (!rest.startsWith("'")) fail("invalid group domain"); const end = closing(rest, 0, "'"); if (end < 0) fail("unterminated quoted value"); const value = decode(rest.slice(1, end)); if (!value) fail("empty value"); parts.push(value); rest = rest.slice(end + 1); if (!rest) break; if (!rest.startsWith("/")) fail("invalid group domain"); rest = rest.slice(1); }
  if (parts.length > 2) fail("invalid group domain"); return parts;
}
function principalIdentifiers(source: string, kind: PrincipalType, byId: boolean): string[] {
  return splitList(source).map((item) => {
    const components = (kind === "group" || kind === "dynamic-group") && !byId ? groupComponents(item) : undefined;
    let value = components?.join("\u0000") ?? quoted(item);
    if (value === undefined) { if (!item || /\s/.test(item)) fail("invalid principal identifier"); value = item; }
    if (byId) { if (!ocid(value)) fail("invalid OCID"); return value.toLowerCase(); }
    if (kind === "group" || kind === "dynamic-group") { if (components) return components.map((part) => `'${part}'`).join("/"); const pieces = value.split("/"); if (pieces.length === 1) return `'${value}'`; if (pieces.length === 2 && pieces.every(Boolean)) return pieces.map((part) => `'${part}'`).join("/"); fail("invalid group domain"); }
    return kind === "tenancy" ? `'${value}'` : value.toLowerCase();
  });
}
function parsePrincipal(source: string, statementType: StatementType): [Principal, string] {
  const [kindRaw, remainder] = takeWord(source); const kind = kindRaw.toLowerCase() as PrincipalType; if (!principalTypes.has(kind)) fail("invalid principal type");
  if (kind === "any-user" || kind === "any-group") { if (!remainder) fail("missing statement body"); if (/^id\s/i.test(remainder)) fail("anonymous principals cannot use id"); const [values, tail] = takePrincipalTail(remainder); if (/^of\s+tenancy\s+/i.test(values)) { if (statementType !== "admit") fail("cross-tenancy principal only applies to admit"); const tenancy = values.replace(/^of\s+tenancy\s+/i, ""); if (!tenancy || /[\s,{}'/]/.test(tenancy)) fail("invalid cross-tenancy principal"); return [{ type: kind, identifiers: [values.toLowerCase()], reference: "literal" }, tail]; } if (values) fail("invalid anonymous principal"); return [{ type: kind, identifiers: [] }, tail]; }
  const [rawValues, tail] = takePrincipalTail(remainder); let values = rawValues; let byId = false; if (/^id\s+/i.test(values)) { if (kind !== "group" && kind !== "dynamic-group") fail("principal cannot use id"); byId = true; values = values.replace(/^id\s+/i, ""); }
  if (!values) fail("missing principal identifier"); const cross = /^(.+?)\s+of\s+tenancy\s+(\S+)$/i.exec(values); if (cross) { if (statementType !== "admit" || byId || (kind !== "group" && kind !== "dynamic-group") || values.includes(",") || /[,{}'/]/.test(cross[2])) fail("invalid cross-tenancy principal"); return [{ type: kind, identifiers: [values.toLowerCase()], reference: "literal" }, tail]; }
  const identifiers = principalIdentifiers(values, kind, byId); if (kind === "tenancy" && (statementType !== "define" || identifiers.length !== 1)) fail("invalid tenancy principal"); return [{ type: kind, identifiers, reference: byId ? "id" : "literal" }, tail];
}
function parsePermissions(text: string, statementType: StatementType): [string[], string] { if (!(statementType === "allow" || statementType === "endorse" || statementType === "admit")) fail("explicit permissions are invalid for this statement type"); if (!text.startsWith("{")) fail("expected permission list"); const end = text.indexOf("}"); if (end < 0) fail("unterminated permission list"); const body = text.slice(1, end); if (/[{']/.test(body)) fail("invalid permission list"); const values = splitList(body); if (values.some((item) => /\s|[{}]/.test(item))) fail("invalid permission"); return [values.map((item) => item.toUpperCase()), text.slice(end + 1).trim()]; }
function parseLocation(text: string, type: StatementType, association = false): [Location, string] {
  const afterIn = takeKeyword(text, "in"); if (afterIn === undefined) fail("missing location"); let [locationType, remainder] = takeWord(afterIn); locationType = locationType.toLowerCase();
  if (locationType === "any-tenancy") { if (type !== "endorse") fail("any-tenancy only applies to endorse"); return [{ type: "any-tenancy" }, remainder]; }
  if (locationType === "tenancy") { const named = type === "admit" && association; if (type === "endorse" || named) { if (association && (!remainder || /^(with|where)\b/i.test(remainder))) return [{ type: "tenancy", reference: "literal" }, remainder]; const [value, tail] = takeWord(remainder); if (/^(where|with)$/i.test(value)) fail("missing tenancy value"); return [{ type: "tenancy", value: value.toLowerCase(), reference: "literal" }, tail]; } return [{ type: "tenancy", reference: "literal" }, remainder]; }
  if (locationType !== "compartment") fail("invalid location type"); let byId = false; if (/^id\s+/i.test(remainder)) { byId = true; remainder = remainder.replace(/^id\s+/i, ""); } const [valueRaw, tail] = takeWord(remainder); if (/^(where|with)$/i.test(valueRaw)) fail("missing compartment value"); if (byId && !ocid(valueRaw)) fail("invalid OCID"); return [{ type: "compartment", value: valueRaw.toLowerCase(), reference: byId ? "id" : "literal" }, tail];
}
function parseAssociation(text: string): [Association, string] { const afterWith = takeKeyword(text, "with"); if (afterWith === undefined) fail("associate requires an association"); let [resource, remainder] = takeWord(afterWith); resource = resource.toLowerCase(); if (!associatable.has(resource)) fail("invalid association resource"); const afterIn = takeKeyword(remainder, "in"); if (afterIn === undefined) fail("association requires a location"); let [kind, tail] = takeWord(afterIn); kind = kind.toLowerCase(); if (kind === "any-tenancy") return [{ resource, type: "any-tenancy" }, tail]; if (kind !== "compartment" && kind !== "tenancy") fail("invalid association location"); if (resource !== "local-peering-gateways" && (!tail || /^(where|with)\b/i.test(tail))) return [{ resource, type: "tenancy" }, tail]; const [value, finalTail] = takeWord(tail); return [{ resource, type: kind as "compartment" | "tenancy", value: value.toLowerCase() }, finalTail]; }

export function parsePolicyStatement(source: string): PolicyStatement {
  const raw = source.trim(); if (!raw) fail("empty policy statement"); let [typeRaw, remainder] = takeWord(raw); typeRaw = typeRaw.toLowerCase(); if (!statementTypes.has(typeRaw as StatementType)) fail("invalid statement type"); const type = typeRaw as StatementType; const [principal, principalTail] = parsePrincipal(remainder, type); remainder = principalTail; const parsed: PolicyStatement = { type, principal };
  if (type === "define") { if (!(principal.type === "tenancy" || principal.type === "group" || principal.type === "dynamic-group")) fail("invalid define principal"); const definition = takeKeyword(remainder, "as"); if (!definition || /\s/.test(definition)) fail("define requires one definition"); const unquoted = definition.replace(/^'|'$/g, ""); if (!ocid(unquoted)) fail("invalid OCID"); parsed.definition = unquoted.toLowerCase(); return parsed; }
  if (/^to\s+/i.test(remainder)) remainder = remainder.replace(/^to\s+/i, "");
  if (remainder.startsWith("{")) [parsed.permissions, remainder] = parsePermissions(remainder, type); else { const [verbRaw, afterVerb] = takeWord(remainder); const verb = verbRaw.toLowerCase() as Verb; if (!verbs.has(verb)) fail("invalid or missing verb"); const [resource, afterResource] = takeWord(afterVerb); if (resource.toLowerCase() === "in") fail("missing resource"); if (verb === "associate" && !associatable.has(resource.toLowerCase())) fail("invalid associate resource"); parsed.verb = verb; parsed.resource = resource.toLowerCase(); remainder = afterResource; }
  [parsed.location, remainder] = parseLocation(remainder, type, parsed.verb === "associate"); if (parsed.verb === "associate") { [parsed.association, remainder] = parseAssociation(remainder); if ((parsed.resource === "local-peering-gateways") !== (parsed.association.resource === "local-peering-gateways")) fail("invalid association resource pair"); }
  if (remainder) { const condition = takeKeyword(remainder, "where"); if (!condition) fail("invalid trailing input"); parsed.condition = parseCondition(condition); }
  return parsed;
}

function renderCondition(condition: Condition, level?: number): string {
  if (condition.kind === "logical") { const indent = "  ".repeat(level ?? 0); const childIndent = "  ".repeat((level ?? 0) + 1); return `${condition.operator} {\n${condition.conditions.map((child) => `${childIndent}${renderCondition(child, (level ?? 0) + 1)}`).join(",\n")}\n${indent}}`; }
  if (condition.kind === "sets-intersect") return `sets-intersect(${condition.left}, ${condition.right})`;
  if (condition.kind === "list") return `${condition.variable} in ( ${condition.values.map((value) => `'${escape(value, "'")}'`).join(", ")} )`;
  if (condition.kind === "literal") return `${condition.variable} ${condition.comparator} '${escape(condition.value, "'")}'`;
  if (condition.kind === "regex") return `${condition.variable} ${condition.comparator} /${escape(condition.value, "/")}/`;
  return `${condition.variable} ${condition.comparator} ${condition.value}`;
}
function renderPrincipal(principal: Principal): string {
  if (principal.type === "any-user" || principal.type === "any-group") return principal.identifiers.length ? `${principal.type} ${principal.identifiers[0]}` : principal.type;
  const identifiers = principal.identifiers.map((value) => {
    if (principal.reference === "id") return value;
    if (principal.type === "group" || principal.type === "dynamic-group") return value.split("/").map((part) => `'${escape(part.replace(/^'|'$/g, ""), "'")}'`).join("/");
    if (principal.type === "tenancy") return `'${escape(value.replace(/^'|'$/g, ""), "'")}'`;
    return value;
  }).join(", ");
  return `${principal.type}${principal.reference === "id" ? " id" : ""} ${identifiers}`;
}
function renderLocation(location: Location, type: StatementType, association: boolean): string { if (location.type === "any-tenancy") return "any-tenancy"; if (location.type === "tenancy") return type === "endorse" || (type === "admit" && association) ? `tenancy${location.value ? ` ${location.value}` : ""}` : "tenancy"; return `compartment${location.reference === "id" ? " id" : ""} ${location.value}`; }
function renderAssociation(value: Association): string { if (value.type === "any-tenancy") return `with ${value.resource} in any-tenancy`; return `with ${value.resource} in ${value.type}${value.value ? ` ${value.value}` : ""}`; }
export function formatPolicyStatement(statement: PolicyStatement): string { const principal = renderPrincipal(statement.principal); if (statement.type === "define") return `define ${principal} as ${statement.definition}`; const action = statement.permissions ? `{${statement.permissions.join(", ")}}` : `${statement.verb} ${statement.resource}`; const association = statement.association ? ` ${renderAssociation(statement.association)}` : ""; const base = `${statement.type} ${principal} to ${action} in ${renderLocation(statement.location!, statement.type, statement.verb === "associate")}${association}`; return statement.condition ? `${base} where ${renderCondition(statement.condition, 0)}` : base; }
