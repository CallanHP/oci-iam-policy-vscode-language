/** Strict OCI IAM policy parser and canonical renderer shared by VS Code features. */
export class PolicySyntaxError extends Error {
    readonly offset: number;
    readonly length: number;
    /** Creates an error whose range identifies the invalid policy source. */
    constructor(message: string, offset: number, length: number) {
        super(message);
        this.name = "PolicySyntaxError";
        this.offset = offset;
        this.length = length;
    }
}
export type StatementType = "allow" | "deny" | "endorse" | "admit" | "define";

export type PrincipalType = "group" | "dynamic-group" | "tenancy" | "service" | "any-user" | "any-group";

export type Verb = "inspect" | "read" | "use" | "manage" | "associate";

export type Condition = LiteralCondition | RegexCondition | VariableCondition | ListCondition | LogicalCondition | SetsIntersectCondition;

export interface Principal {
    type: PrincipalType;
    identifiers: string[];
    reference?: "literal" | "id";
}
export interface Location {
    type: "compartment" | "tenancy" | "any-tenancy";
    value?: string;
    reference?: "literal" | "id";
}

export interface Association {
    resource: string;
    type: "compartment" | "tenancy" | "any-tenancy";
    value?: string;
}

export interface LiteralCondition {
    kind: "literal";
    variable: string;
    comparator: "=" | "!=";
    value: string;
}

export interface RegexCondition {
    kind: "regex";
    variable: string;
    comparator: "=" | "!=";
    value: string;
}

export interface VariableCondition {
    kind: "variable";
    variable: string;
    comparator: "=" | "!=";
    value: string;
}

export interface ListCondition {
    kind: "list";
    variable: string;
    values: string[];
}

export interface LogicalCondition {
    kind: "logical";
    operator: "any" | "all";
    conditions: Condition[];
}

export interface SetsIntersectCondition {
    kind: "sets-intersect";
    left: string;
    right: string;
}

export interface PolicyStatement {
    type: StatementType;
    principal: Principal;
    verb?: Verb;
    resource?: string;
    location?: Location;
    permissions?: string[];
    definition?: string;
    association?: Association;
    condition?: Condition;
}

export interface PolicyDiagnostic {
    severity: "error" | "warning" | "information" | "hint";
    message: string;
    offset: number;
    length: number;
}

export interface PolicyParseResult {
    statement?: PolicyStatement;
    diagnostics: PolicyDiagnostic[];
}

export interface ConditionParseResult {
    condition?: Condition;
    diagnostics: PolicyDiagnostic[];
}

const statementTypes = new Set<StatementType>(["allow", "deny", "endorse", "admit", "define"]);
const principalTypes = new Set<PrincipalType>(["group", "dynamic-group", "tenancy", "service", "any-user", "any-group"]);
const verbs = new Set<Verb>(["inspect", "read", "use", "manage", "associate"]);
const associatable = new Set(["local-peering-gateways", "dns-zones", "dns-views", "dns-resolver", "dns-records"]);

/**
 *  Span objects are used throughout the implementation to maintain the full
 *  statement, while tracking only the sub-string we are currently looking at.
 *  Represents an inclusive-start, exclusive-end slice of policy source text.
 */
interface Span {
    source: string;
    start: number;
    end: number;
}
/** Create a source span, defaulting to the complete source string. */
const S = (source: string, start = 0, end = source.length): Span => ({ source, start, end });
/** Return the source text covered by a span. */
const T = (s: Span): string => s.source.slice(s.start, s.end);
/** Return a span with adjusted boundaries. */
function P(s: Span, start: number, end = s.end): Span {
    return { ...s, start, end };
}

/** Remove leading and trailing whitespace from a span. */
function trim(s: Span): Span {
    let { start, end } = s;
    while (start < end && /\s/.test(s.source[start]))
        start++;
    while (end > start && /\s/.test(s.source[end - 1]))
        end--;
    return P(s, start, end);
}

const failures = {
    expectedAdditionalSyntax: "Expected additional policy syntax",
    expectedPrincipalType: "Expected a principal type",
    unterminatedQuotedValue: "Unterminated quoted value; add a closing single quote",
    unexpectedTextAfterQuotedValue: "Unexpected text after quoted value",
    emptyConditionValue: "Condition values cannot be empty",
    emptyListItem: "List items cannot be empty",
    emptyLogicalConditionMember: "Logical condition members cannot be empty",
    unterminatedLogicalCondition: "Unterminated logical condition; add a closing '}'",
    unexpectedTextAfterLogicalCondition: "Unexpected text after logical condition",
    emptyLogicalCondition: "Logical conditions must contain at least one condition",
    invalidConditionOperator: "Invalid condition operator; expected =, !=, or in",
    expectedConditionVariable: "Expected a condition variable before the operator",
    listConditionNeedsParentheses: "List conditions must use parentheses after 'in'",
    unterminatedRegularExpression: "Unterminated regular expression; add a closing '/'",
    unexpectedTextAfterRegularExpression: "Unexpected text after regular expression",
    invalidConditionValue: "Condition value must be a variable name, quoted string, regular expression, or quoted list",
    expectedActionAfterPrincipal: "Expected a policy action after the principal",
    invalidGroupPrincipalName: "Group and dynamic-group names must be a quoted name or quoted domain/name pair",
    invalidPrincipalIdentifier: "Principal identifiers must be a name, quoted name, or comma-separated list",
    invalidPrincipalOcid: "Invalid OCID for a principal specified by 'id'",
    invalidPrincipalType: "Invalid principal type; expected group, dynamic-group, tenancy, service, any-user, or any-group",
    idModifierForAnyPrincipal: "The 'id' modifier cannot be used with any-user or any-group",
    invalidCrossTenancyPrincipal: "Cross-tenancy principals are only valid for group or dynamic-group in an admit statement, without 'id' or multiple identifiers",
    namedAnyPrincipal: "any-user and any-group cannot have a principal name",
    invalidPrincipalIdModifier: "The 'id' modifier is only valid for group and dynamic-group principals",
    expectedPrincipalIdentifier: "Expected a principal identifier",
    invalidTenancyPrincipal: "A tenancy principal is only valid in a define statement and must have one identifier",
    invalidPermissionList: "Permission lists are only valid in allow, endorse, or admit statements",
    expectedPermissionList: "Expected a permission list enclosed in braces",
    unterminatedPermissionList: "Unterminated permission list; add a closing '}'",
    invalidPermissionListContents: "Permission lists contain comma-separated unquoted permission names only",
    invalidPermission: "Invalid permission; permission names cannot contain whitespace or braces",
    expectedLocation: "Expected a location beginning with 'in'",
    expectedLocationAfterIn: "Expected a location after 'in'",
    invalidAnyTenancyLocation: "any-tenancy is only valid in an endorse statement",
    expectedTenancyName: "Expected a tenancy name",
    invalidLocationType: "Invalid location type; expected compartment or tenancy",
    expectedCompartmentName: "Expected a compartment name or OCID after 'compartment'",
    invalidLocationOcid: "Invalid OCID for a location specified by 'id'",
    invalidCompartmentName: "Invalid location - compartment names can only be letters, numbers, periods, hyphens, and underscores",
    invalidCompartmentPath: "Invalid compartment path.",
    expectedAssociation: "Expected an association after 'with'",
    expectedAssociatedResource: "Expected an associated resource after 'with'",
    invalidAssociatedResource: "Invalid associated resource; expected local-peering-gateways, dns-zones, dns-views, dns-resolver, or dns-records",
    expectedAssociationLocation: "Expected an association location beginning with 'in'",
    expectedAssociationLocationAfterIn: "Expected an association location after 'in'",
    expectedAssociationLocationValue: "Expected a value for the association location",
    invalidAssociationLocation: "Invalid association location; expected compartment, tenancy, or any-tenancy",
    emptyPolicyStatement: "Policy statement is empty",
    invalidStatementType: "Invalid policy statement type; expected allow, deny, endorse, admit, or define",
    invalidDefinePrincipal: "define statements support only tenancy, group, or dynamic-group principals",
    expectedDefineAs: "Expected 'as' before the define OCID",
    expectedDefineOcid: "Expected one OCID after 'as' in a define statement",
    invalidDefineOcid: "Invalid OCID in define statement",
    invalidPolicyVerb: "Invalid policy verb; expected inspect, read, use, manage, or associate",
    expectedPolicyVerb: "Expected a policy verb",
    expectedPolicyResource: "Expected a resource after the policy verb",
    invalidAssociateResource: "Invalid resource for associate; expected local-peering-gateways, dns-zones, dns-views, dns-resolver, or dns-records",
    mismatchedAssociatedResource: "The associated resource must match the resource being associated",
    unexpectedTextAfterStatement: "Unexpected text after the policy statement",
    expectedCondition: "Expected a condition after 'where'",
} as const;

/** Throw a syntax error covering the specified source span. */
function fail(message: string, s: Span, length = s.end - s.start): never {
    const offset = Math.min(Math.max(s.start, 0), s.source.length);
    throw new PolicySyntaxError(message, offset, Math.min(Math.max(length, 0), s.source.length - offset));
}

const warnings = {
    defaultIdentityDomain: "Group and dynamic-group names without an identity domain are assumed to be part of the Default identity domain. It is recommended to specify this explicitly.",
    quotePrincipal: "Group and dynamic-group names should be enclosed in single quotes",
    quotedSlashPrincipal: "A quoted group or dynamic-group name is treated as a literal group name in the Default identity domain. Did you mean to specify a domain/group pairing?",
    quoteListMember: "List values should be enclosed in single quotes",
    quoteComparisonValue: "Unquoted condition values are treated as variables; enclose literal values for comparison in single quotes",
} as const;

/** Create a Warning Diagnostic from a message */
const warning = (message: string, s: Span): PolicyDiagnostic => ({ severity: "warning", message, offset: s.start, length: s.end - s.start });



/** Consume the next whitespace-delimited token and return it with the remainder. */
function take(s: Span, failure_message: string = failures.expectedAdditionalSyntax): [Span, Span] {
    s = trim(s);
    if (s.start === s.end) {
        fail(failure_message, s, 0);
    }
    let end = s.start;
    while (end < s.end && !/\s/.test(s.source[end]))
        end++;
    return [P(s, s.start, end), trim(P(s, end))];
}

/** Consume a case-insensitive policy keyword when it begins a span. */
function key(s: Span, value: string): Span | undefined {
    s = trim(s);
    const end = s.start + value.length;
    return s.source.slice(s.start, end).toLowerCase() === value && (end === s.end || /\s/.test(s.source[end])) ? trim(P(s, end)) : undefined;
}
/** Determine whether a value has the supported OCI resource identifier form. */
const ocid = (value: string): boolean => /^ocid1\.[a-z0-9._-]+$/i.test(value);
/** Escape backslashes and the delimiter for a quoted policy value. */
const escape = (value: string, delimiter: string): string => value.replace(/\\/g, "\\\\").replaceAll(delimiter, `\\${delimiter}`);
/** Find the unescaped closing delimiter for an opening delimiter at a span start. */
function close(s: Span, delimiter: string): number {
    for (let i = s.start + 1, escaped = false; i < s.end; i++) {
        if (escaped) {
            escaped = false;
        }
        else if (s.source[i] === "\\") {
            escaped = true;
        }
        else if (s.source[i] === delimiter) {
            return i;
        }
    }
    return -1;
}

/** Decode escaped characters from the contents of a quoted value. */
function decode(s: Span, failure_message: string = failures.unterminatedQuotedValue): string {
    let result = "";
    for (let i = s.start; i < s.end; i++) {
        if (s.source[i] !== "\\") {
            result += s.source[i];
        } else {
            if (++i >= s.end) {
                fail(failure_message, P(s, s.start - 1));
            }
            result += s.source[i];
        }
    }
    return result;
}

/** Parse one complete single-quoted value, if the span begins with a quote. */
function quote(s: Span): string | undefined {
    if (s.source[s.start] !== "'") {
        return undefined;
    }
    const end = close(s, "'");
    if (end < 0) {
        fail(failures.unterminatedQuotedValue, s);
    }
    if (trim(P(s, end + 1)).start !== s.end) {
        fail(failures.unexpectedTextAfterQuotedValue, P(s, end + 1));
    }
    const value = decode(P(s, s.start + 1, end));
    if (!value) {
        fail(failures.emptyConditionValue, s);
    }
    return value;
}

/** Split a comma-separated list while respecting quoted values and escapes. */
function list(s: Span, empty: string = failures.emptyListItem): Span[] {
    const result: Span[] = [];
    let start = s.start, quoteOpen = false, escaped = false;
    for (let i = s.start; i < s.end; i++) {
        const c = s.source[i];
        if (escaped) {
            escaped = false;
        }
        else if (c === "\\") {
            escaped = true;
        }
        else if (c === "'") {
            quoteOpen = !quoteOpen;
        }
        else if (c === "," && !quoteOpen) {
            const item = trim(P(s, start, i));
            if (item.start === item.end) {
                fail(empty, P(s, i, i + 1));
            }
            result.push(item);
            start = i + 1;
        }
    }
    if (quoteOpen || escaped) {
        fail(failures.unterminatedQuotedValue, P(s, start));
    }
    const item = trim(P(s, start));
    if (item.start === item.end) {
        fail(empty, P(s, s.end), 0);
    }
    result.push(item);
    return result;
}

/** Find the closing brace matching an opening logical-condition brace. */
function brace(s: Span, open: number): number {
    let depth = 1, quoted = false, regex = false, escaped = false;
    for (let i = open + 1; i < s.end; i++) {
        const c = s.source[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c === "\\" && (quoted || regex)) {
            escaped = true;
            continue;
        }
        if (c === "'" && !regex) {
            quoted = !quoted;
        }
        else if (c === "/" && !quoted) {
            regex = !regex;
        }
        else if (!quoted && !regex) {
            if (c === "{") {
                depth++;
            }
            if (c === "}" && --depth === 0) {
                return i;
            }
        }
    }
    return -1;
}

/** Split top-level members of a logical condition. */
function conditions(s: Span): Span[] {
    const result: Span[] = [];
    let start = s.start, braces = 0, parens = 0, quoted = false, regex = false, escaped = false;
    for (let i = s.start; i < s.end; i++) {
        const c = s.source[i];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (c === "\\" && (quoted || regex)) {
            escaped = true;
            continue;
        }
        if (c === "'" && !regex) {
            quoted = !quoted;
        }
        else if (c === "/" && !quoted) {
            regex = !regex;
        }
        else if (!quoted && !regex) {
            if (c === "{") {
                braces++;
            }
            else if (c === "}") {
                braces--;
            }
            else if (c === "(") {
                parens++;
            }
            else if (c === ")") {
                parens--;
            }
            else if (c === "," && !braces && !parens) {
                const item = trim(P(s, start, i));
                if (item.start === item.end) {
                    fail(failures.emptyLogicalConditionMember, P(s, i, i + 1));
                }
                result.push(item);
                start = i + 1;
            }
        }
    }
    const item = trim(P(s, start));
    if (item.start === item.end) {
        fail(failures.emptyLogicalConditionMember, P(s, s.end), 0);
    }
    result.push(item);
    return result;
}

interface ConditionParseStep {
    condition: Condition;
    warnings: PolicyDiagnostic[];
}

/** Parse a condition from a source span, retaining warnings from nested members. */
function parseConditionSpan(s: Span): ConditionParseStep {
    s = trim(s);
    const logical = /^(any|all)\s*\{/i.exec(T(s));
    if (logical) {
        const open = s.start + logical[0].length - 1;
        const end = brace(s, open);
        if (end < 0) {
            fail(failures.unterminatedLogicalCondition, P(s, open));
        }
        if (trim(P(s, end + 1)).start !== s.end) {
            fail(failures.unexpectedTextAfterLogicalCondition, P(s, end + 1));
        }
        const body = trim(P(s, open + 1, end));
        if (body.start === body.end) {
            fail(failures.emptyLogicalCondition, body, 0);
        }
        const members = conditions(body).map(parseConditionSpan);
        return {
            condition: { kind: "logical", operator: logical[1].toLowerCase() as "any" | "all", conditions: members.map((member) => member.condition) },
            warnings: members.flatMap((member) => member.warnings),
        };
    }
    const intersect = /^sets-intersect\(\s*([^\s,()]+)\s*,\s*([^\s,()]+)\s*\)$/i.exec(T(s));
    if (intersect) {
        return { condition: { kind: "sets-intersect", left: intersect[1].toLowerCase(), right: intersect[2].toLowerCase() }, warnings: [] };
    }
    const match = /^([^\s=!]+)\s*(=|!=|in)\s*([\s\S]*)$/i.exec(T(s));
    if (!match) {
        const bad = /\b(?:is|equals|contains)\b/i.exec(T(s));
        if (bad && bad.index !== undefined) {
            fail(failures.invalidConditionOperator, P(s, s.start + bad.index, s.start + bad.index + bad[0].length));
        }
        fail(failures.expectedConditionVariable, s);
    }
    const rhs = trim(P(s, s.end - match[3].length));
    if (match[2].toLowerCase() === "in") {
        if (rhs.source[rhs.start] !== "(" || rhs.source[rhs.end - 1] !== ")") {
            fail(failures.listConditionNeedsParentheses, rhs);
        }
        const members = list(P(rhs, rhs.start + 1, rhs.end - 1));
        const unquoted = members.filter((item) => quote(item) === undefined);
        return {
            condition: { kind: "list", variable: match[1].toLowerCase(), values: members.map((item) => quote(item) ?? T(item)) },
            warnings: unquoted.map((item) => warning(warnings.quoteListMember, item)),
        };
    }
    if (rhs.source[rhs.start] === "'") {
        return { condition: { kind: "literal", variable: match[1].toLowerCase(), comparator: match[2] as "=" | "!=", value: quote(rhs)! }, warnings: [] };
    }
    if (rhs.source[rhs.start] === "/") {
        const end = close(rhs, "/");
        if (end < 0) {
            fail(failures.unterminatedRegularExpression, rhs);
        }
        if (trim(P(rhs, end + 1)).start !== rhs.end) {
            fail(failures.unexpectedTextAfterRegularExpression, P(rhs, end + 1));
        }
        const value = decode(P(rhs, rhs.start + 1, end), failures.unterminatedRegularExpression);
        if (!value) {
            fail(failures.emptyConditionValue, rhs);
        }
        return { condition: { kind: "regex", variable: match[1].toLowerCase(), comparator: match[2] as "=" | "!=", value }, warnings: [] };
    }
    if (rhs.start === rhs.end || /\s|[(){}',/]/.test(T(rhs))) {
        fail(failures.invalidConditionValue, rhs);
    }
    const value = T(rhs).toLowerCase();
    return {
        condition: { kind: "variable", variable: match[1].toLowerCase(), comparator: match[2] as "=" | "!=", value },
        warnings: value.includes(".") ? [] : [warning(warnings.quoteComparisonValue, rhs)],
    };
}

/** Parse one OCI IAM condition expression into its structured representation. */
export function parseCondition(source: string): ConditionParseResult {
    try {
        const parsed = parseConditionSpan(S(source));
        if (parsed.condition.kind === "logical") {
            const trailing = /[ \t]+$/.exec(source)?.[0];
            if (trailing) {
                parsed.warnings.push({
                    severity: "warning",
                    message: "logical condition has trailing whitespace before its line ending",
                    offset: source.length - trailing.length,
                    length: trailing.length,
                });
            }
        }
        return { condition: parsed.condition, diagnostics: parsed.warnings };
    } catch (error) {
        if (error instanceof PolicySyntaxError) {
            return { diagnostics: [{ severity: "error", message: error.message, offset: error.offset, length: error.length }] };
        }
        throw error;
    }
}

/** Separate a principal definition from its following action clause. */
function principalTail(s: Span, define = false): [
    Span,
    Span
] {
    let quoted = false, escaped = false;
    for (let i = s.start; i < s.end; i++) {
        const c = s.source[i];
        if (escaped) {
            escaped = false;
        }
        else if (c === "\\") {
            escaped = true;
        }
        else if (c === "'") {
            quoted = !quoted;
        }
        else if (!quoted && (i === s.start || /\s/.test(s.source[i - 1])) && (define ? /^(?:(?:to|as)(?:\s|$)|\{|ocid1\.)/i : /^(?:(?:to|as)(?:\s|$)|\{)/i).test(s.source.slice(i, s.end))) {
            return [trim(P(s, s.start, i)), trim(P(s, i))];
        }
    }
    if (quoted || escaped) {
        fail(failures.unterminatedQuotedValue, s);
    }
    fail(failures.expectedActionAfterPrincipal, P(s, s.end), 0);
}

/** Parse the quoted name or quoted domain/name form for group principals. */
function groupParts(s: Span): string[] | undefined {
    if (s.source[s.start] !== "'") {
        return undefined;
    }
    const result: string[] = [];
    let at = s.start;
    while (at < s.end) {
        if (s.source[at] !== "'") {
            fail(failures.invalidGroupPrincipalName, P(s, at));
        }
        const end = close(P(s, at), "'");
        if (end < 0) {
            fail(failures.unterminatedQuotedValue, P(s, at));
        }
        const value = decode(P(s, at + 1, end));
        if (!value) {
            fail(failures.emptyConditionValue, P(s, at, end + 1));
        }
        result.push(value);
        at = end + 1;
        if (at === s.end) {
            break;
        }
        if (s.source[at] !== "/") {
            fail(failures.invalidGroupPrincipalName, P(s, at));
        }
        at++;
    }
    if (result.length > 2) {
        fail(failures.invalidGroupPrincipalName, s);
    }
    return result;
}

/** Parse and normalize the identifiers for a principal type. */
function principalIds(s: Span, kind: PrincipalType, byId: boolean, diagnosticWarnings: PolicyDiagnostic[], warnPrincipalNames: boolean, idRange = s): string[] {
    return list(s).map((item) => {
        const parts = (kind === "group" || kind === "dynamic-group") && !byId ? groupParts(item) : undefined;
        let value = parts?.join("\0") ?? quote(item);
        if (value === undefined) {
            if (/\s/.test(T(item))) {
                fail(failures.invalidPrincipalIdentifier, item);
            }
            value = T(item);
        }
        if (byId) {
            if (!ocid(value)) {
                fail(failures.invalidPrincipalOcid, idRange);
            }
            return value.toLowerCase();
        }
        if (kind === "group" || kind === "dynamic-group") {
            if (parts) {
                if (warnPrincipalNames && parts.length === 1) {
                    diagnosticWarnings.push(warning(parts[0].split("/").length === 2 ? warnings.quotedSlashPrincipal : warnings.defaultIdentityDomain, item));
                }
                return parts.join("\0");
            }
            const names = value.split("/");
            if (names.length === 1) {
                if (warnPrincipalNames) {
                    diagnosticWarnings.push(warning(warnings.defaultIdentityDomain, item), warning(warnings.quotePrincipal, item));
                }
                return value;
            }
            if (names.length === 2 && names.every(Boolean)) {
                if (warnPrincipalNames) diagnosticWarnings.push(warning(warnings.quotePrincipal, item));
                return names.join("\0");
            }
            fail(failures.invalidGroupPrincipalName, item);
        }
        return kind === "tenancy" ? `'${value}'` : value.toLowerCase();
    });
}

/** Parse a statement principal and return the following action clause. */
function principal(s: Span, type: StatementType, diagnosticWarnings: PolicyDiagnostic[]): [
    Principal,
    Span
] {
    const [kindSpan, rest] = take(s, failures.expectedPrincipalType);
    const kind = T(kindSpan).toLowerCase() as PrincipalType;
    if (!principalTypes.has(kind)) {
        fail(failures.invalidPrincipalType, kindSpan);
    }
    if (kind === "any-user" || kind === "any-group") {
        if (rest.start === rest.end) {
            fail(failures.expectedActionAfterPrincipal, rest, 0);
        }
        if (key(rest, "id")) {
            fail(failures.idModifierForAnyPrincipal, take(rest)[0]);
        }
        const [names, tail] = principalTail(rest);
        if (/^of\s+tenancy\s+/i.test(T(names))) {
            if (type !== "admit" || !/^of\s+tenancy\s+\S+$/i.test(T(names)) || /[,{}'/]/.test(T(names).replace(/^of\s+tenancy\s+/i, ""))) {
                fail(failures.invalidCrossTenancyPrincipal, names);
            }
            return [{ type: kind, identifiers: [T(names).toLowerCase()], reference: "literal" }, tail];
        }
        if (names.start !== names.end) {
            fail(failures.namedAnyPrincipal, names);
        }
        return [{ type: kind, identifiers: [] }, tail];
    }
    const [names, tail] = principalTail(rest, type === "define");
    const idRest = key(names, "id");
    const byId = idRest !== undefined;
    if (byId && kind !== "group" && kind !== "dynamic-group") {
        fail(failures.invalidPrincipalIdModifier, take(names)[0]);
    }
    const values = idRest ?? names;
    if (values.start === values.end) {
        fail(failures.expectedPrincipalIdentifier, values, 0);
    }
    const cross = /^(.+?)\s+of\s+tenancy\s+(\S+)$/i.exec(T(values));
    if (cross) {
        if (type !== "admit" || byId || (kind !== "group" && kind !== "dynamic-group") || T(values).includes(",") || /[,{}'/]/.test(cross[2])) {
            fail(failures.invalidCrossTenancyPrincipal, values);
        }
        return [{ type: kind, identifiers: [T(values).toLowerCase()], reference: "literal" }, tail];
    }
    const ids = principalIds(values, kind, byId, diagnosticWarnings, type === "allow" || type === "endorse", names);
    if (kind === "tenancy" && (type !== "define" || ids.length !== 1)) {
        fail(failures.invalidTenancyPrincipal, values);
    }
    return [{ type: kind, identifiers: ids, reference: byId ? "id" : "literal" }, tail];
}

/** Parse a brace-enclosed permission list for a supported statement type. */
function permissions(s: Span, type: StatementType): [
    string[],
    Span
] {
    if (!(type === "allow" || type === "endorse" || type === "admit")) {
        fail(failures.invalidPermissionList, s);
    }
    if (s.source[s.start] !== "{") {
        fail(failures.expectedPermissionList, s);
    }
    let end = s.start + 1;
    while (end < s.end && s.source[end] !== "}")
        end++;
    if (end === s.end) {
        fail(failures.unterminatedPermissionList, s);
    }
    const body = P(s, s.start + 1, end);
    if (/[{']/.test(T(body))) {
        fail(failures.invalidPermissionListContents, body);
    }
    const values = list(body);
    for (const value of values)
        if (/\s|[{}]/.test(T(value))) {
            fail(failures.invalidPermission, value);
        }
    return [values.map((value) => T(value).toUpperCase()), trim(P(s, end + 1))];
}

/** Parse a policy location, including associate-statement variants. */
function location(s: Span, type: StatementType, association = false): [
    Location,
    Span
] {
    const after = key(s, "in");
    if (!after) {
        fail(failures.expectedLocation, trim(s), 0);
    }
    const [kindSpan, rest] = take(after, failures.expectedLocationAfterIn);
    const kind = T(kindSpan).toLowerCase();
    if (kind === "any-tenancy") {
        if (type !== "endorse") {
            fail(failures.invalidAnyTenancyLocation, kindSpan);
        }
        return [{ type: "any-tenancy" }, rest];
    }
    if (kind === "tenancy") {
        const named = type === "admit" && association;
        if (type === "endorse" || named) {
            if (association && (rest.start === rest.end || /^(with|where)\b/i.test(T(rest)))) {
                return [{ type: "tenancy", reference: "literal" }, rest];
            }
            const [value, tail] = take(rest, failures.expectedTenancyName);
            if (/^(where|with)$/i.test(T(value))) {
                fail(failures.expectedTenancyName, value);
            }
            return [{ type: "tenancy", value: T(value).toLowerCase(), reference: "literal" }, tail];
        }
        return [{ type: "tenancy", reference: "literal" }, rest];
    }
    if (kind !== "compartment") {
        fail(failures.invalidLocationType, kindSpan);
    }
    const idRest = key(rest, "id");
    const byId = idRest !== undefined;
    const [value, tail] = take(idRest ?? rest, failures.expectedCompartmentName);
    if (/^(where|with)$/i.test(T(value))) {
        fail(failures.expectedCompartmentName, value);
    }
    if (byId && !ocid(T(value))) {
        fail(failures.invalidLocationOcid, P(rest, rest.start, value.end));
    }
    if (!byId && !/^[A-Za-z0-9._:-]+$/.test(T(value))) {
        fail(failures.invalidCompartmentName, value);
    }
    if (!byId && /(^:|:$|::)/.test(T(value))) {
        fail(failures.invalidCompartmentPath, value);
    }

    return [{ type: "compartment", value: T(value).toLowerCase(), reference: byId ? "id" : "literal" }, tail];
}

/** Parse the target clause following an associate statement. */
function association(s: Span): [
    Association,
    Span,
    Span
] {
    const after = key(s, "with");
    if (!after) {
        fail(failures.expectedAssociation, trim(s), 0);
    }
    const [resource, rest] = take(after, failures.expectedAssociatedResource);
    if (!associatable.has(T(resource).toLowerCase())) {
        fail(failures.invalidAssociatedResource, resource);
    }
    const afterIn = key(rest, "in");
    if (!afterIn) {
        fail(failures.expectedAssociationLocation, rest, 0);
    }
    const [kind, tail] = take(afterIn, failures.expectedAssociationLocationAfterIn);
    const type = T(kind).toLowerCase();
    if (type === "any-tenancy") {
        return [{ resource: T(resource).toLowerCase(), type: "any-tenancy" }, tail, resource];
    }
    if (type !== "compartment" && type !== "tenancy") {
        fail(failures.invalidAssociationLocation, kind);
    }
    if (T(resource).toLowerCase() !== "local-peering-gateways" && (tail.start === tail.end || /^(where|with)\b/i.test(T(tail)))) {
        return [{ resource: T(resource).toLowerCase(), type: "tenancy" }, tail, resource];
    }
    const [value, finalTail] = take(tail, failures.expectedAssociationLocationValue);
    return [{ resource: T(resource).toLowerCase(), type: type as "compartment" | "tenancy", value: T(value).toLowerCase() }, finalTail, resource];
}
interface PolicyStatementParseStep {
    statement: PolicyStatement;
    warnings: PolicyDiagnostic[];
}

/** Parse and validate one OCI IAM policy statement, raising internal syntax errors. */
function parsePolicyStatementInternal(source: string): PolicyStatementParseStep {
    const all = S(source), input = trim(all);
    if (input.start === input.end) {
        fail(failures.emptyPolicyStatement, input, 0);
    }
    const [typeSpan, afterType] = take(input);
    const type = T(typeSpan).toLowerCase() as StatementType;
    if (!statementTypes.has(type)) {
        fail(failures.invalidStatementType, typeSpan);
    }
    const warnings: PolicyDiagnostic[] = [];
    const [who, principalTail] = principal(afterType, type, warnings);
    let rest = principalTail;
    const parsed: PolicyStatement = { type, principal: who };
    if (type === "define") {
        if (!(who.type === "tenancy" || who.type === "group" || who.type === "dynamic-group")) {
            fail(failures.invalidDefinePrincipal, typeSpan);
        }
        const definition = key(rest, "as");
        if (!definition) {
            fail(failures.expectedDefineAs, rest, 0);
        }
        if (/\s/.test(T(definition))) {
            fail(failures.expectedDefineOcid, definition, definition.end - definition.start);
        }
        if (!ocid(T(definition))) {
            fail(failures.invalidDefineOcid, definition);
        }
        parsed.definition = T(definition).toLowerCase();
        return { statement: parsed, warnings };
    }
    const afterTo = key(rest, "to");
    if (afterTo) {
        rest = afterTo;
    }
    if (rest.source[rest.start] === "{") {
        [parsed.permissions, rest] = permissions(rest, type);
    } else {
        const [verbSpan, afterVerb] = take(rest, failures.expectedPolicyVerb);
        const verb = T(verbSpan).toLowerCase() as Verb;
        if (!verbs.has(verb)) {
            fail(failures.invalidPolicyVerb, verbSpan);
        }
        const [resource, afterResource] = take(afterVerb, failures.expectedPolicyResource);
        if (T(resource).toLowerCase() === "in") {
            fail(failures.expectedPolicyResource, resource);
        }
        if (verb === "associate" && !associatable.has(T(resource).toLowerCase())) {
            fail(failures.invalidAssociateResource, resource);
        }
        parsed.verb = verb;
        parsed.resource = T(resource).toLowerCase();
        rest = afterResource;
    }
    [parsed.location, rest] = location(rest, type, parsed.verb === "associate");
    if (parsed.verb === "associate") {
        const [associated, tail, resource] = association(rest);
        parsed.association = associated;
        rest = tail;
        if ((parsed.resource === "local-peering-gateways") !== (associated.resource === "local-peering-gateways")) {
            fail(failures.mismatchedAssociatedResource, resource);
        }
    }
    if (rest.start !== rest.end) {
        const condition = key(rest, "where");
        if (!condition) {
            fail(failures.unexpectedTextAfterStatement, rest);
        }
        if (condition.start === condition.end) {
            fail(failures.expectedCondition, condition, 0);
        }
        const parsedCondition = parseConditionSpan(condition);
        parsed.condition = parsedCondition.condition;
        warnings.push(...parsedCondition.warnings);
    }
    return { statement: parsed, warnings };
}

/** Parse one statement and report syntax problems and non-fatal warnings as diagnostics. */
export function parsePolicyStatement(source: string): PolicyParseResult {
    try {
        const parsed = parsePolicyStatementInternal(source);
        if (parsed.statement.condition?.kind === "logical") {
            const trailing = /[ \t]+$/.exec(source)?.[0];
            if (trailing) {
                parsed.warnings.push({
                    severity: "warning",
                    message: "logical condition has trailing whitespace before its line ending",
                    offset: source.length - trailing.length,
                    length: trailing.length,
                });
            }
        }
        return { statement: parsed.statement, diagnostics: parsed.warnings };
    } catch (error) {
        if (error instanceof PolicySyntaxError) {
            return { diagnostics: [{ severity: "error", message: error.message, offset: error.offset, length: error.length }] };
        }
        throw error;
    }
}

/** Render a condition using canonical OCI IAM policy syntax. */
function renderCondition(condition: Condition, level?: number): string {
    if (condition.kind === "logical") {
        const indent = "  ".repeat(level ?? 0), child = "  ".repeat((level ?? 0) + 1);
        return `${condition.operator} {\n${condition.conditions.map((item) => `${child}${renderCondition(item, (level ?? 0) + 1)}`).join(",\n")}\n${indent}}`;
    }
    if (condition.kind === "sets-intersect") {
        return `sets-intersect(${condition.left}, ${condition.right})`;
    }
    if (condition.kind === "list") {
        return `${condition.variable} in ( ${condition.values.map((value) => `'${escape(value, "'")}'`).join(", ")} )`;
    }
    if (condition.kind === "literal") {
        return `${condition.variable} ${condition.comparator} '${escape(condition.value, "'")}'`;
    }
    if (condition.kind === "regex") {
        return `${condition.variable} ${condition.comparator} /${escape(condition.value, "/")}/`;
    }
    return `${condition.variable} ${condition.comparator} ${condition.value}`;
}

/** Render a principal, preserving literal versus OCID references. */
function renderPrincipal(principal: Principal): string {
    if (principal.type === "any-user" || principal.type === "any-group") {
        return principal.identifiers.length ? `${principal.type} ${principal.identifiers[0]}` : principal.type;
    }
    const ids = principal.identifiers.map((value) => {
        if (principal.reference === "id") {
            return value;
        }
        if (principal.type === "group" || principal.type === "dynamic-group") {
            return value.split("\0").map((part) => `'${escape(part, "'")}'`).join("/");
        }
        if (principal.type === "tenancy") {
            return `'${escape(value.replace(/^'|'$/g, ""), "'")}'`;
        }
        return value;
    }).join(", ");
    return `${principal.type}${principal.reference === "id" ? " id" : ""} ${ids}`;
}

/** Render the statement location appropriate to its policy statement type. */
function renderLocation(location: Location, type: StatementType, association: boolean): string {
    if (location.type === "any-tenancy") {
        return "any-tenancy";
    }
    if (location.type === "tenancy") {
        return type === "endorse" || (type === "admit" && association) ? `tenancy${location.value ? ` ${location.value}` : ""}` : "tenancy";
    }
    return `compartment${location.reference === "id" ? " id" : ""} ${location.value}`;
}

/** Render an associate-clause target. */
function renderAssociation(value: Association): string { return value.type === "any-tenancy" ? `with ${value.resource} in any-tenancy` : `with ${value.resource} in ${value.type}${value.value ? ` ${value.value}` : ""}`; }
/** Format a parsed policy statement as canonical OCI IAM policy text. */
export function formatPolicyStatement(statement: PolicyStatement): string {
    const principal = renderPrincipal(statement.principal);
    if (statement.type === "define") {
        return `define ${principal} as ${statement.definition}`;
    }
    const action = statement.permissions ? `{${statement.permissions.join(", ")}}` : `${statement.verb} ${statement.resource}`;
    const association = statement.association ? ` ${renderAssociation(statement.association)}` : "";
    const condition = statement.condition ? ` where ${renderCondition(statement.condition)}` : "";
    return `${statement.type} ${principal} to ${action} in ${renderLocation(statement.location!, statement.type, statement.verb === "associate")}${association}${condition}`;
}
