# OCI IAM Policy for VS Code

This extension adds syntax highlighting, parser-backed diagnostics, formatting, and conservative quick fixes for the OCI IAM policy statement language.

> [!IMPORTANT]  
> This parser does not validate the specific policy content, only the syntax and structure. A policy reporting no errors does not mean it is a valid OCI IAM policy.

## Use

Open a policy file and select **OCI IAM Policy** from VS Code's language mode picker. The extension deliberately registers no filename extension as there is not a common offline format for OCI IAM Policies.

Use **Format Document** to canonicalize supported policy statements. It normalizes keywords and permission names, quotes applicable principal names, and formats condition lists consistently. Ordinary statements and simple `where` conditions stay on one line. Logical `where any { ... }` and `where all { ... }` groups are expanded across lines with two-space nested indentation for readability.

The formatter preserves blank lines, standalone comments, the document's line-ending convention, and invalid source. A malformed statement receives an error diagnostic but is not changed, while other valid statements in the document are still formatted.

Documents accept standalone comments between statements: `# ...`, `// ...`, and `/* ... */` (including multi-line blocks). Comments may be indented and are preserved by formatting, but cannot trail a policy statement or appear inside a multiline logical condition. An unterminated standalone block comment extends to the end of the document. A document otherwise contains one statement per nonblank line, except a logical condition block, which can span lines.

## Diagnostics and quick fixes

Diagnostics identify invalid policy constructs at their precise source ranges, including invalid principal types, verbs, OCIDs, locations, condition syntax, and malformed logical blocks. The parser also warns about trailing whitespace after a top-level logical condition, unquoted list literals and comparison literals, and group or dynamic-group names that may unintentionally rely on the Default identity domain.

Where a correction is unambiguous and makes the statement valid, VS Code offers a quick fix. These include close spelling corrections for supported policy vocabulary, inserting explicit `in`, `with`, or `as` keywords, removing an invalid `id` modifier, and adding needed quotes or an explicit identity-domain pairing. Ambiguous, stale, distant, or unrelated diagnostics intentionally receive no fix.

## Development

```powershell
npm.cmd install
npm.cmd test
npm.cmd run package
```

The package command produces `oci-iam-policy-0.1.0.vsix` in this directory. Install it with VS Code's **Extensions: Install from VSIX...** command.
