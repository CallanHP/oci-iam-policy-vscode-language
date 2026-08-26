# OCI IAM Policy for VS Code

This extension adds syntax highlighting, strict diagnostics, and formatting for the OCI IAM policy statement subset implemented by this repository's Python parser.

## Use

Open a policy file and select **OCI IAM Policy** from VS Code's language mode picker. The extension deliberately registers no filename extension, so it does not claim generic `.policy` files.

Use **Format Document** to canonicalize statements. Ordinary statements and simple `where` conditions are one line. Logical `where any { ... }` and `where all { ... }` groups are formatted across lines with two-space indentation. Invalid statements receive an error diagnostic and are not changed by the formatter.

Documents accept standalone comments between statements: `# ...`, `// ...`, and `/* ... */` (including multi-line blocks). Comments may be indented and are preserved by formatting, but cannot trail a policy statement or appear inside a multiline logical condition. A document otherwise contains one statement per nonblank line, except a logical condition block, which can span lines.

## Development

```powershell
npm.cmd install
npm.cmd test
npm.cmd run package
```

The package command produces `oci-iam-policy-0.1.0.vsix` in this directory. Install it with VS Code's **Extensions: Install from VSIX...** command.
