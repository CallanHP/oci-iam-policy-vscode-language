import * as vscode from "vscode";
import { formatDocument, logicalTrailingWhitespace, splitStatements, statementError } from "./document";

const languageId = "oci-iam-policy";

function updateDiagnostics(document: vscode.TextDocument, collection: vscode.DiagnosticCollection): void {
  if (document.languageId !== languageId) return;
  const diagnostics: vscode.Diagnostic[] = [];
  const source = document.getText();
  const spans = splitStatements(source);
  for (let index = 0; index < spans.length; index += 1) {
    const span = spans[index];
    const message = statementError(span);
    const range = new vscode.Range(document.positionAt(span.start), document.positionAt(span.end));
    if (message) diagnostics.push(new vscode.Diagnostic(range, message, vscode.DiagnosticSeverity.Error));
    const trailingWhitespace = logicalTrailingWhitespace(span);
    if (trailingWhitespace) {
      diagnostics.push(new vscode.Diagnostic(
        new vscode.Range(document.positionAt(span.end - trailingWhitespace.length), document.positionAt(span.end)),
        "logical condition has trailing whitespace before its line ending",
        vscode.DiagnosticSeverity.Warning,
      ));
    }
  }
  collection.set(document.uri, diagnostics);
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("oci-iam-policy"); context.subscriptions.push(diagnostics);
  const refresh = (document: vscode.TextDocument): void => updateDiagnostics(document, diagnostics);
  vscode.workspace.textDocuments.forEach(refresh);
  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(refresh), vscode.workspace.onDidChangeTextDocument((event) => refresh(event.document)), vscode.workspace.onDidCloseTextDocument((document) => diagnostics.delete(document.uri)));
  context.subscriptions.push(vscode.languages.registerDocumentFormattingEditProvider(languageId, { provideDocumentFormattingEdits(document): vscode.TextEdit[] { const source = document.getText(); const formatted = formatDocument(source); return formatted === source ? [] : [vscode.TextEdit.replace(new vscode.Range(document.positionAt(0), document.positionAt(source.length)), formatted)]; } }));
}

export function deactivate(): void {}
