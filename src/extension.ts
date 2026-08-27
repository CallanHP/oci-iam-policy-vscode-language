import * as vscode from "vscode";
import { formatDocument, splitStatements, statementDiagnostics } from "./document";
import { statementQuickFix } from "./quick-fixes";

const languageId = "oci-iam-policy";
const severity: Record<"error" | "warning" | "information" | "hint", vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};

function updateDiagnostics(document: vscode.TextDocument, collection: vscode.DiagnosticCollection): void {
  if (document.languageId !== languageId) return;
  const diagnostics: vscode.Diagnostic[] = [];
  const source = document.getText();
  const spans = splitStatements(source);
  for (let index = 0; index < spans.length; index += 1) {
    const span = spans[index];
    for (const diagnostic of statementDiagnostics(span)) {
      const start = span.start + diagnostic.offset;
      const end = start + diagnostic.length;
      const range = new vscode.Range(document.positionAt(start), document.positionAt(end));
      const vscodeDiagnostic = new vscode.Diagnostic(range, diagnostic.message, severity[diagnostic.severity]);
      vscodeDiagnostic.code = diagnostic.code;
      diagnostics.push(vscodeDiagnostic);
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
  context.subscriptions.push(vscode.languages.registerCodeActionsProvider(languageId, {
    provideCodeActions(document, _range, context): vscode.CodeAction[] {
      const actions: vscode.CodeAction[] = [];
      for (const diagnostic of context.diagnostics) {
        if (typeof diagnostic.code !== "string") continue;
        const offset = document.offsetAt(diagnostic.range.start);
        const spans = splitStatements(document.getText());
        const span = spans.find((item) => offset >= item.start && offset <= item.end);
        if (!span) continue;
        const parserDiagnostic = statementDiagnostics(span).find((item) => item.code === diagnostic.code && item.message === diagnostic.message);
        if (!parserDiagnostic) continue;
        const start = span.start + parserDiagnostic.offset;
        const end = start + parserDiagnostic.length;
        if (document.offsetAt(diagnostic.range.start) !== start || document.offsetAt(diagnostic.range.end) !== end) continue;
        const fix = statementQuickFix(span, parserDiagnostic);
        if (!fix) continue;
        const action = new vscode.CodeAction(fix.title, vscode.CodeActionKind.QuickFix);
        action.diagnostics = [diagnostic];
        action.edit = new vscode.WorkspaceEdit();
        action.edit.replace(document.uri, new vscode.Range(document.positionAt(span.start + fix.offset), document.positionAt(span.start + fix.offset + fix.length)), fix.text);
        actions.push(action);
      }
      return actions;
    },
  }, { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }));
}

export function deactivate(): void {}
