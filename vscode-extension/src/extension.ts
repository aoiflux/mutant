import * as vscode from "vscode";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  CloseAction,
  ErrorAction,
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
} from "vscode-languageclient/node";

let client: LanguageClient | undefined;
let lspState: "starting" | "running" | "failed" | "stopped" = "stopped";
let lspLastError = "";
let lspCommand = "";
let lspOutput: vscode.OutputChannel | undefined;
const maxBufferedLogLines = 1000;
const lspLogBuffer: string[] = [];
const restartBackoffWindowMs = 3 * 60 * 1000;
const restartBackoffMaxCrashes = 5;
const lspCrashTimestamps: number[] = [];

type CrashWindowStatus = {
  crashCount: number;
  blocked: boolean;
  warningMessage: string;
};

type BinaryCandidate = {
  path: string;
  mtimeMs: number;
};

export async function activate(context: vscode.ExtensionContext): Promise<void> {
  lspOutput = vscode.window.createOutputChannel("Mutant LSP");
  context.subscriptions.push(lspOutput);

  applyMutantFormattingPreferences();

  context.subscriptions.push(
    vscode.commands.registerCommand("mutant.restartLsp", async () => {
      await restartLsp();
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("mutant.format.onType.enabled")) {
        applyMutantFormattingPreferences();
      }
    })
  );

  logLsp("Activating extension.");
  await startLspClient(context, true);

  context.subscriptions.push(
    vscode.commands.registerCommand("mutant.openSmokeFile", async () => {
      await openSmokeFile();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("mutant.runSmokeChecks", async () => {
      await runSmokeChecks();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("mutant.showLspStatus", async () => {
      await showLspStatus();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("mutant.showLspLogs", async () => {
      showLspLogs();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("mutant.copyLspLogs", async () => {
      await copyLspLogs();
    })
  );
}

function applyMutantFormattingPreferences(): void {
  const mutantConfig = vscode.workspace.getConfiguration("mutant");
  const enabled = mutantConfig.get<boolean>("format.onType.enabled", false);
  const editorConfig = vscode.workspace.getConfiguration("editor", { languageId: "mutant" } as vscode.ConfigurationScope);
  void editorConfig.update("formatOnType", enabled, vscode.ConfigurationTarget.Workspace);
}

export async function deactivate(): Promise<void> {
  await stopLspClient();
  lspState = "stopped";
  logLsp("Extension deactivated.");
}

function resolveLanguageServerCommand(config: vscode.WorkspaceConfiguration): string {
  const configured = config.get<string>("languageServer.path", "").trim();
  const folders = vscode.workspace.workspaceFolders ?? [];
  const roots = folders.map((folder) => folder.uri.fsPath);
  return resolveLanguageServerCommandFromInputs(configured, roots, process.platform);
}

function resolveLanguageServerCommandFromInputs(
  configured: string,
  workspaceRoots: string[],
  platform: NodeJS.Platform
): string {
  const trimmedConfigured = configured.trim();
  if (trimmedConfigured.length > 0) {
    return trimmedConfigured;
  }

  const searchDirectories = new Set<string>();
  for (const root of workspaceRoots) {
    searchDirectories.add(root);
    searchDirectories.add(resolve(root, ".."));
  }

  const latest = findLatestServerBinary(Array.from(searchDirectories));
  if (latest) {
    return latest;
  }

  if (platform === "win32") {
    return "mlsp.exe";
  }
  return "mlsp";
}

function findLatestServerBinary(searchDirectories: string[]): string | undefined {
  let latest: BinaryCandidate | undefined;

  for (const directory of searchDirectories) {
    if (!existsSync(directory)) {
      continue;
    }

    let entries: string[];
    try {
      entries = readdirSync(directory);
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (!isLanguageServerBinaryName(entry)) {
        continue;
      }

      const fullPath = join(directory, entry);
      let stats: ReturnType<typeof statSync>;
      try {
        stats = statSync(fullPath);
      } catch {
        continue;
      }

      if (!stats.isFile()) {
        continue;
      }

      if (!latest || stats.mtimeMs > latest.mtimeMs) {
        latest = {
          path: fullPath,
          mtimeMs: stats.mtimeMs,
        };
      }
    }
  }

  return latest?.path;
}

function isLanguageServerBinaryName(name: string): boolean {
  const lower = name.toLowerCase();
  const base = lower.endsWith(".exe") ? lower.slice(0, -4) : lower;
  const canonical = "mlsp";
  const legacy = "mutantlsp";

  if (base === canonical || base === legacy) {
    return true;
  }

  // Accept versioned artifacts like mlsp-v1.2.3 or mutantlsp-v1.2.3.
  const prefix = base.startsWith(canonical)
    ? canonical
    : base.startsWith(legacy)
      ? legacy
      : "";
  if (prefix === "") {
    return false;
  }

  if (base.length == prefix.length) {
    return true;
  }

  const separator = base.charAt(prefix.length);
  return separator === "-" || separator === "_" || separator === ".";
}

async function openSmokeFile(): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const folder of folders) {
    const smokePath = join(folder.uri.fsPath, "smoke", "feature-smoke.mut");
    if (!existsSync(smokePath)) {
      continue;
    }

    const doc = await vscode.workspace.openTextDocument(smokePath);
    await vscode.window.showTextDocument(doc, { preview: false });
    return;
  }

  void vscode.window.showWarningMessage(
    "Could not find smoke/feature-smoke.mut in the current workspace."
  );
}

async function runSmokeChecks(): Promise<void> {
  const task = await findOrCreateSmokeTask();
  if (!task) {
    void vscode.window.showWarningMessage(
      "Could not determine a workspace to run smoke checks."
    );
    return;
  }

  void vscode.window.showInformationMessage("Running Mutant LSP smoke checks...");
  const exitCode = await executeTaskAndWait(task);
  if (exitCode === 0) {
    void vscode.window.showInformationMessage("Mutant LSP smoke checks passed.");
    return;
  }

  if (typeof exitCode === "number") {
    void vscode.window.showErrorMessage(
      `Mutant LSP smoke checks failed (exit code ${exitCode}).`
    );
    return;
  }

  void vscode.window.showWarningMessage(
    "Mutant LSP smoke checks finished without an exit code."
  );
}

async function findOrCreateSmokeTask(): Promise<vscode.Task | undefined> {
  const tasks = await vscode.tasks.fetchTasks();
  const existing = tasks.find((task) => task.name === "smoke: lsp features");
  if (existing) {
    return existing;
  }

  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    return undefined;
  }

  const root = resolve(folder.uri.fsPath, "..");
  const definition: vscode.TaskDefinition = {
    type: "shell",
  };

  return new vscode.Task(
    definition,
    folder,
    "smoke: lsp features",
    "mutant",
    new vscode.ShellExecution("go", [
      "test",
      "./lsp/internal/server",
      "-run",
      "TestDidOpenPublishesDuplicateTopLevelDeclarationLintDiagnostic|TestSemanticTokensFullReturnsData|TestDocumentFormattingNormalizesWhitespace",
      "-v",
    ], {
      cwd: root,
    })
  );
}

async function executeTaskAndWait(task: vscode.Task): Promise<number | undefined> {
  const execution = await vscode.tasks.executeTask(task);
  return new Promise<number | undefined>((resolveExitCode) => {
    const disposable = vscode.tasks.onDidEndTaskProcess((event) => {
      if (event.execution !== execution) {
        return;
      }
      disposable.dispose();
      resolveExitCode(event.exitCode);
    });
  });
}

async function showLspStatus(): Promise<void> {
  if (lspState === "running") {
    void vscode.window.showInformationMessage(`Mutant LSP is running (command: ${lspCommand}).`);
    return;
  }

  if (lspState === "starting") {
    void vscode.window.showInformationMessage(`Mutant LSP is starting (command: ${lspCommand}).`);
    return;
  }

  if (lspState === "failed") {
    const detail = lspLastError.length > 0 ? ` Last error: ${lspLastError}` : "";
    void vscode.window.showWarningMessage(
      `Mutant LSP failed to start (command: ${lspCommand}).${detail}`
    );
    return;
  }

  void vscode.window.showInformationMessage("Mutant LSP is stopped.");
}

async function restartLsp(): Promise<void> {
  logLsp("Manual restart requested.");
  await stopLspClient();
  lspCrashTimestamps.length = 0;
  await startLspClient(undefined, false);
}

async function startLspClient(context: vscode.ExtensionContext | undefined, showStartedMessage: boolean): Promise<void> {
  const config = vscode.workspace.getConfiguration("mutant");
  const command = resolveLanguageServerCommand(config);
  const args = config.get<string[]>("languageServer.args", []);

  lspCommand = command;
  lspState = "starting";
  lspLastError = "";
  logLsp(`Starting language server. Command: ${command}`);
  if (args.length > 0) {
    logLsp(`Server args: ${args.join(" ")}`);
  }

  const serverOptions: ServerOptions = {
    command,
    args,
    options: {
      shell: false,
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: "file", language: "mutant" },
      { scheme: "untitled", language: "mutant" },
    ],
    synchronize: {
      configurationSection: "mutant",
    },
    errorHandler: {
      error: (error) => {
        const message = error instanceof Error ? error.message : String(error);
        lspLastError = message;
        logLsp(`Client transport error: ${message}`);
        return { action: ErrorAction.Continue };
      },
      closed: () => {
        const status = recordCrashAndGetStatus(Date.now());
        if (status.blocked) {
          lspState = "failed";
          lspLastError = status.warningMessage;
          logLsp(status.warningMessage);
          void vscode.window.showWarningMessage(status.warningMessage);
          return { action: CloseAction.DoNotRestart, handled: true };
        }

        logLsp(
          `Language server connection closed. Auto-restart attempt ${status.crashCount}/${restartBackoffMaxCrashes} in rolling window.`
        );
        return { action: CloseAction.Restart };
      },
    },
  };

  try {
    const nextClient = new LanguageClient(
      "mutantLanguageServer",
      "Mutant Language Server",
      serverOptions,
      clientOptions
    );

    await nextClient.start();
    client = nextClient;
    lspState = "running";
    logLsp("Language server started successfully.");
    if (showStartedMessage) {
      void vscode.window.showInformationMessage(`Mutant LSP started (command: ${command}).`);
    }
    if (context) {
      context.subscriptions.push(nextClient);
    }
  } catch (err) {
    client = undefined;
    lspState = "failed";
    const message = err instanceof Error ? err.message : String(err);
    lspLastError = message;
    logLsp(`Language server failed to start: ${message}`);
    void vscode.window.showErrorMessage(
      `Failed to start Mutant language server (command: ${command}). ${message}`
    );
  }
}

async function stopLspClient(): Promise<void> {
  if (!client) {
    lspState = "stopped";
    logLsp("Stop requested with no active language client.");
    return;
  }

  try {
    await client.stop();
    logLsp("Language server stopped.");
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logLsp(`Language server stop failed: ${message}`);
  } finally {
    client = undefined;
    lspState = "stopped";
  }
}

function showLspLogs(): void {
  if (!lspOutput) {
    void vscode.window.showWarningMessage("Mutant LSP log output channel is not available.");
    return;
  }
  lspOutput.show(true);
}

async function copyLspLogs(): Promise<void> {
  if (lspLogBuffer.length === 0) {
    void vscode.window.showWarningMessage("No Mutant LSP logs are available to copy yet.");
    return;
  }

  const input = await vscode.window.showInputBox({
    prompt: "How many recent Mutant LSP log lines should be copied?",
    value: "50",
    validateInput: (value) => {
      const trimmed = value.trim();
      const parsed = Number.parseInt(trimmed, 10);
      if (trimmed.length === 0 || Number.isNaN(parsed) || parsed <= 0) {
        return "Enter a positive integer.";
      }
      return undefined;
    },
  });

  if (input === undefined) {
    return;
  }

  const requested = Number.parseInt(input.trim(), 10);
  const count = Number.isNaN(requested) || requested <= 0 ? 50 : requested;
  const lines = lspLogBuffer.slice(-count);
  await vscode.env.clipboard.writeText(lines.join("\n"));
  void vscode.window.showInformationMessage(`Copied ${lines.length} Mutant LSP log line(s) to clipboard.`);
}

function logLsp(message: string): void {
  const line = `[${new Date().toISOString()}] ${message}`;
  lspLogBuffer.push(line);
  if (lspLogBuffer.length > maxBufferedLogLines) {
    lspLogBuffer.shift();
  }
  if (!lspOutput) {
    return;
  }
  lspOutput.appendLine(line);
}

function recordCrashAndGetStatus(now: number): CrashWindowStatus {
  lspCrashTimestamps.push(now);
  while (lspCrashTimestamps.length > 0 && now - lspCrashTimestamps[0] > restartBackoffWindowMs) {
    lspCrashTimestamps.shift();
  }

  const crashCount = lspCrashTimestamps.length;
  if (crashCount < restartBackoffMaxCrashes) {
    return {
      crashCount,
      blocked: false,
      warningMessage: "",
    };
  }

  const windowMinutes = Math.floor(restartBackoffWindowMs / 60000);
  return {
    crashCount,
    blocked: true,
    warningMessage: `Mutant LSP crashed ${crashCount} times in ${windowMinutes} minute(s). Auto-restart is disabled until you run 'Mutant: Restart LSP'.`,
  };
}

export const __test = {
  resetCrashTracking(): void {
    lspCrashTimestamps.length = 0;
    lspState = "stopped";
    lspLastError = "";
  },

  recordCrashAt(now: number): CrashWindowStatus {
    return recordCrashAndGetStatus(now);
  },

  resolveLanguageServerCommandFromInputs(
    configured: string,
    workspaceRoots: string[],
    platform: NodeJS.Platform
  ): string {
    return resolveLanguageServerCommandFromInputs(configured, workspaceRoots, platform);
  },
};
