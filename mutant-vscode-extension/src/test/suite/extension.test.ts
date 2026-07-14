import * as assert from "node:assert";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync, utimesSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

import * as vscode from "vscode";
import { __test } from "../../extension";

suite("Mutant extension integration", () => {
  test("activates and contributes expected commands", async () => {
    const extension = vscode.extensions.getExtension("mutant.mutant-language-tools");
    assert.ok(extension, "extension should be installed in test host");

    await extension.activate();
    assert.strictEqual(extension.isActive, true, "extension should be active");

    const commands = await vscode.commands.getCommands(true);
    const expectedCommands = [
      "mutant.openSmokeFile",
      "mutant.runSmokeChecks",
      "mutant.showLspStatus",
      "mutant.showLspLogs",
      "mutant.restartLsp",
      "mutant.copyLspLogs",
    ];

    for (const command of expectedCommands) {
      assert.ok(commands.includes(command), `expected command ${command} to be registered`);
    }
  });

  test("declares mutant language with .mut extension", async () => {
    const extension = vscode.extensions.getExtension("mutant.mutant-language-tools");
    assert.ok(extension, "extension should be installed in test host");

    await extension.activate();

    const packageJson = extension.packageJSON as {
      contributes?: { languages?: Array<{ id?: string; extensions?: string[] }> };
    };

    const languages = packageJson.contributes?.languages ?? [];
    const mutantLanguage = languages.find((language) => language.id === "mutant");
    assert.ok(mutantLanguage, "mutant language contribution should exist");
    assert.ok(
      mutantLanguage.extensions?.includes(".mut"),
      "mutant language should include .mut file extension"
    );
  });

  test("declares format-on-save defaults and nesting lint configuration", async () => {
    const extension = vscode.extensions.getExtension("mutant.mutant-language-tools");
    assert.ok(extension, "extension should be installed in test host");

    await extension.activate();

    const packageJson = extension.packageJSON as {
      contributes?: {
        configurationDefaults?: Record<string, Record<string, unknown>>;
        configuration?: { properties?: Record<string, unknown> };
      };
    };

    const configDefaults = packageJson.contributes?.configurationDefaults ?? {};
    assert.strictEqual(
      configDefaults["[mutant]"]?.["editor.formatOnSave"],
      true,
      "mutant files should default to format on save"
    );

    const props = packageJson.contributes?.configuration?.properties ?? {};
    assert.ok(
      Object.prototype.hasOwnProperty.call(props, "mutant.lint.rules.nestingComplexity.severity"),
      "nesting complexity lint setting should be contributed"
    );

    assert.ok(
      Object.prototype.hasOwnProperty.call(props, "mutant.format.onType.enabled"),
      "on-type formatting setting should be contributed"
    );

    assert.strictEqual(
      configDefaults["[mutant]"]?.["editor.formatOnType"],
      false,
      "mutant files should default to format on type disabled"
    );
  });

  test("restart backoff only blocks after threshold crashes in window", () => {
    __test.resetCrashTracking();

    const start = Date.now();
    for (let i = 0; i < 4; i++) {
      const status = __test.recordCrashAt(start + i * 10_000);
      assert.strictEqual(status.blocked, false, `crash ${i + 1} should not block restarts`);
      assert.strictEqual(status.crashCount, i + 1, `crash ${i + 1} should be counted`);
    }

    const blocked = __test.recordCrashAt(start + 40_000);
    assert.strictEqual(blocked.blocked, true, "5th crash in rolling window should block restarts");
    assert.match(blocked.warningMessage, /Auto-restart is disabled/, "should include operator guidance");
  });

  test("restart backoff window expires old crash entries", () => {
    __test.resetCrashTracking();

    const start = Date.now();
    for (let i = 0; i < 4; i++) {
      const status = __test.recordCrashAt(start + i * 15_000);
      assert.strictEqual(status.blocked, false);
    }

    const outsideWindow = start + 241_000;
    const statusAfterWindow = __test.recordCrashAt(outsideWindow);
    assert.strictEqual(
      statusAfterWindow.blocked,
      false,
      "a crash after the rolling window should not be treated as a loop"
    );
    assert.strictEqual(statusAfterWindow.crashCount, 1, "old crashes should be pruned from window count");
  });

  test("auto-detect picks latest mlsp binary by modified time", () => {
    const workspaceRoot = mkdtempSync(join(tmpdir(), "mutant-lsp-workspace-"));
    const parentRoot = mkdtempSync(join(tmpdir(), "mutant-lsp-parent-"));

    try {
      const older = join(workspaceRoot, "mlsp.exe");
      const newer = join(parentRoot, "mlsp-v1.2.3.exe");

      writeFileSync(older, "older");
      writeFileSync(newer, "newer");

      utimesSync(older, new Date(1_000), new Date(1_000));
      utimesSync(newer, new Date(2_000), new Date(2_000));

      const selected = __test.resolveLanguageServerCommandFromInputs(
        "",
        [workspaceRoot, join(parentRoot, "child")],
        "win32",
        "x64"
      );

      assert.strictEqual(selected, newer, "expected newest local binary to be selected");
    } finally {
      rmSync(workspaceRoot, { recursive: true, force: true });
      rmSync(parentRoot, { recursive: true, force: true });
    }
  });

  test("configured language server path overrides auto-detection", () => {
    const selected = __test.resolveLanguageServerCommandFromInputs(
      "  C:/tools/mlsp.exe  ",
      ["C:/repo"],
      "win32",
      "x64"
    );

    assert.strictEqual(selected, "C:/tools/mlsp.exe");
  });

  test("auto-detect still accepts legacy mutantlsp binary names", () => {
    const workspaceRoot = mkdtempSync(join(tmpdir(), "mutant-lsp-legacy-workspace-"));

    try {
      const legacy = join(workspaceRoot, "mutantlsp-v0.9.0.exe");
      writeFileSync(legacy, "legacy");
      utimesSync(legacy, new Date(3_000), new Date(3_000));

      const selected = __test.resolveLanguageServerCommandFromInputs("", [workspaceRoot], "win32", "x64");
      assert.strictEqual(selected, legacy, "expected legacy mutantlsp binary to remain discoverable");
    } finally {
      rmSync(workspaceRoot, { recursive: true, force: true });
    }
  });

  test("prefers bundled platform binary when present", () => {
    const extensionRoot = mkdtempSync(join(tmpdir(), "mutant-ext-root-"));

    try {
      mkdirSync(join(extensionRoot, "bin"), { recursive: true });
      const bundled = join(extensionRoot, "bin", "mlsp-windows-amd64.exe");
      writeFileSync(bundled, "bundled");

      const selected = __test.resolveLanguageServerCommandFromInputs(
        "",
        [join(extensionRoot, "workspace")],
        "win32",
        "x64",
        extensionRoot
      );

      assert.strictEqual(selected, bundled, "expected bundled binary to be selected first");
    } finally {
      rmSync(extensionRoot, { recursive: true, force: true });
    }
  });

  test("maps platform and arch to release binary names", () => {
    assert.strictEqual(__test.bundledLanguageServerBinaryName("win32", "x64"), "mlsp-windows-amd64.exe");
    assert.strictEqual(__test.bundledLanguageServerBinaryName("win32", "arm64"), "mlsp-windows-arm64.exe");
    assert.strictEqual(__test.bundledLanguageServerBinaryName("linux", "x64"), "mlsp-linux-amd64");
    assert.strictEqual(__test.bundledLanguageServerBinaryName("linux", "arm64"), "mlsp-linux-arm64");
    assert.strictEqual(__test.bundledLanguageServerBinaryName("darwin", "x64"), "mlsp-darwin-amd64");
    assert.strictEqual(__test.bundledLanguageServerBinaryName("darwin", "arm64"), "mlsp-darwin-arm64");
    assert.strictEqual(__test.bundledLanguageServerBinaryName("freebsd", "x64"), undefined);
    assert.strictEqual(__test.bundledLanguageServerBinaryName("linux", "arm"), undefined);
  });
});
