import * as esbuild from "esbuild";

const production = process.argv.includes("--production");
const watch = process.argv.includes("--watch");

const context = await esbuild.context({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  outfile: "out/extension.js",
  // 'vscode' is provided by the host at runtime and must not be bundled.
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  // Matches the Electron/Node runtime of VS Code ^1.90.
  target: "node18",
  sourcemap: !production,
  minify: production,
  logLevel: "info",
});

if (watch) {
  await context.watch();
} else {
  await context.rebuild();
  await context.dispose();
}
