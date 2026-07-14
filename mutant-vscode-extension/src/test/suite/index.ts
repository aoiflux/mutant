import * as path from "node:path";

import Mocha from "mocha";
import { glob } from "glob";

export async function run(): Promise<void> {
  const mocha = new Mocha({
    ui: "tdd",
    color: true,
    timeout: 20_000,
  });

  const testsRoot = path.resolve(__dirname);
  const testFiles = await glob("**/*.test.js", {
    cwd: testsRoot,
  });

  for (const file of testFiles) {
    mocha.addFile(path.resolve(testsRoot, file));
  }

  await new Promise<void>((resolve, reject) => {
    mocha.run((failures: number) => {
      if (failures > 0) {
        reject(new Error(`${failures} test(s) failed.`));
        return;
      }
      resolve();
    });
  });
}
