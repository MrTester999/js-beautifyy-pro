import { build } from "esbuild";
import { copyFile } from "node:fs/promises";

await build({
  entryPoints: ["editor/editor-entry.js"],
  outfile: "vendor/editor.bundle.js",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["chrome120"],
  minify: true,
  legalComments: "none",
  sourcemap: false
});

await copyFile("node_modules/codemirror/LICENSE", "vendor/codemirror.LICENSE");
console.log("Bundled CodeMirror 6 JavaScript editor");
