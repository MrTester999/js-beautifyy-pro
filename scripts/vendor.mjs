import { copyFile, mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
await mkdir(path.join(root, "vendor"), { recursive: true });
await Promise.all([
  copyFile(
    path.join(root, "node_modules/js-beautify/js/lib/beautifier.min.js"),
    path.join(root, "vendor/beautifier.min.js")
  ),
  copyFile(
    path.join(root, "node_modules/js-beautify/LICENSE"),
    path.join(root, "vendor/js-beautify.LICENSE")
  )
]);
console.log("Vendored js-beautify 2.0.3");
