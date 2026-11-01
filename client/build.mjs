// Builds the browser scripts: boot.js and sw.js as classic scripts (IIFE,
// ES2020), and dist/seal-node.mjs (ESM) for the Node interop tests.
import { build } from "esbuild";

const common = { bundle: true, target: "es2020", legalComments: "none", logLevel: "warning" };
await build({ ...common, entryPoints: ["src/boot.ts"], outfile: "dist/boot.js", format: "iife", minify: true });
await build({ ...common, entryPoints: ["src/sw.ts"], outfile: "dist/sw.js", format: "iife", minify: true });
await build({ ...common, entryPoints: ["src/sw-kill.ts"], outfile: "dist/sw-kill.js", format: "iife", minify: true });
await build({ ...common, entryPoints: ["src/node.ts"], outfile: "dist/seal-node.mjs", format: "esm", platform: "neutral", target: "es2022" });
console.log("client built");
