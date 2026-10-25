// Builds the static site into web/dist: bundles the TypeScript, compiles poltergift.wasm from the
// Rust workspace, and copies the deployment record and static assets.
import { execFileSync, spawnSync } from "node:child_process";
import { copyFileSync, cpSync, existsSync, mkdirSync, rmSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const root = resolve(web, "..");
const dist = join(web, "dist");

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await build({
  entryPoints: [join(web, "src/main.ts")],
  bundle: true,
  minify: true,
  format: "esm",
  target: "es2022",
  outfile: join(dist, "app.js"),
  logLevel: "warning",
});

const wasmOut = join(dist, "poltergift.wasm");
if (!process.env.POLTERGIFT_SKIP_CARGO) {
  execFileSync("cargo", ["build", "-q", "-p", "poltergift-wasm", "--target", "wasm32-unknown-unknown", "--release"], {
    cwd: root,
    stdio: "inherit",
  });
}
const wasmIn = join(root, "target/wasm32-unknown-unknown/release/poltergift_wasm.wasm");
const wasmOpt = existsSync(join(web, "node_modules/.bin/wasm-opt")) ? join(web, "node_modules/.bin/wasm-opt") : "wasm-opt";
const opt = spawnSync(wasmOpt, ["-Oz", "--enable-bulk-memory", "--enable-sign-ext", "--enable-nontrapping-float-to-int", "--enable-mutable-globals", "--strip-debug", "--strip-producers", wasmIn, "-o", wasmOut]);
if (opt.status !== 0) copyFileSync(wasmIn, wasmOut);

copyFileSync(join(web, "index.html"), join(dist, "index.html"));
copyFileSync(join(web, "src/style.css"), join(dist, "style.css"));
cpSync(join(web, "public"), dist, { recursive: true });
const deployment = join(root, "deployments/esmeralda.json");
if (existsSync(deployment)) copyFileSync(deployment, join(dist, "deployments.json"));

const kb = (f) => `${(statSync(join(dist, f)).size / 1024).toFixed(0)} KB`;
console.log(`web/dist ready: app.js ${kb("app.js")}, poltergift.wasm ${kb("poltergift.wasm")}${opt.status === 0 ? " (wasm-opt)" : ""}`);
