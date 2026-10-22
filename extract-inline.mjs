import { readFile, writeFile } from "node:fs/promises";

const html = await readFile("index.html", "utf8");
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
console.log(`inline scripts: ${scripts.length}`);
const target = scripts[scripts.length - 1];
await writeFile(".verify-inline.js", target);
