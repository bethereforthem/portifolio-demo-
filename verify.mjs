// Temporary verification script (removed after the run).
const base = "http://localhost:3000";

const checks = [
  ["/", [200], "text/html"],
  ["/login.html", [200], "text/html"],
  ["/photos/My_passport_photo.png", [200], "image/png"],
  ["/api/threat-search?q=ransomware%20healthcare", [200, 503], "application/json"],
  ["/api/threat-search?q=", [400], "application/json"],
  ["/.env", [404], "text/plain"],
  ["/server.mjs", [404], "text/plain"],
  ["/package.json", [404], "text/plain"],
  ["/lib/exa-search.mjs", [404], "text/plain"],
];

let failures = 0;
for (const [path, okStatuses, type] of checks) {
  const res = await fetch(base + path);
  const body = await res.text();
  const statusOk = okStatuses.includes(res.status);
  const typeOk = (res.headers.get("content-type") || "").includes(type);
  if (!statusOk || !typeOk) failures++;
  console.log(
    `${statusOk && typeOk ? "PASS" : "FAIL"} ${res.status} ${path} [${res.headers.get("content-type")}] ${body.slice(0, 140).replace(/\s+/g, " ")}`,
  );
}

const page = await (await fetch(base + "/")).text();
for (const needle of ["id=\"intel\"", "intelForm", "api/threat-search", "EXA_API_KEY"]) {
  const found = page.includes(needle);
  if (needle === "EXA_API_KEY" ? found : !found) failures++;
  console.log(`${needle === "EXA_API_KEY" ? (found ? "FAIL" : "PASS") : found ? "PASS" : "FAIL"} page contains ${needle}`);
}

console.log(failures === 0 ? "ALL_OK" : `FAILURES=${failures}`);
