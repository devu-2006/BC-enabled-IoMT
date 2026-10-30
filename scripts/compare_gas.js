// Usage: node scripts/compare_gas.js   (after running `npx hardhat test`)
const fs = require("fs");
const path = require("path");
const dir = path.join(__dirname, "..", "results");
const base = JSON.parse(fs.readFileSync(path.join(dir, "baseline_gas.json"), "utf8"));
const opt = JSON.parse(fs.readFileSync(path.join(dir, "optimized_gas.json"), "utf8"));

const rows = [];
let md = "| Function | Baseline gas | Optimized gas | Saved |\n|---|---:|---:|---:|\n";
for (const k of Object.keys(base)) {
    if (!(k in opt)) continue;
    const saved = ((base[k] - opt[k]) / base[k]) * 100;
    rows.push({ function: k, baseline: base[k], optimized: opt[k], "saved_%": saved.toFixed(1) });
    md += `| ${k} | ${base[k]} | ${opt[k]} | ${saved.toFixed(1)}% |\n`;
}
// batch registration vs 4 separate baseline registrations
const b4 = Object.keys(base).filter((k) => k.startsWith("registerEntity(")).reduce((s, k) => s + base[k], 0);
if (opt["registerEntities(4 batch)"]) {
    const o = opt["registerEntities(4 batch)"];
    const saved = ((b4 - o) / b4) * 100;
    rows.push({ function: "register 4 entities (baseline: 4 txs, optimized: 1 batch tx)", baseline: b4, optimized: o, "saved_%": saved.toFixed(1) });
    md += `| register 4 entities (4 txs vs 1 batch tx) | ${b4} | ${o} | ${saved.toFixed(1)}% |\n`;
}
console.table(rows);
const extra = Object.keys(opt).filter((k) => !(k in base) && k !== "registerEntities(4 batch)");
if (extra.length) {
    md += "\nNew in the optimized contract (no baseline equivalent):\n\n| Function | Gas |\n|---|---:|\n";
    extra.forEach((k) => (md += `| ${k} | ${opt[k]} |\n`));
    console.log("\nNew functions:", Object.fromEntries(extra.map((k) => [k, opt[k]])));
}
fs.writeFileSync(path.join(dir, "gas_comparison.md"), md);
console.log("\nSaved results/gas_comparison.md");