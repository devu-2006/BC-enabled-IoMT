const fs = require("fs");
const path = require("path");

/** Collects gasUsed per function so results can be compared later (baseline vs optimized). */
class GasRecorder {
  constructor(label) { this.label = label; this.rows = {}; }
  async rec(name, txPromise) {
    const tx = await txPromise;
    const receipt = await tx.wait();
    this.rows[name] = Number(receipt.gasUsed);
    return receipt;
  }
  save() {
    const dir = path.join(__dirname, "..", "results");
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${this.label}_gas.json`), JSON.stringify(this.rows, null, 2));
    console.table(this.rows);
  }
}
module.exports = { GasRecorder };
