"""Exploratory look at the IDS dataset (Day 1).
Usage:  python ids/01_eda.py ids/data/<your_file>.csv
Writes a text report to results/ids_eda.txt
"""
import sys
import pathlib
import pandas as pd

if len(sys.argv) < 2:
    sys.exit("Usage: python ids/01_eda.py <path-to-csv>")

path = pathlib.Path(sys.argv[1])
df = pd.read_csv(path)
lines = []


def out(s=""):
    print(s)
    lines.append(str(s))


out(f"File: {path.name}")
out(f"Shape (rows, columns): {df.shape}")
out(f"Full-row duplicates: {int(df.duplicated().sum())}")
out(f"Total missing values: {int(df.isna().sum().sum())}")

out("\n--- Columns (dtype | unique values | missing) ---")
for c in df.columns:
    out(f"{c!r:35} {str(df[c].dtype):10} {df[c].nunique():8} {int(df[c].isna().sum()):6}")

out("\n--- Candidate label columns (name contains 'label' or 'attack') ---")
cands = [c for c in df.columns if "label" in c.lower() or "attack" in c.lower()]
for c in cands:
    out(f"\n{c}:")
    out(df[c].value_counts(dropna=False).to_string())

out("\n--- Non-numeric columns (possible identifiers / leakage risks) ---")
obj = [c for c in df.columns if df[c].dtype == "object"]
out(obj if obj else "none")

out("\n--- Constant columns (no information) ---")
const = [c for c in df.columns if df[c].nunique() <= 1]
out(const if const else "none")

out("\n--- First 3 rows (transposed) ---")
out(df.head(3).T.to_string())

pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path("results/ids_eda.txt").write_text("\n".join(lines), encoding="utf-8")
print("\nSaved report to results/ids_eda.txt")