"""Leakage and shortcut check for the IDS dataset (Day 1).
Usage:  python ids/02_leakage_check.py ids/data/<your_file>.csv
Writes a text report to results/ids_leakage.txt
"""
import sys
import pathlib
import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import roc_auc_score, f1_score

if len(sys.argv) < 2:
    sys.exit("Usage: python ids/02_leakage_check.py <path-to-csv>")

df = pd.read_csv(sys.argv[1])
TARGET = "Label"
lines = []


def out(s=""):
    print(s)
    lines.append(str(s))


# 1. Non-numeric columns (works for both 'object' and 'str' dtypes)
nonnum = list(df.select_dtypes(exclude="number").columns)
out(f"Non-numeric columns: {nonnum}")

# 2. Majority-class baseline: any model must beat this accuracy
maj = df[TARGET].value_counts(normalize=True).max()
out(f"\nMajority-class accuracy (always predict 'normal'): {maj:.4f}")
out(f"Attack share: {1 - maj:.4f}")

# 3. Label vs Attack Category (the category column must NOT be used as a feature)
if "Attack Category" in df.columns:
    out("\n--- Attack Category vs Label (category is derived from the label -> drop it) ---")
    out(pd.crosstab(df["Attack Category"], df[TARGET]).to_string())

# 4. Low-cardinality text columns vs label
out("\n--- Low-cardinality text columns vs Label ---")
for c in nonnum:
    if c != "Attack Category" and df[c].nunique() <= 10:
        out(f"\n{c}:")
        out(pd.crosstab(df[c], df[TARGET]).to_string())

# 5. Single-feature models: a feature that alone predicts the label is a shortcut
feats = {}
for c in df.columns:
    if c in (TARGET, "Attack Category") or df[c].nunique() <= 1:
        continue
    s = df[c]
    if c in nonnum:
        if s.nunique() > 50:
            continue  # high-cardinality identifier (e.g. Sport): skipped here
        s = pd.Series(pd.factorize(s)[0], index=df.index)
    feats[c] = s

y = df[TARGET]
rows = []
for c, s in feats.items():
    Xtr, Xte, ytr, yte = train_test_split(
        s.to_frame(), y, test_size=0.3, stratify=y, random_state=42)
    m = DecisionTreeClassifier(max_depth=3, random_state=42).fit(Xtr, ytr)
    p = m.predict_proba(Xte)[:, 1]
    rows.append((c, roc_auc_score(yte, p), f1_score(yte, m.predict(Xte))))
rows.sort(key=lambda r: -r[1])
out("\n--- Top single-feature models (depth-3 tree, 70/30 stratified split) ---")
out(f"{'feature':20}{'AUC':>8}{'F1':>8}")
for c, a, f in rows[:15]:
    out(f"{c:20}{a:8.3f}{f:8.3f}")

# 6. Ordering: are attacks contiguous blocks in file order? (matters for random splits)
runs = int((y != y.shift()).sum())
out(f"\nNumber of contiguous label runs in file order: {runs}")
out(f"Average run length: {len(y) / runs:.1f} rows")

pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path("results/ids_leakage.txt").write_text("\n".join(lines), encoding="utf-8")
print("\nSaved report to results/ids_leakage.txt")