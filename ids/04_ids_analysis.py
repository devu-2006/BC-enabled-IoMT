"""Per-attack-category recall and alert-threshold operating points (block-wise out-of-fold scores).

Usage: python ids/04_ids_analysis.py ids/data/<file>.csv [--folds 5]
Writes results/ids_analysis.md and results/ids_pr_curve.png
"""
import argparse
import pathlib
import warnings

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, precision_recall_curve
from sklearn.model_selection import GroupKFold
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
TARGET, CAT = "Label", "Attack Category"
IDENT = ["SrcMac", "Sport", "Packet_num"]
BLOCK, SEED = 500, 42

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--folds", type=int, default=5)
args = ap.parse_args()

# ----------------------------------------------------------------------------- data (same preparation as 03_train_ids.py)
df = pd.read_csv(args.csv)
y = df[TARGET].astype(int).to_numpy()
cat = df[CAT].astype(str).to_numpy() if CAT in df.columns else None
X = df.drop(columns=[TARGET] + ([CAT] if CAT in df.columns else []))
for c in list(X.columns):
    if pd.api.types.is_numeric_dtype(X[c]):
        continue
    num = pd.to_numeric(X[c], errors="coerce")
    if num.notna().mean() > 0.95:
        X[c] = num.fillna(-1)
    elif X[c].nunique() <= 50:
        X[c] = pd.factorize(X[c])[0]
    else:
        X = X.drop(columns=c)
X = X.drop(columns=[c for c in X.columns if X[c].nunique() <= 1])
FS_B = [c for c in X.columns if c not in IDENT]
FS_B2 = [c for c in FS_B if c != "Flgs"]
groups = np.arange(len(X)) // BLOCK


def oof_scores(cols):
    """Each row is scored by a model that never saw its block."""
    s = np.zeros(len(X))
    for tr, te in GroupKFold(args.folds).split(X, y, groups):
        pos = max(int(y[tr].sum()), 1)
        m = XGBClassifier(learning_rate=0.1, max_depth=15, n_estimators=150, subsample=0.8,
                          colsample_bytree=0.8, scale_pos_weight=(len(tr) - pos) / pos,
                          eval_metric="logloss", n_jobs=-1, random_state=SEED)
        m.fit(X.iloc[tr][cols], y[tr])
        s[te] = m.predict_proba(X.iloc[te][cols])[:, 1]
    return s


md = ["# IDS analysis (XGBoost, block-wise out-of-fold scores)\n"]

# ----------------------------------------------------------------------------- per-category recall
scores = {}
if cat is not None:
    md += ["## Detection rate per traffic category (threshold 0.5)\n",
           "| Feature set | Category | Rows | Detected (flagged as attack) |", "|---|---|---:|---:|"]
for name, cols in (("FS-B", FS_B), ("FS-B2", FS_B2)):
    s = oof_scores(cols)
    scores[name] = s
    if cat is not None:
        for c in sorted(set(cat)):
            mask = cat == c
            label = f"{c} (false-alarm rate)" if c.lower() == "normal" else f"{c} (recall)"
            md.append(f"| {name} | {label} | {int(mask.sum())} | {(s[mask] >= 0.5).mean():.3f} |")

# ----------------------------------------------------------------------------- operating points
s = scores["FS-B"]
prec, rec, thr = precision_recall_curve(y, s)
prec, rec = prec[:-1], rec[:-1]
f1 = 2 * prec * rec / np.maximum(prec + rec, 1e-12)
n_normal = int((y == 0).sum())


def point(idx):
    pred = s >= thr[idx]
    fp = int(((pred == 1) & (y == 0)).sum())
    return thr[idx], prec[idx], rec[idx], f1[idx], fp / n_normal


points = {"default (0.5)": int(np.argmin(np.abs(thr - 0.5))), "best F1": int(np.argmax(f1))}
for target in (0.8, 0.9):
    ok = np.where(rec >= target)[0]
    if len(ok):
        points[f"recall >= {target:.1f}"] = int(ok[np.argmax(prec[ok])])

md += ["\n## Alert-threshold operating points (FS-B)\n",
       f"PR-AUC = {average_precision_score(y, s):.3f}; random baseline = {y.mean():.3f}. "
       "Thresholds are read from the same out-of-fold scores, so treat them as indicative.\n",
       "| Operating point | Threshold | Precision | Recall | F1 | False-alarm rate |", "|---|---:|---:|---:|---:|---:|"]
for name, i in points.items():
    t, p, r, f, far = point(i)
    md.append(f"| {name} | {t:.3f} | {p:.3f} | {r:.3f} | {f:.3f} | {far:.3f} |")

out = pathlib.Path("results")
out.mkdir(exist_ok=True)
(out / "ids_analysis.md").write_text("\n".join(md), encoding="utf-8")
print("\n".join(md))

fig, ax = plt.subplots(figsize=(4.6, 3.8))
ax.plot(rec, prec, label="XGBoost (FS-B, block CV)")
ax.axhline(y.mean(), ls="--", c="grey", label="random baseline")
for name, i in points.items():
    ax.scatter(rec[i], prec[i], s=22, zorder=3)
    ax.annotate(name, (rec[i], prec[i]), fontsize=7, xytext=(4, 4), textcoords="offset points")
ax.set_xlabel("Recall")
ax.set_ylabel("Precision")
ax.set_xlim(0, 1.02)
ax.set_ylim(0, 1.02)
ax.legend(fontsize=8)
fig.tight_layout()
fig.savefig(out / "ids_pr_curve.png", dpi=200)
print("saved results/ids_analysis.md and results/ids_pr_curve.png")