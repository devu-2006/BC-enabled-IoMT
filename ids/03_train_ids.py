"""IDS training and leakage-safe evaluation (Contribution C4).

Usage:
  python ids/03_train_ids.py ids/data/<file>.csv [--models rf,xgb,svm] [--k 10] [--folds 5]

Feature sets
  FS-A   all usable features (paper-style, includes identity/ordering shortcuts)
  FS-B   FS-A minus SrcMac, Sport, Packet_num (identity / ordering columns)
  FS-B2  FS-B minus Flgs (protocol flag that nearly identifies one attack type)
  FS-C   top-k features of FS-B, chosen INSIDE each training fold (no test-label leakage)
Protocols
  random  stratified k-fold (what a naive evaluation does)
  block   contiguous blocks of 500 rows kept together (attacks come in blocks, so neighbours
          must not be split between train and test)
Hyper-parameters follow Table 1 of the base paper; class imbalance is handled with class weights.
"""
import argparse
import json
import pathlib
import time
import warnings
from collections import Counter

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import GroupKFold, StratifiedKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from xgboost import XGBClassifier

warnings.filterwarnings("ignore")
TARGET, LEAK = "Label", ["Attack Category"]
IDENT = ["SrcMac", "Sport", "Packet_num"]
BLOCK = 500
SEED = 42

ap = argparse.ArgumentParser()
ap.add_argument("csv")
ap.add_argument("--models", default="rf,xgb,svm")
ap.add_argument("--k", type=int, default=10)
ap.add_argument("--folds", type=int, default=5)
args = ap.parse_args()
MODELS = [m.strip() for m in args.models.split(",")]

# ----------------------------------------------------------------------------- data
df = pd.read_csv(args.csv)
y = df[TARGET].astype(int).to_numpy()
X = df.drop(columns=[TARGET] + [c for c in LEAK if c in df.columns])
dropped = []
for c in list(X.columns):
    if pd.api.types.is_numeric_dtype(X[c]):
        continue
    num = pd.to_numeric(X[c], errors="coerce")
    if num.notna().mean() > 0.95:
        X[c] = num.fillna(-1)
    elif X[c].nunique() <= 50:
        X[c] = pd.factorize(X[c])[0]
    else:
        dropped.append(c)
        X = X.drop(columns=c)
constant = [c for c in X.columns if X[c].nunique() <= 1]
X = X.drop(columns=constant)
FS_A = list(X.columns)
FS_B = [c for c in FS_A if c not in IDENT]
FS_B2 = [c for c in FS_B if c != "Flgs"]
print(f"rows={len(X)}  attack share={y.mean():.4f}  majority accuracy={1 - y.mean():.4f}")
print(f"dropped constant={constant}  dropped high-cardinality text={dropped}")
print(f"features: A={len(FS_A)}  B={len(FS_B)}  B2={len(FS_B2)}  C=top-{args.k} of B")


# ----------------------------------------------------------------------------- models
def make_model(name, ytr):
    pos = max(int(ytr.sum()), 1)
    neg = len(ytr) - pos
    if name == "rf":
        return RandomForestClassifier(n_estimators=100, max_depth=20, min_samples_split=2,
                                      class_weight="balanced_subsample", n_jobs=-1, random_state=SEED)
    if name == "xgb":
        return XGBClassifier(learning_rate=0.1, max_depth=15, n_estimators=150, subsample=0.8,
                             colsample_bytree=0.8, scale_pos_weight=neg / pos,
                             eval_metric="logloss", n_jobs=-1, random_state=SEED)
    if name == "svm":
        return make_pipeline(StandardScaler(), SVC(C=1, gamma=0.1, kernel="rbf", class_weight="balanced"))
    raise SystemExit(f"unknown model {name}")


def score(model, Xte):
    return model.predict_proba(Xte)[:, 1] if hasattr(model, "predict_proba") else model.decision_function(Xte)


def top_k_features(Xtr, ytr, k):
    m = make_model("xgb", ytr).fit(Xtr[FS_B], ytr)
    order = np.argsort(m.feature_importances_)[::-1][:k]
    return [FS_B[i] for i in order]


def columns_for(fs, Xtr, ytr):
    return {"FS-A": FS_A, "FS-B": FS_B, "FS-B2": FS_B2}.get(fs) or top_k_features(Xtr, ytr, args.k)


def splits(protocol):
    if protocol == "random":
        return StratifiedKFold(args.folds, shuffle=True, random_state=SEED).split(X, y)
    groups = np.arange(len(X)) // BLOCK
    return GroupKFold(args.folds).split(X, y, groups)


# ----------------------------------------------------------------------------- evaluation
rows, selected = [], Counter()
for protocol in ("random", "block"):
    for fold, (tr, te) in enumerate(splits(protocol)):
        Xtr, Xte, ytr, yte = X.iloc[tr], X.iloc[te], y[tr], y[te]
        for fs in ("FS-A", "FS-B", "FS-B2", "FS-C"):
            cols = columns_for(fs, Xtr, ytr)
            if fs == "FS-C" and protocol == "block":
                selected.update(cols)
            for name in MODELS:
                m = make_model(name, ytr).fit(Xtr[cols], ytr)
                t0 = time.perf_counter()
                pred = m.predict(Xte[cols])
                latency_ms = (time.perf_counter() - t0) / len(Xte) * 1000
                sc = score(m, Xte[cols])
                tn, fp, fn, tp = confusion_matrix(yte, pred, labels=[0, 1]).ravel()
                both = len(set(yte)) == 2
                rows.append(dict(
                    protocol=protocol, feature_set=fs, model=name, fold=fold,
                    accuracy=accuracy_score(yte, pred),
                    precision=precision_score(yte, pred, zero_division=0),
                    recall=recall_score(yte, pred, zero_division=0),
                    f1=f1_score(yte, pred, zero_division=0),
                    pr_auc=average_precision_score(yte, sc) if both else np.nan,
                    roc_auc=roc_auc_score(yte, sc) if both else np.nan,
                    fnr=fn / (fn + tp) if (fn + tp) else np.nan,
                    latency_ms=latency_ms))
        print(f"done {protocol} fold {fold + 1}/{args.folds}", flush=True)

res = pd.DataFrame(rows)
out = pathlib.Path("results")
out.mkdir(exist_ok=True)
res.to_csv(out / "ids_results_per_fold.csv", index=False)
metrics = ["accuracy", "precision", "recall", "f1", "pr_auc", "roc_auc", "fnr", "latency_ms"]
g = res.groupby(["protocol", "feature_set", "model"])[metrics]
summary = g.mean().round(4).join(g.std().round(4), rsuffix="_std").reset_index()
summary.to_csv(out / "ids_results_summary.csv", index=False)

lines = ["| Protocol | Feature set | Model | Accuracy | Precision | Recall | F1 | PR-AUC | FNR | Latency (ms/sample) |",
         "|---|---|---|---:|---:|---:|---:|---:|---:|---:|"]
for _, r in summary.iterrows():
    lines.append(f"| {r.protocol} | {r.feature_set} | {r.model} | {r.accuracy:.3f} | {r.precision:.3f} | "
                 f"{r.recall:.3f} | {r.f1:.3f}±{r.f1_std:.3f} | {r.pr_auc:.3f} | {r.fnr:.3f} | {r.latency_ms:.4f} |")
(out / "ids_results_summary.md").write_text("\n".join(lines), encoding="utf-8")
print("\n".join(lines))
print(f"\nMajority-class accuracy for reference: {1 - y.mean():.4f}")

# ----------------------------------------------------------------------------- figure
fig, axes = plt.subplots(1, len(MODELS), figsize=(4.2 * len(MODELS), 3.6), sharey=True)
axes = np.atleast_1d(axes)
fsets = ["FS-A", "FS-B", "FS-B2", "FS-C"]
for ax, name in zip(axes, MODELS):
    for i, protocol in enumerate(("random", "block")):
        vals = [summary[(summary.protocol == protocol) & (summary.feature_set == f) & (summary.model == name)].f1.iloc[0]
                for f in fsets]
        ax.bar(np.arange(len(fsets)) + (i - 0.5) * 0.38, vals, 0.38, label=protocol)
    ax.set_xticks(range(len(fsets)))
    ax.set_xticklabels(fsets, fontsize=8)
    ax.set_title(name.upper())
    ax.set_ylim(0, 1.05)
axes[0].set_ylabel("F1-score")
axes[0].legend(title="split", fontsize=8)
fig.tight_layout()
fig.savefig(out / "ids_f1_comparison.png", dpi=200)

# ----------------------------------------------------------------------------- final model for the oracle
final_cols = top_k_features(X, y, args.k)
final = make_model("xgb", y).fit(X[final_cols], y)
pathlib.Path("ids/models").mkdir(parents=True, exist_ok=True)
joblib.dump({"model": final, "features": final_cols}, "ids/models/ids_xgb_fsC.joblib")
(out / "ids_fsC_features.json").write_text(json.dumps(
    {"final_features": final_cols, "selection_frequency_across_block_folds": selected.most_common()}, indent=2))
print("final FS-C features:", final_cols)
print("saved: results/ids_results_summary.md/.csv, ids_f1_comparison.png, ids/models/ids_xgb_fsC.joblib")