"""Scores telemetry windows with the saved IDS model and decides ok / alert / suspend per device.

Usage:  python ids/05_score_telemetry.py ids/data/<file>.csv
Needs:  ids/models/ids_xgb_fsC.joblib  (created by 03_train_ids.py)
Writes: results/ids_decisions.json

Decision rule (per device window of WINDOW rows), thresholds are design parameters:
  suspend : at least MIN_HITS rows scored >= HIGH   (strict threshold, very few false alarms)
  alert   : at least MIN_HITS rows scored >= LOW    (needs human review, no automatic action)
  ok      : otherwise
NOTE: the demo rows come from the training dataset, so this demonstrates the pipeline, not detection
accuracy. Accuracy is reported by 03_train_ids.py / 04_ids_analysis.py (block-wise cross-validation).
"""
import json
import pathlib
import sys
import warnings

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
HIGH, LOW, MIN_HITS, WINDOW = 0.95, 0.50, 3, 100
TARGET, CAT = "Label", "Attack Category"

if len(sys.argv) < 2:
    sys.exit("Usage: python ids/05_score_telemetry.py <path-to-csv>")

# ----------------------------------------------------------------------------- same preparation as 03_train_ids.py
df = pd.read_csv(sys.argv[1])
cat = df[CAT].astype(str).to_numpy()
X = df.drop(columns=[TARGET, CAT])
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

bundle = joblib.load("ids/models/ids_xgb_fsC.joblib")
model, feats = bundle["model"], bundle["features"]
scores_all = model.predict_proba(X[feats])[:, 1]


def window(category, start_after=-1):
    """First run of WINDOW consecutive rows of `category` that starts after `start_after`."""
    idx = np.flatnonzero(cat == category)
    for i in range(len(idx) - WINDOW + 1):
        if idx[i] > start_after and idx[i + WINDOW - 1] - idx[i] == WINDOW - 1:
            return idx[i:i + WINDOW]
    return idx[:WINDOW]


def decide(scores):
    n_high = int((scores >= HIGH).sum())
    n_alert = int((scores >= LOW).sum())
    if n_high >= MIN_HITS:
        return "suspend", n_high, n_alert
    if n_alert >= MIN_HITS:
        return "alert", n_high, n_alert
    return "ok", n_high, n_alert


plan = [("device-A", "normal", -1), ("device-B", "Data Alteration", -1),
        ("device-C", "Spoofing", -1), ("device-D", "normal", len(df) // 2)]
out = []
for device, category, after in plan:
    rows = window(category, after)
    s = scores_all[rows]
    decision, n_high, n_alert = decide(s)
    out.append(dict(device=device, true_category=category, rows=len(rows),
                    max_score=round(float(s.max()), 4), rows_high=n_high, rows_alert=n_alert,
                    decision=decision))
    print(f"{device}  true={category:16}  max={s.max():.3f}  high={n_high:3d}  >=0.5:{n_alert:3d}  -> {decision}")

pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path("results/ids_decisions.json").write_text(json.dumps(
    {"thresholds": {"high": HIGH, "low": LOW, "min_hits": MIN_HITS, "window": WINDOW}, "decisions": out}, indent=2))
print("saved results/ids_decisions.json")