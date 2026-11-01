"""Scores telemetry rows with the saved IDS model and applies the two-threshold decision rule."""
import joblib
import numpy as np
import pandas as pd


class IdsService:
    def __init__(self, model_path, csv_path, high=0.95, low=0.50, min_hits=3):
        bundle = joblib.load(model_path)
        self.model, self.features = bundle["model"], bundle["features"]
        self.high, self.low, self.min_hits = high, low, min_hits
        # Rebuild the text encodings exactly as 03_train_ids.py did (same CSV, same factorize order)
        df = pd.read_csv(csv_path)
        self.encoders = {}
        for f in self.features:
            col = df[f]
            if pd.api.types.is_numeric_dtype(col):
                continue
            num = pd.to_numeric(col, errors="coerce")
            if num.notna().mean() > 0.95:
                continue
            codes, uniques = pd.factorize(col)
            self.encoders[f] = {str(u).strip(): i for i, u in enumerate(uniques)}

    def _vector(self, row: dict):
        v = []
        for f in self.features:
            if f not in row:
                raise ValueError(f"missing feature '{f}'")
            if f in self.encoders:
                v.append(self.encoders[f].get(str(row[f]).strip(), -1))
            else:
                v.append(float(row[f]))
        return v

    def score(self, rows):
        X = np.array([self._vector(r) for r in rows], dtype=float)
        return self.model.predict_proba(pd.DataFrame(X, columns=self.features))[:, 1]

    def decide(self, rows):
        s = self.score(rows)
        n_high = int((s >= self.high).sum())
        n_alert = int((s >= self.low).sum())
        decision = ("suspend" if n_high >= self.min_hits
                    else "alert" if n_alert >= self.min_hits else "ok")
        return {"decision": decision, "rows": len(rows), "max_score": round(float(s.max()), 4),
                "rows_high": n_high, "rows_alert": n_alert}