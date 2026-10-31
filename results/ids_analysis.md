# IDS analysis (XGBoost, block-wise out-of-fold scores)

## Detection rate per traffic category (threshold 0.5)

| Feature set | Category | Rows | Detected (flagged as attack) |
|---|---|---:|---:|
| FS-B | Data Alteration (recall) | 922 | 1.000 |
| FS-B | Spoofing (recall) | 1124 | 0.170 |
| FS-B | normal (false-alarm rate) | 14272 | 0.019 |
| FS-B2 | Data Alteration (recall) | 922 | 0.995 |
| FS-B2 | Spoofing (recall) | 1124 | 0.069 |
| FS-B2 | normal (false-alarm rate) | 14272 | 0.023 |

## Alert-threshold operating points (FS-B)

PR-AUC = 0.699; random baseline = 0.125. Thresholds are read from the same out-of-fold scores, so treat them as indicative.

| Operating point | Threshold | Precision | Recall | F1 | False-alarm rate |
|---|---:|---:|---:|---:|---:|
| default (0.5) | 0.500 | 0.802 | 0.544 | 0.648 | 0.019 |
| best F1 | 0.950 | 0.994 | 0.522 | 0.684 | 0.000 |
| recall >= 0.8 | 0.014 | 0.278 | 0.801 | 0.413 | 0.298 |
| recall >= 0.9 | 0.004 | 0.212 | 0.901 | 0.343 | 0.481 |