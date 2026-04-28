"""
Run this ONCE locally before pushing to GitHub / deploying to Render.

What it does:
  1. Loads the full CICIoMT2024 parquet (119 MB)
  2. Samples 5 000 rows per attack category  →  backend/data/replay_pool.parquet (~6 MB)
  3. Copies the trained model               →  backend/models/best_model_lightgbm.joblib

Usage:
  cd iomt-react/backend
  python create_sample.py
"""

import sys
import shutil
from pathlib import Path

import pandas as pd
import numpy as np

# ── Paths ─────────────────────────────────────────────────────────────────────
HERE      = Path(__file__).parent
REPO_ROOT = HERE.parent
PROJECT   = REPO_ROOT.parent / "IoMT_Anomaly_Detection_Project"

SRC_DATA  = PROJECT / "data" / "raw" / "CIC_IoMT_2024_WiFi_MQTT_train.parquet"
SRC_MODEL = PROJECT / "models" / "best_model_lightgbm.joblib"
DST_DATA  = HERE / "data" / "replay_pool.parquet"
DST_MODEL = HERE / "models" / "best_model_lightgbm.joblib"

# ── Validation ────────────────────────────────────────────────────────────────
for p in [SRC_DATA, SRC_MODEL]:
    if not p.exists():
        print(f"[ERROR] Not found: {p}")
        sys.exit(1)

# ── Create output dirs ────────────────────────────────────────────────────────
DST_DATA.parent.mkdir(parents=True, exist_ok=True)
DST_MODEL.parent.mkdir(parents=True, exist_ok=True)

# ── Load + label ──────────────────────────────────────────────────────────────
print("Loading parquet (this may take a moment)...")
df = pd.read_parquet(SRC_DATA)

label_col = next((c for c in df.columns if c.lower() == "label"), None)
if not label_col:
    print("[ERROR] No 'label' column found.")
    sys.exit(1)

LABEL_MAP = {
    "ddos": "DDoS", "dos": "DoS", "spoofing": "Spoofing",
    "recon": "Recon", "mqtt": "MQTT", "benign": "Benign",
}

def strip_suffix(s):
    return s.split("-")[0].split("_")[0].strip() if isinstance(s, str) else s

def map_label(s):
    key = strip_suffix(str(s)).lower()
    for k, v in LABEL_MAP.items():
        if k in key:
            return v
    return "Unknown"

df["category"] = df[label_col].apply(map_label)
df = df[df["category"] != "Unknown"]

# ── Sample ────────────────────────────────────────────────────────────────────
ROWS_PER_CLASS = 5_000
samples = [
    grp.sample(min(len(grp), ROWS_PER_CLASS), random_state=42)
    for _, grp in df.groupby("category")
]
pool = pd.concat(samples).reset_index(drop=True)

print(f"Class breakdown in sample:")
for cat, cnt in pool["category"].value_counts().items():
    print(f"  {cat}: {cnt}")

# Clean features
NON_FEAT = {"label", "category", "is_attack", label_col.lower()}
feat_cols = [c for c in pool.columns if c.lower() not in NON_FEAT]
pool[feat_cols] = pool[feat_cols].replace([np.inf, -np.inf], np.nan)
pool[feat_cols] = pool[feat_cols].fillna(pool[feat_cols].median(numeric_only=True))

# ── Save ──────────────────────────────────────────────────────────────────────
pool.to_parquet(DST_DATA, index=False)
size_mb = DST_DATA.stat().st_size / 1_048_576
print(f"\nSaved replay pool -> {DST_DATA}  ({size_mb:.1f} MB)")

print(f"Copying model -> {DST_MODEL} ...")
shutil.copy2(SRC_MODEL, DST_MODEL)
model_mb = DST_MODEL.stat().st_size / 1_048_576
print(f"Model copied  ({model_mb:.1f} MB)")

print("\nDone. You can now commit and push to GitHub, then deploy on Render.")
