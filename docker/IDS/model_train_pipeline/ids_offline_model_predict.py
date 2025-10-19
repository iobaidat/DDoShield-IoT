#!/usr/bin/env python3
"""
ids_offline_model_predict.py

Simple helper to run predictions from a saved bundle created by train_ids_model.py.
Enforces feature order exactly as saved in the bundle metadata.

Usage:
  python3 ids_offline_model_predict.py --bundle ./ids-model-bundle-2025... --csv ./new.csv --out preds.csv
"""
import argparse
import joblib
import pandas as pd
from pathlib import Path

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bundle", required=True, help="Path to bundle directory containing model.joblib")
    ap.add_argument("--csv", required=True, help="CSV file with feature columns")
    ap.add_argument("--out", default=None, help="Optional output CSV for predictions (pred, proba)")
    args = ap.parse_args()

    bundle_path = Path(args.bundle).expanduser().resolve()
    model_obj = joblib.load(bundle_path / "model.joblib")
    feature_names = model_obj["feature_names"]
    pipe = model_obj["pipeline"]

    df = pd.read_csv(args.csv)
    X = df.reindex(columns=feature_names, fill_value=0)
    if hasattr(pipe, "predict_proba"):
        proba = pipe.predict_proba(X)[:,1]
    elif hasattr(pipe, "decision_function"):
        import numpy as np
        z = pipe.decision_function(X)
        proba = 1.0/(1.0+np.exp(-z))
    else:
        proba = pipe.predict(X)

    pred = (proba >= 0.5).astype(int)

    out_df = df.copy()
    out_df["pred_proba"] = proba
    out_df["pred"] = pred

    if args.out:
        out_df.to_csv(args.out, index=False)
        print(f"Wrote predictions: {Path(args.out).resolve()}")
    else:
        print(out_df.head(10).to_string(index=False))

if __name__ == "__main__":
    main()
