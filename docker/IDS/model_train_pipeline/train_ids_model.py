#!/usr/bin/env python3
"""
train_ids_model.py

Train a LIGHTWEIGHT classifier on features exported by ids-online-save-csv.py.
Selects the best of a few small models via cross-validation and saves a
version-friendly *bundle* that includes:

  bundle/
    model.joblib            # sklearn Pipeline (preproc + estimator)
    metadata.json           # feature_names, target, metrics, versions, etc.
    requirements.txt        # pinned versions for reproducibility
    README.txt              # how to use
    (optional) model.onnx   # if --export-onnx and supported

The bundle is designed so your online code can enforce feature order:
    feature_names = model_dict["feature_names"]
    X = X.reindex(columns=feature_names, fill_value=0)
    yhat = model_dict["pipeline"].predict(X)

Usage:
  python3 train_ids_model.py --data ./features-*.csv --out ./ids_bundle --export-onnx
"""
import argparse
import json
import os
import sys
import glob
from datetime import datetime
from pathlib import Path
import warnings

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split, StratifiedKFold, GridSearchCV
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, roc_auc_score,
                             precision_score, recall_score, f1_score, classification_report,
                             confusion_matrix)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.utils import check_random_state
import joblib

def _collect_paths(patterns):
    files = []
    for p in patterns:
        p = os.path.expanduser(p)
        if os.path.isdir(p):
            files.extend(glob.glob(os.path.join(p, "*.csv")))
        else:
            files.extend(glob.glob(p))
    return sorted(set(files))

def _load_data(csv_paths, target):
    dfs = []
    for p in csv_paths:
        try:
            df = pd.read_csv(p)
            if target not in df.columns:
                raise ValueError(f"Target '{target}' not in columns of {p}")
            dfs.append(df)
        except Exception as e:
            print(f"[WARN] failed to read {p}: {e}", file=sys.stderr)
    if not dfs:
        raise SystemExit("No valid CSVs found to train on.")
    data = pd.concat(dfs, ignore_index=True)
    # Ensure numeric features only; convert bools to ints
    for col in data.columns:
        if data[col].dtype == bool:
            data[col] = data[col].astype(np.int32)
    # Drop obvious timestamp-ish columns if present
    drop_like = [c for c in data.columns if c.lower() in {"timestamp", "time", "datetime"}]
    data = data.drop(columns=drop_like, errors="ignore")
    # Shuffle
    data = data.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return data

def _split_xy(df, target):
    y = df[target].astype(int).values
    X = df.drop(columns=[target])
    # Only keep numeric columns; everything else is dropped
    num_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    X = X[num_cols].copy()
    return X, y, num_cols

def _build_candidates(random_state):
    """
    Assemble a few lightweight candidate models:
      - LogisticRegression (strong baseline, scaled)
      - RandomForestClassifier (robust, small depth)
      - HistGradientBoostingClassifier (fast, accurate, lightweight)
    """
    # Pipelines so we can keep preprocessing with the estimator
    lr_pipe = Pipeline(steps=[
        ("scaler", StandardScaler(with_mean=True, with_std=True)),
        ("clf", LogisticRegression(max_iter=200, n_jobs=None, class_weight="balanced", solver="lbfgs"))
    ])
    lr_grid = {
        "clf__C": [0.1, 1.0, 3.0],
        "clf__penalty": ["l2"]
    }

    rf_pipe = Pipeline(steps=[
        ("identity", "passthrough"),
        ("clf", RandomForestClassifier(
            n_estimators=200, max_depth=None, min_samples_leaf=2,
            n_jobs=-1, class_weight="balanced_subsample", random_state=random_state))
    ])
    rf_grid = {
        "clf__n_estimators": [150, 250],
        "clf__max_depth": [None, 10, 20],
        "clf__min_samples_leaf": [1, 2, 4]
    }

    hgb_pipe = Pipeline(steps=[
        ("identity", "passthrough"),
        ("clf", HistGradientBoostingClassifier(
            learning_rate=0.1, max_depth=None, l2_regularization=0.0,
            early_stopping=True, random_state=random_state))
    ])
    hgb_grid = {
        "clf__learning_rate": [0.05, 0.1],
        "clf__max_depth": [None, 6, 12],
        "clf__l2_regularization": [0.0, 0.1]
    }

    return [
        ("logreg", lr_pipe, lr_grid),
        ("rf", rf_pipe, rf_grid),
        ("hgb", hgb_pipe, hgb_grid),
    ]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", nargs="+", required=True,
                    help="CSV path(s), globs, or directories (e.g., ./captures/*.csv ./more/)")
    ap.add_argument("--target", default="Label", help="Target column name (default: Label)")
    ap.add_argument("--test-size", type=float, default=0.2, help="Holdout test size fraction")
    ap.add_argument("--cv", type=int, default=5, help="CV folds")
    ap.add_argument("--random-state", type=int, default=42)
    ap.add_argument("--out", default=None, help="Output bundle directory (created). Default: ids-model-bundle-<timestamp>")
    ap.add_argument("--scoring", default="roc_auc", choices=["roc_auc", "balanced_accuracy", "accuracy", "f1"],
                    help="Primary CV scoring metric")
    ap.add_argument("--export-onnx", action="store_true", help="Try to export ONNX (if supported)")
    args = ap.parse_args()

    rng = check_random_state(args.random_state)

    csv_paths = _collect_paths(args.data)
    if not csv_paths:
        raise SystemExit("No CSV files matched the provided --data paths.")
    print(f"Found {len(csv_paths)} CSV file(s).")

    df = _load_data(csv_paths, args.target)
    X, y, feature_names = _split_xy(df, args.target)

    # Split train/holdout
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, stratify=y, random_state=args.random_state
    )

    # Build candidates and search
    cv = StratifiedKFold(n_splits=args.cv, shuffle=True, random_state=args.random_state)
    best = None
    best_name = None
    best_score = -np.inf
    best_search = None

    for name, pipe, grid in _build_candidates(args.random_state):
        print(f"\n=== Tuning {name} ===")
        search = GridSearchCV(
            pipe, param_grid=grid, scoring=args.scoring,
            cv=cv, n_jobs=-1, verbose=1
        )
        search.fit(X_train, y_train)
        print(f"{name} best {args.scoring}: {search.best_score_:.4f} | params: {search.best_params_}")

        if search.best_score_ > best_score:
            best_score = search.best_score_
            best = search.best_estimator_
            best_name = name
            best_search = search

    # Evaluate on holdout
    def _prob_safe(clf, Xt):
        if hasattr(clf, "predict_proba"):
            return clf.predict_proba(Xt)[:, 1]
        elif hasattr(clf, "decision_function"):
            # scale to [0,1] via logistic-ish transform
            z = clf.decision_function(Xt)
            return 1.0 / (1.0 + np.exp(-z))
        else:
            # fallback
            return clf.predict(Xt)

    y_proba = _prob_safe(best, X_test)
    y_pred = (y_proba >= 0.5).astype(int)

    metrics = {
        "cv_best_model": best_name,
        "cv_best_score": float(best_score),
        "holdout_accuracy": float(accuracy_score(y_test, y_pred)),
        "holdout_balanced_accuracy": float(balanced_accuracy_score(y_test, y_pred)),
        "holdout_roc_auc": float(roc_auc_score(y_test, y_proba)),
        "holdout_precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "holdout_recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "holdout_f1": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "classification_report": classification_report(y_test, y_pred, zero_division=0)
    }
    print("\n=== Holdout Metrics ===")
    for k in ["holdout_accuracy","holdout_balanced_accuracy","holdout_roc_auc","holdout_precision","holdout_recall","holdout_f1"]:
        print(f"{k}: {metrics[k]:.4f}")
    print("\nConfusion Matrix:\n", np.array(metrics["confusion_matrix"]))
    print("\nClassification Report:\n", metrics["classification_report"])

    # Build bundle dir
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    bundle_dir = Path(args.out) if args.out else Path(f"ids-model-bundle-{ts}")
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # Persist pipeline + metadata in a dict for compatibility
    model_dict = {
        "pipeline": best,
        "feature_names": feature_names,
        "target_name": args.target,
        "created_at": ts,
        "sklearn_version": __import__("sklearn").__version__,
        "numpy_version": np.__version__,
        "pandas_version": pd.__version__,
        "cv_scoring": args.scoring,
        "cv_params": best_search.best_params_ if best_search else {},
        "metrics": metrics,
    }
    joblib.dump(model_dict, bundle_dir / "model.joblib", compress=3)

    # Write metadata.json (human-readable, no pickles)
    meta = dict(model_dict)
    meta.pop("pipeline")  # not JSON-serializable
    (bundle_dir / "metadata.json").write_text(json.dumps(meta, indent=2))

    # requirements.txt for environment recreation
    req_txt = f"""python=={sys.version.split()[0]}
numpy=={np.__version__}
pandas=={pd.__version__}
scikit-learn=={__import__("sklearn").__version__}
joblib=={joblib.__version__}
"""
    (bundle_dir / "requirements.txt").write_text(req_txt)

    # README
    readme = f"""IDS Model Bundle
=================

Created: {ts}
Best CV model: {best_name} ({args.scoring}={best_score:.4f})

Files:
- model.joblib       : sklearn Pipeline + metadata dict
- metadata.json      : feature names, versions, metrics (no code)
- requirements.txt   : helpful for exact-env recreation
- (optional) model.onnx : if exported with --export-onnx

Quickstart (Python):
--------------------
import pandas as pd, joblib
bundle = joblib.load("{(bundle_dir / 'model.joblib').as_posix()}")
feature_names = bundle["feature_names"]
pipe = bundle["pipeline"]
X = pd.read_csv("new.csv").reindex(columns=feature_names, fill_value=0)
proba = pipe.predict_proba(X)[:,1]
pred = (proba >= 0.5).astype(int)

"""
    (bundle_dir / "README.txt").write_text(readme)

    # Optional ONNX export
    if args.export_onnx:
        onnx_path = bundle_dir / "model.onnx"
        try:
            from skl2onnx import convert_sklearn
            from skl2onnx.common.data_types import FloatTensorType
            # Build a dummy input of correct shape
            initial_type = [("float_input", FloatTensorType([None, len(feature_names)]))]
            onx = convert_sklearn(best, initial_types=initial_type)
            with open(onnx_path, "wb") as f:
                f.write(onx.SerializeToString())
            print(f"Exported ONNX to {onnx_path}")
        except Exception as e:
            print(f"[WARN] ONNX export failed or unsupported: {e}", file=sys.stderr)

    print(f"\nSaved bundle to: {bundle_dir.resolve()}")

if __name__ == "__main__":
    main()
