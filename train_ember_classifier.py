"""
Train a real static-file malware classifier on the EMBER2018 dataset
(https://github.com/elastic/ember) -- real malicious/benign PE files scanned
by VirusTotal, not synthetic data. Unlike train_malware_classifier.py (which
trains on data/labeled/'s synthetic samples), this uses the full 2381-dim
EMBER feature vector (byte histogram, byte/entropy histogram, strings,
general file info, header, sections, imports, exports, data directories) via
security/ember_vendor/features.py -- a patched copy of EMBER's own feature
extractor, so the exact same code computes features here (from the dataset's
precomputed raw feature JSON) and at inference time (from a live file via
lief). See ember_vendor/features.py's module comment for the specific
lief/numpy compatibility patches applied, including one known imprecision
(dll_characteristics hashing) versus the original 2018 feature computation.

Usage:
    python train_ember_classifier.py --data-dir data/ember2018/ember2018

Expects the extracted EMBER2018 dataset directory to contain:
    train_features_0.jsonl .. train_features_5.jsonl
    test_features.jsonl
(this is the layout produced by extracting ember_dataset_2018_2.tar.bz2)
"""
import argparse
import json
import logging
import multiprocessing
import os
import time
from pathlib import Path

import numpy as np
import lightgbm as lgb
from sklearn.metrics import classification_report, roc_auc_score

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

MODEL_DIR = Path(__file__).resolve().parent / 'models'

# Module-level so worker processes (spawned by multiprocessing.Pool) can use it
# without re-pickling a PEFeatureExtractor instance per task.
_extractor = None


def _init_worker():
    global _extractor
    from security.ember_vendor import PEFeatureExtractor
    _extractor = PEFeatureExtractor(2, print_feature_warning=False)


def _vectorize_line(line):
    try:
        obj = json.loads(line)
        label = obj.get('label', -1)
        if label not in (0, 1):
            return None  # skip unlabeled samples
        vec = _extractor.process_raw_features(obj)
        return vec, label
    except Exception as e:
        logging.warning(f'Skipping unparseable row: {e}')
        return None


def load_split(jsonl_paths, n_workers):
    X, y = [], []
    t0 = time.time()
    total_lines = 0
    with multiprocessing.Pool(n_workers, initializer=_init_worker) as pool:
        for jsonl_path in jsonl_paths:
            logging.info(f'Vectorizing {jsonl_path} ...')
            with open(jsonl_path, 'r') as f:
                lines = f.readlines()
            total_lines += len(lines)
            for i, result in enumerate(pool.imap(_vectorize_line, lines, chunksize=256)):
                if result is not None:
                    vec, label = result
                    X.append(vec)
                    y.append(label)
                if (i + 1) % 50000 == 0:
                    logging.info(f'  {i + 1}/{len(lines)} rows processed in {jsonl_path.name} '
                                 f'({time.time() - t0:.0f}s elapsed)')
    logging.info(f'Vectorized {len(X)}/{total_lines} labeled rows in {time.time() - t0:.0f}s')
    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int32)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', required=True,
                         help='Directory containing train_features_*.jsonl and test_features.jsonl')
    parser.add_argument('--workers', type=int, default=max(1, multiprocessing.cpu_count() - 1))
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    train_paths = sorted(data_dir.glob('train_features_*.jsonl'))
    test_paths = sorted(data_dir.glob('test_features.jsonl'))
    if not train_paths or not test_paths:
        logging.error(f'Could not find train_features_*.jsonl / test_features.jsonl under {data_dir}')
        return

    logging.info(f'Found {len(train_paths)} train shard(s), {len(test_paths)} test shard(s)')

    X_train, y_train = load_split(train_paths, args.workers)
    X_test, y_test = load_split(test_paths, args.workers)
    logging.info(f'Train: {X_train.shape}, label distribution: {dict(zip(*np.unique(y_train, return_counts=True)))}')
    logging.info(f'Test: {X_test.shape}, label distribution: {dict(zip(*np.unique(y_test, return_counts=True)))}')

    train_data = lgb.Dataset(X_train, label=y_train)
    test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)

    # Parameters roughly matching EMBER's own published baseline (gradient
    # boosted decision trees over the same feature set).
    params = {
        'boosting_type': 'gbdt',
        'objective': 'binary',
        'metric': 'auc',
        'num_leaves': 2048,
        'learning_rate': 0.05,
        'feature_fraction': 0.5,
        'min_data_in_leaf': 50,
        'verbose': -1,
    }

    logging.info('Training LightGBM model...')
    model = lgb.train(
        params,
        train_data,
        num_boost_round=1000,
        valid_sets=[test_data],
        callbacks=[lgb.early_stopping(stopping_rounds=20), lgb.log_evaluation(period=50)],
    )

    y_pred_proba = model.predict(X_test, num_iteration=model.best_iteration)
    y_pred = (y_pred_proba > 0.5).astype(int)
    logging.info(f'Held-out test AUC: {roc_auc_score(y_test, y_pred_proba):.4f}')
    logging.info(f'Held-out test set performance:\n{classification_report(y_test, y_pred, zero_division=0)}')

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    model_path = MODEL_DIR / 'ember_malware_model.txt'
    model.save_model(str(model_path), num_iteration=model.best_iteration)
    logging.info(f'Saved trained model to {model_path}')


if __name__ == '__main__':
    main()
