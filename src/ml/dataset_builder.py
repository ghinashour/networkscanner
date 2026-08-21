"""src.ml.dataset_builder

Utility for producing ML-ready feature rows from database entities.

This project has two different feature pipelines:
- Training: `scripts/train_with_features.py` uses `src/ml/feature_extractor.DeviceFeatureExtractor`
- Prediction: `scripts/predict_device.py` uses `src/ml/dataset_builder.MLDatasetBuilder`

To avoid feature-dimension mismatches (e.g., scaler expecting 10 features but
prediction providing 14), this builder delegates to the same extractor class
used during training.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import pandas as pd

from src.ml.feature_extractor import DeviceFeatureExtractor


@dataclass
class MLDatasetBuilder:
    """Build numeric feature vectors for device prediction."""

    extractor: DeviceFeatureExtractor = DeviceFeatureExtractor()

    def _extract_features(
        self,
        host: Any,
        services: List[Any],
    ) -> Dict[str, float]:
        """Extract numeric features for a single host.

        Returns a dict of numeric feature_name -> value, matching the columns
        produced by `DeviceFeatureExtractor.extract_features`.
        """

        # Convert DB entities into a 1-row DataFrame matching the expected input
        # schema of DeviceFeatureExtractor.
        open_ports: List[str] = []
        service_names: List[str] = []

        for svc in services or []:
            port = getattr(svc, "port", None)
            if port is not None:
                try:
                    open_ports.append(str(int(port)))
                except Exception:
                    pass

            name = (
                getattr(svc, "service_name", None)
                or getattr(svc, "name", None)
                or ""
            )
            if name:
                service_names.append(str(name))

        df = pd.DataFrame(
            [
                {
                    "ip": getattr(host, "ip_address", ""),
                    "os_fingerprint": getattr(host, "os_name", None)
                    or getattr(host, "os_family", None)
                    or "",
                    "open_ports": ",".join(open_ports),
                    "services": ",".join(service_names),
                    "mac_vendor": "",
                    "hostname": getattr(host, "hostname", ""),
                }
            ]
        )

        feature_df = self.extractor.extract_features(df)
        row = feature_df.iloc[0].to_dict()

        # IMPORTANT: keep only the subset of features the model expects.
        # This prevents scaler dimension mismatch when prediction is run on
        # DB-derived inputs that may lead to slightly different extractor output.
        # If we can't determine expected features here, fall back to numeric-only.
        #
        # Training script uses: src/ml/feature_extractor.DeviceFeatureExtractor
        # which currently produces 19 columns for the training CSV.
        #
        # We'll filter by a known stable feature set produced by that extractor.
        # Keep feature-name ordering stable by using the 10-feature subset
        # produced by the training-time feature pipeline that `model_trainer`
        # sees (it filters numeric columns from the training DataFrame).
        expected_keys = {
            'has_http', 'has_https', 'has_ssh', 'has_smtp', 'has_ftp', 'has_sql',
            'has_rdp', 'has_snmp', 'num_ports', 'port_range_span'
        }


        out: Dict[str, float] = {}
        for k, v in row.items():
            if expected_keys and k not in expected_keys:
                continue
            try:
                out[str(k)] = float(v)
            except Exception:
                out[str(k)] = 0.0

        # If filtering removed everything, degrade gracefully.
        if not out:
            for k, v in row.items():
                try:
                    out[str(k)] = float(v)
                except Exception:
                    out[str(k)] = 0.0

        return out


