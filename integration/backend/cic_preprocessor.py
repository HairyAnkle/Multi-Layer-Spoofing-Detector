import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.preprocessing import StandardScaler


class CICPreprocessor(BaseEstimator, TransformerMixin):
    """
    CICFlowMeter feature normalizer + scaler.
    """

    DEFAULT_RENAME_MAP = {
        "Total Fwd Packet": "Total Fwd Packets",
        "Total Bwd packets": "Total Backward Packets",
        "Total Length of Fwd Packet": "Fwd Packets Length Total",
        "Total Length of Bwd Packet": "Bwd Packets Length Total",
        "Average Packet Size": "Avg Packet Size",
        "Fwd Segment Size Avg": "Avg Fwd Segment Size",
        "Bwd Segment Size Avg": "Avg Bwd Segment Size",
        "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
        "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
        "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
        "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
        "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
        "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
        "FWD Init Win Bytes": "Init Fwd Win Bytes",
        "Bwd Init Win Bytes": "Init Bwd Win Bytes",
        "Fwd Act Data Pkts": "Fwd Act Data Packets"
    }

    DEFAULT_DROP_COLUMNS = [
        "Flow ID", "Src IP", "Dst IP",
        "Src Port", "Dst Port",
        "Timestamp", "Label",
        "ICMP Code", "ICMP Type",
        "Fwd TCP Retrans. Count",
        "Bwd TCP Retrans. Count",
        "Total TCP Retrans. Count"
    ]

    def __init__(self):
        self.scaler = StandardScaler()
        self.feature_columns_ = None
        self.exclude_log = ["Protocol", "Down/Up Ratio"]

        self.allowed_columns = [
            "Protocol",
            "Flow Duration",
            "Total Fwd Packets",
            "Total Backward Packets",
            "Fwd Packets Length Total",
            "Bwd Packets Length Total",
            "Fwd Packet Length Max",
            "Fwd Packet Length Min",
            "Fwd Packet Length Mean",
            "Fwd Packet Length Std",
            "Bwd Packet Length Max",
            "Bwd Packet Length Min",
            "Bwd Packet Length Mean",
            "Bwd Packet Length Std",
            "Flow Bytes/s",
            "Flow Packets/s",
            "Flow IAT Mean",
            "Flow IAT Std",
            "Flow IAT Max",
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Std",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Bwd IAT Total",
            "Bwd IAT Mean",
            "Bwd IAT Std",
            "Bwd IAT Max",
            "Bwd IAT Min",
            "Fwd PSH Flags",
            "Bwd PSH Flags",
            "Fwd Header Length",
            "Bwd Header Length",
            "Fwd Packets/s",
            "Bwd Packets/s",
            "Packet Length Min",
            "Packet Length Max",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "FIN Flag Count",
            "SYN Flag Count",
            "RST Flag Count",
            "PSH Flag Count",
            "ACK Flag Count",
            "Down/Up Ratio",
            "Avg Packet Size",
            "Avg Fwd Segment Size",
            "Avg Bwd Segment Size",
            "Fwd Avg Bytes/Bulk",
            "Fwd Avg Packets/Bulk",
            "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk",
            "Bwd Avg Packets/Bulk",
            "Bwd Avg Bulk Rate",
            "Subflow Fwd Packets",
            "Subflow Fwd Bytes",
            "Subflow Bwd Packets",
            "Subflow Bwd Bytes",
            "Init Fwd Win Bytes",
            "Init Bwd Win Bytes",
            "Fwd Act Data Packets",
            "Fwd Seg Size Min",
            "Active Mean",
            "Active Std",
            "Active Max",
            "Active Min",
            "Idle Mean",
            "Idle Std",
            "Idle Max",
            "Idle Min"
        ]

        self.rename_map = self.DEFAULT_RENAME_MAP.copy()
        self.drop_columns = self.DEFAULT_DROP_COLUMNS.copy()


    def __setstate__(self, state):
        self.__dict__.update(state)

        # Restore missing attributes from older models
        if not hasattr(self, "rename_map"):
            self.rename_map = self.DEFAULT_RENAME_MAP.copy()

        if not hasattr(self, "drop_columns"):
            self.drop_columns = self.DEFAULT_DROP_COLUMNS.copy()

        if not hasattr(self, "exclude_log"):
            self.exclude_log = ["Protocol", "Down/Up Ratio"]

    def _normalize_schema(self, X):
        X = X.rename(columns=self.rename_map)

        X = X.drop(
            columns=[c for c in self.drop_columns if c in X.columns],
            errors="ignore"
        )

        for col in self.allowed_columns:
            if col not in X.columns:
                X[col] = 0.0

        return X[self.allowed_columns]

    def fit(self, X, y=None):
        X = self._normalize_schema(X)
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        num_cols = [c for c in X.columns if c != "Protocol"]
        log_cols = [c for c in num_cols if c not in self.exclude_log]

        X[log_cols] = np.log1p(X[log_cols].clip(lower=0))
        X[num_cols] = self.scaler.fit_transform(X[num_cols])

        X = pd.get_dummies(X, columns=["Protocol"], prefix="Protocol")
        self.feature_columns_ = X.columns.tolist()
        return self

    def transform(self, X):
        X = self._normalize_schema(X)
        X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

        num_cols = [c for c in X.columns if c != "Protocol"]
        log_cols = [c for c in num_cols if c not in self.exclude_log]

        X[log_cols] = np.log1p(X[log_cols].clip(lower=0))
        X[num_cols] = self.scaler.transform(X[num_cols])

        X = pd.get_dummies(X, columns=["Protocol"], prefix="Protocol")
        return X.reindex(columns=self.feature_columns_, fill_value=0)
