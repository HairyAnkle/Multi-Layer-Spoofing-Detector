"""
Pipeline:
CSV (from FIXED CICFlowMeter Docker)
→ CICPreprocessor
→ Hybrid Random Forest + XGBoost
→ JSON (for WPF)
"""

import os
import sys
import json
import joblib
import pandas as pd

from cic_preprocessor import CICPreprocessor

class SpoofingDetector:
    """
    Handles ML inference only.
    Feature extraction (PCAP → CSV) is handled by CICFlowMeter Docker.
    """

    def __init__(self, model_path=None):
        try:
            if model_path is None:
                base_dir = os.path.dirname(os.path.abspath(__file__))
                model_path = os.path.abspath(
                    os.path.join(base_dir, "..", "models", "RFandXGBoost.pkl")
                )

            bundle = joblib.load(model_path)

            self.pipeline = bundle["pipeline"]
            self.label_encoder = bundle["label_encoder"]

            self.emit_status("success", "Hybrid RF + XGBoost model loaded")

        except Exception as e:
            self.emit_error(f"Model loading failed: {str(e)}")

    # CSV loading (raw CICFlowMeter output)
    def load_csv(self, csv_path):
        try:
            df = pd.read_csv(csv_path)

            if df.empty:
                raise ValueError("CSV file is empty")

            if "Label" in df.columns:
                df = df.drop(columns=["Label"])

            return df

        except Exception as e:
            self.emit_error(f"CSV loading error: {str(e)}")

    # Main inference pipeline
    def detect_spoofing(self, csv_path):
        try:
            if not os.path.exists(csv_path):
                self.emit_error("CSV file not found")

            self.emit_status("processing", "Loading CICFlowMeter CSV")
            df = self.load_csv(csv_path)

            self.emit_status("processing", "Running Hybrid RF + XGBoost inference")

            predictions = self.pipeline.predict(df)
            probabilities = self.pipeline.predict_proba(df)
            labels = self.label_encoder.inverse_transform(predictions)

            arp_spoofing = []
            dns_spoofing = []
            ip_spoofing = []

            for i, label in enumerate(labels):
                if label == "BENIGN":
                    continue

                confidence = round(float(probabilities[i].max()) * 100, 2)

                threat = {
                    "type": label,
                    "confidence": confidence,
                    "details": f"Flow {i} classified as {label}",
                    "src_ip": "Unknown"
                }

                if label == "ARP Spoofing":
                    arp_spoofing.append(threat)
                elif label == "DNS Spoofing":
                    dns_spoofing.append(threat)
                elif label == "IP Spoofing":
                    ip_spoofing.append(threat)

            print(json.dumps({
                "status": "success",
                "total_packets": int(len(df)),
                "arp_spoofing": arp_spoofing,
                "dns_spoofing": dns_spoofing,
                "ip_spoofing": ip_spoofing
            }))

            sys.exit(0)

        except Exception as e:
            self.emit_error(str(e))

    # Model metadata
    def get_model_info(self):
        try:
            info = {
                "model_type": "Hybrid Random Forest + XGBoost",
                "classes": list(self.label_encoder.classes_),
                "feature_count": len(
                    self.pipeline.named_steps["preprocessor"].feature_columns_
                ),
                "feature_extraction": "CICFlowMeter (Docker)"
            }

            print(json.dumps({
                "status": "success",
                "info": info
            }))

        except Exception as e:
            self.emit_error(str(e))

    # JSON helpers
    def emit_status(self, status, message):
        print(json.dumps({
            "status": status,
            "message": message
        }))

    def emit_error(self, message):
        print(json.dumps({
            "status": "error",
            "message": message
        }))
        sys.exit(1)

# CLI entry point (called from Docker / WPF)
def main():
    if len(sys.argv) < 2:
        print(json.dumps({
            "status": "error",
            "message": "Usage: python spoofing_detector.py <analyze|info> <csv_path>"
        }))
        sys.exit(1)

    command = sys.argv[1]
    detector = SpoofingDetector()

    if command == "analyze":
        if len(sys.argv) < 3:
            detector.emit_error("CSV path required")
        detector.detect_spoofing(sys.argv[2])

    elif command == "info":
        detector.get_model_info()

    else:
        detector.emit_error(f"Unknown command: {command}")

if __name__ == "__main__":
    main()


