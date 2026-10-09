## AI -Powered Threat Detection PLatform

## Description
AI - powered threat detection and response platform that streams and processes live traffic to detect active attacks and annomalies in real time.

# Layer 3 Threat Detection Engine (Isolation Forest)

This directory contains the implementation of the **Layer 3 Anomaly Detection Engine** for network traffic monitoring. It utilizes an **Isolation Forest** unsupervised machine learning model trained on the CIC-IDS-2017 dataset to flag potential security threats and DDoS anomalies.

---

## Directory Structure

```text
app/
├── ml_engine.py              # Data preprocessing & Isolation Forest training pipeline
└── models/
    └── isolation_forest.joblib # Serialized model artifact (generated after training)
