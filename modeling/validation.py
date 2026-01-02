import pandas as pd
import pickle
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)
import numpy as np
import csv

with open('./models/model.pkl', 'rb') as file:
    model = pickle.load(file)

validation_data = pd.read_csv('./data/validation.csv')

X_val = validation_data[['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.flags_numeric', 'tcp.window_size_value']]
y_val = validation_data[['type_f', 'type_n']]

y_val_pred = model.predict(X_val)

accuracy = accuracy_score(y_val, y_val_pred)
precision = precision_score(y_val, y_val_pred, average="weighted",zero_division=0)
recall = recall_score(y_val, y_val_pred, average="weighted",zero_division=0)
f1 = f1_score(y_val, y_val_pred, average="weighted",zero_division=0)

metrics = {
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1
}

CSV_PATH = "metrics/validation_metrics.csv"

with open(CSV_PATH, mode="a", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=metrics.keys())

    if f.tell() == 0:
        writer.writeheader()

    writer.writerow(metrics)

print("[*] Metrics saved to validation_metrics.csv")

print("Classification Report on Validation Data:\n", classification_report(y_val, y_val_pred))

