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

test_data = pd.read_csv('./data/test.csv')

X_test = test_data[['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.flags_numeric', 'tcp.window_size_value']]
y_test = test_data[['type_f', 'type_n']]

y_test_pred = model.predict(X_test)

print("Classification Report on Test Data:\n", classification_report(y_test, y_test_pred))

accuracy = accuracy_score(y_test, y_test_pred)
precision = precision_score(y_test, y_test_pred, average="weighted",zero_division=0)
recall = recall_score(y_test, y_test_pred, average="weighted",zero_division=0)
f1 = f1_score(y_test, y_test_pred average="weighted",zero_division=0)

metrics = {
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1
}

CSV_PATH = "metrics/test_metrics.csv"

with open(CSV_PATH, mode="a", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=metrics.keys())

    # Write header only once
    if f.tell() == 0:
        writer.writeheader()

    writer.writerow(metrics)

print("[*] Metrics saved to test_metrics.csv")