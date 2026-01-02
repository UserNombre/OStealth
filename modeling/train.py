import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report
)
from sklearn.preprocessing import LabelEncoder
import pickle
import numpy as np
import csv

data = pd.read_csv('./data/train.csv')

X = data[['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.flags_numeric', 'tcp.window_size_value']]
y = data[['type_f', 'type_n']]

model = RandomForestClassifier(class_weight='balanced', max_depth=2, n_estimators=200, random_state=42)

model.fit(X, y)

y_pred = model.predict(X)

print("Classification Report:\n", classification_report(y, y_pred))

with open('./models/model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("Model saved as './models/model.pkl'")

accuracy = accuracy_score(y, y_pred)
precision = precision_score(y ,y_pred,average="weighted", zero_division=0)
recall = recall_score(y, y_pred, average="weighted",zero_division=0)
f1 = f1_score(y, y_pred ,average="weighted",zero_division=0)

metrics = {
    "accuracy": accuracy,
    "precision": precision,
    "recall": recall,
    "f1_score": f1
}

CSV_PATH = "metrics/training_metrics.csv"

with open(CSV_PATH, mode="a", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=metrics.keys())

    if f.tell() == 0:
        writer.writeheader()

    writer.writerow(metrics)

print("[*] Metrics saved to training_metrics.csv")



