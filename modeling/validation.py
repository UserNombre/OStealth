import pandas as pd
import pickle
from sklearn.metrics import classification_report
import numpy as np

with open('./models/model.pkl', 'rb') as file:
    model = pickle.load(file)

validation_data = pd.read_csv('./data/validation.csv')

X_val = validation_data[['tcp.srcport', 'tcp.dstport', 'tcp.flags', 'tcp.flags_numeric', 'tcp.window_size_value']]
y_val = validation_data[['type_f', 'type_n']]

y_val_pred = model.predict(X_val)

print("Classification Report on Validation Data:\n", classification_report(y_val, y_val_pred))

