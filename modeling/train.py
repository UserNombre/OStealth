import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder
import pickle
import numpy as np

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