import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.impute import SimpleImputer

file_path = r"C:\Users\SREE\Downloads\creditcard.csv (1)\creditcard.csv"

data = pd.read_csv(file_path)

print("Dataset Head:\n", data.head())
print("\nDataset Info:\n")
data.info()
print("\nDataset Description:\n", data.describe())

print("\nDataset Columns:\n", data.columns)

numerical_features = ['V1', 'V2', 'V3', 'V4', 'V5', 'V6', 'V7', 'V8', 'V9', 'V10', 'V11', 'V12', 'V13', 'V14', 'V15', 'V16', 'V17', 'V18', 'V19', 'V20', 'V21', 'V22', 'V23', 'V24', 'V25', 'V26', 'V27', 'V28', 'Amount']  # Example, adjust accordingly

data_numerical = data[numerical_features]

imputer = SimpleImputer(strategy='mean')
data_imputed = imputer.fit_transform(data_numerical)

scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_imputed)

isolation_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
anomaly_labels = isolation_forest.fit_predict(data_scaled)

anomaly_labels = pd.Series(anomaly_labels).map({1: 0, -1: 1})

data['Anomaly'] = anomaly_labels

anomalies = data[data['Anomaly'] == 1]
anomalies_file_path = r'C:\Users\SREE\Documents\extracted_anomalies.csv'
anomalies.to_csv(anomalies_file_path, index=False)
print(f"Anomalies exported to: {anomalies_file_path}")

def visualize_data(data, labels=None, title="Data Visualization"):
    plt.figure(figsize=(10, 6))
    if labels is None:
        plt.scatter(data[:, 0], data[:, 1], c='blue', s=10, label='Data')
    else:
        colors = np.array(['blue', 'red'])  # Normal: blue, Anomalies: red
        plt.scatter(data[:, 0], data[:, 1], c=colors[labels], s=10)
    plt.title(title)
    plt.xlabel('Feature 1')
    plt.ylabel('Feature 2')
    plt.legend(['Normal', 'Anomaly'] if labels is not None else ['Data'])
    plt.grid(True)
    plt.show()

visualize_data(data_scaled, title="Before Anomaly Detection")

visualize_data(data_scaled, anomaly_labels, title="After Anomaly Detection")
