import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.svm import OneClassSVM

data = pd.read_csv("C:/Users/SREE/Downloads/creditcard.csv (1)/creditcard.csv")

print("Dataset Head:\n", data.head())
print("Dataset Info:\n", data.info())
print("Dataset Description:\n", data.describe())

numerical_features = data.drop(columns=['Class']).columns
data_numerical = data[numerical_features]

scaler = StandardScaler()
data_scaled = scaler.fit_transform(data_numerical)

pca = PCA(n_components=2)
X_pca = pca.fit_transform(data_scaled)

svm_model = OneClassSVM(nu=0.01, kernel='rbf', gamma='auto')  
svm_model.fit(X_pca)

y_pred = svm_model.predict(X_pca)

plt.scatter(X_pca[:, 0], X_pca[:, 1], c=y_pred, cmap='coolwarm', marker='o', s=50, alpha=0.6)

plt.xlabel('PCA Component 1')
plt.ylabel('PCA Component 2')
plt.title('One-Class SVM Anomaly Detection')
plt.colorbar(label='Anomaly Status')

plt.show()
