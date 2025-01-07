import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score

import warnings
warnings.filterwarnings('ignore')

try:
    df = pd.read_csv("C:/Users/SREE/Downloads/creditcard.csv (1)/creditcard.csv")

    X = df.drop(columns=["Class", "Time"])
    y = df["Class"]

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_scaled = np.reshape(X_scaled, (X_scaled.shape[0], 1, X_scaled.shape[1]))

    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    model = Sequential()
    model.add(LSTM(units=50, return_sequences=False, input_shape=(X_train.shape[1], X_train.shape[2])))
    model.add(Dense(units=1, activation="sigmoid"))

    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])

    history = model.fit(X_train, y_train, epochs=20, batch_size=32, validation_data=(X_test, y_test), verbose=1)

    plt.figure(figsize=(10, 5))
    plt.plot(history.history['loss'], label="Training Loss", color="blue", linestyle='-', linewidth=2)
    plt.plot(history.history['val_loss'], label="Validation Loss", color="orange", linestyle='--', linewidth=2)

    anomalies_indices = np.where(y_test == 1)[0]  

    valid_anomalies_indices = anomalies_indices[anomalies_indices < len(history.history['val_loss'])]

    plt.scatter(valid_anomalies_indices, np.array(history.history['val_loss'])[valid_anomalies_indices], color="red", s=50, label="Anomalies", zorder=5)

    plt.title("Model Loss Over Epochs with Anomalies")
    plt.xlabel("Epochs")
    plt.ylabel("Loss")
    plt.legend()
    plt.grid(True)
    plt.show()

    y_pred = model.predict(X_test)
    y_pred = (y_pred > 0.5)  

    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_pred)

    print("Model Evaluation Metrics:")
    print(f"Precision: {precision}")
    print(f"Recall: {recall}")
    print(f"F1-Score: {f1}")
    print(f"ROC-AUC: {roc_auc}")

    test_indices = y_test.index  
    anomalies = df.iloc[test_indices]  
    anomalies['Predicted'] = y_pred 

    anomalies.to_csv("C:/Users/SREE/Documents/detected_anomalies_lstm.csv", index=False)

except Exception as e:
    print(f"An error occurred: {e}")
