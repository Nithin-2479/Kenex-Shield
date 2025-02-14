import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed, Dropout, BatchNormalization
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
import re
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
import tensorflow.keras.backend as K

# Function to detect if logs are structured or unstructured
def detect_log_type(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        first_line = file.readline()
    return "," in first_line or "\t" in first_line  

# Function to preprocess structured logs
def preprocess_structured_logs(df):
    categorical_cols = [col for col in df.columns if df[col].dtype == 'object']
    numeric_cols = [col for col in df.columns if df[col].dtype != 'object']
    
    label_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        label_encoders[col] = le
    
    scaler = StandardScaler()
    df_scaled = scaler.fit_transform(df[numeric_cols])
    return df_scaled

# Function to preprocess unstructured logs
def preprocess_unstructured_logs(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        log_lines = file.readlines()
    
    # Extract potential features using regex
    features = []
    for line in log_lines:
        source_ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        status_code = re.search(r'\b(\d{3})\b', line)
        port = re.search(r'(?<!\d)(\d{2,5})(?!\d)', line)
        
        features.append([
            source_ip.group(0) if source_ip else '0.0.0.0',
            status_code.group(0) if status_code else '0',
            port.group(0) if port else '0'
        ])
    
    df = pd.DataFrame(features, columns=['source_ip', 'status_code', 'port'])
    
    # Convert extracted features to numerical
    df['status_code'] = df['status_code'].astype(int)
    df['port'] = df['port'].astype(int)
    df['source_ip'] = LabelEncoder().fit_transform(df['source_ip'])
    
    return StandardScaler().fit_transform(df)

# Load and preprocess logs dynamically
file_path = "C:\\Users\\SREE\\Downloads\\application_logs_5000.csv"
if detect_log_type(file_path):
    df = pd.read_csv(file_path, on_bad_lines='skip')
    data = preprocess_structured_logs(df)
else:
    data = preprocess_unstructured_logs(file_path)

# Create sequences for LSTM
TIME_STEPS = 10
def create_sequences(data, time_steps=TIME_STEPS):
    sequences = []
    for i in range(len(data) - time_steps):
        sequences.append(data[i:i + time_steps])
    return np.array(sequences)

data_sequences = create_sequences(data)

# Build LSTM Autoencoder with improvements
model = Sequential([
    LSTM(128, activation='relu', input_shape=(TIME_STEPS, data.shape[1]), return_sequences=True),
    BatchNormalization(),
    Dropout(0.2),
    LSTM(64, activation='relu', return_sequences=False),
    RepeatVector(TIME_STEPS),
    LSTM(64, activation='relu', return_sequences=True),
    BatchNormalization(),
    Dropout(0.2),
    LSTM(128, activation='relu', return_sequences=True),
    TimeDistributed(Dense(data.shape[1]))
])

def custom_loss(y_true, y_pred):
    return K.mean(K.square(y_true - y_pred))

model.compile(optimizer='adam', loss=custom_loss)
model.summary()

# Train Autoencoder with improved configuration
X_train = data_sequences
model.fit(X_train, X_train, epochs=50, batch_size=64, validation_split=0.1, shuffle=True)

# Detect Anomalies in Real-Time
def detect_anomalies(log_file):
    if detect_log_type(log_file):
        df_new = pd.read_csv(log_file, on_bad_lines='skip')
        new_data = preprocess_structured_logs(df_new)
    else:
        new_data = preprocess_unstructured_logs(log_file)
    
    new_sequences = create_sequences(new_data)
    
    X_pred = model.predict(new_sequences)
    mse = np.mean(np.power(new_sequences - X_pred, 2), axis=(1, 2))
    
    # Dynamic threshold using IQR method
    Q1 = np.percentile(mse, 25)
    Q3 = np.percentile(mse, 75)
    IQR = Q3 - Q1
    threshold = Q3 + 1.5 * IQR
    
    anomalies = mse > threshold
    
    return anomalies, mse, threshold

# Run real-time anomaly detection
anomalies, mse, threshold = detect_anomalies(file_path)

plt.figure(figsize=(16, 8))
plt.plot(mse, label='Error Level Over Time', color='blue', linewidth=1.5, linestyle='-')
plt.scatter(np.where(anomalies)[0], mse[anomalies], color='red', marker='o', label='Anomalies', s=50)
plt.axhline(y=threshold, color='r', linestyle='--', label='Anomaly Threshold')
plt.xlabel('Log Entry Number', fontsize=14)
plt.ylabel('Reconstruction Error (MSE)', fontsize=14)
plt.title('Anomaly Detection in Application Logs', fontsize=16)
plt.legend(fontsize=12)
plt.grid(True, linestyle='--', alpha=0.6)
plt.show()

print("Detected Anomalies at indexes:", np.where(anomalies))
