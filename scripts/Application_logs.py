import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential # type: ignore
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed, Dropout, BatchNormalization # type: ignore
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
import re
import matplotlib.pyplot as plt
from sklearn.feature_extraction.text import TfidfVectorizer
import tensorflow.keras.backend as K # type: ignore
import json
import sys
from io import BytesIO
import base64
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('application_analysis.log'),
        logging.StreamHandler()
    ]
)

TIME_STEPS = 10

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

def create_sequences(data, time_steps=TIME_STEPS):
        sequences = []
        for i in range(len(data) - time_steps):
            sequences.append(data[i:i + time_steps])
        return np.array(sequences)

def custom_loss(y_true, y_pred):
    return K.mean(K.square(y_true - y_pred))

def analyse_application_logs(file_path):

    df = pd.read_csv(file_path, on_bad_lines='skip')
    data = preprocess_structured_logs(df)

    # Create sequences for LSTM
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



    model.compile(optimizer='adam', loss=custom_loss)
    model.summary()

    # Train Autoencoder with improved configuration
    X_train = data_sequences
    model.fit(X_train, X_train, epochs=1, batch_size=64, validation_split=0.1, shuffle=True)

  
    
    X_pred = model.predict(data_sequences)
    mse = np.mean(np.power(data_sequences - X_pred, 2), axis=(1, 2))

    
    #create a new dataframe with the mse values and IP_Address[10:] column
    anamoly_df = pd.DataFrame()
    anamoly_df['MSE'] = mse
    anamoly_df['IP_Address'] = df['IP_Address'][10:]
    #chang IPaddress to string
    anamoly_df['IP_Address'] = anamoly_df['IP_Address'].astype(str)
    

    # Dynamic threshold using IQR method
    Q1 = np.percentile(mse, 25)
    Q3 = np.percentile(mse, 75)
    IQR = Q3 - Q1
    threshold = Q3 + 1.5 * IQR
    
    anamoly_df = anamoly_df[anamoly_df['MSE'] > threshold]

    # Run real-time anomaly detection
    anomalies = mse > threshold

    plt.figure(figsize=(16, 8))
    plt.plot(mse, label='Error Level Over Time', color='blue', linewidth=1.5, linestyle='-')
    plt.scatter(np.where(anomalies)[0], mse[anomalies], color='red', marker='o', label='Anomalies', s=50)
    plt.axhline(y=threshold, color='r', linestyle='--', label='Anomaly Threshold')
    plt.xlabel('Log Entry Number', fontsize=14)
    plt.ylabel('Reconstruction Error (MSE)', fontsize=14)
    plt.title('Anomaly Detection in Application Logs', fontsize=16)
    plt.legend(fontsize=12)
    plt.grid(True, linestyle='--', alpha=0.6)
      # Save plot to bytes
    buf = BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    image_bytes = buf.getvalue()
    plt.close()  # Close the figure to free memory
    image_base64 = base64.b64encode(image_bytes).decode('utf-8')

    num_anomalies = len(anamoly_df)
    
     # Prepare output data
    output_data = {
        'total_logs': int(len(df)),
        'malicious_events': num_anomalies,
        'alert_level': 'High' if num_anomalies > ((int) (len(df)*0.1)) else 'Medium' if num_anomalies > ((int) (len(df)*0.05)) else 'Low',
        "sourceIp": "\n".join(anamoly_df["IP_Address"].tolist()),
        'log_type': "Application Logs",
        'graph_data': image_base64
    }

    print(output_data)
    return output_data


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python firewall_analysis.py <input_file_path>"}))
        sys.exit(1)
    
    try:
        input_file = sys.argv[1]
        result = analyse_application_logs(input_file)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "traceback": logging.format_exc()
        }))
        sys.exit(1)


