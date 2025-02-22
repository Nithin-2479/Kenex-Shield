import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Model # type: ignore
from tensorflow.keras.layers import Input, LSTM, RepeatVector, TimeDistributed, Dense, Dropout # type: ignore
from tensorflow.keras.callbacks import EarlyStopping # type: ignore
import sys
from io import BytesIO
import base64
import json
import logging
from typing import Dict, Any, List, Tuple
import traceback

# Configure logging with more detailed format
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_analysis.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def load_and_preprocess_data(file_path: str) -> Tuple[pd.DataFrame, np.ndarray, List[str]]:
    """Load and preprocess network log data."""
    try:
        df = pd.read_csv(file_path)
        logger.info(f"Successfully loaded data from {file_path} with shape {df.shape}")
        
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        
        numerical_features = ['packet_size', 'duration', 'bytes_sent', 'bytes_received']
        scaler = MinMaxScaler()
        scaled_data = scaler.fit_transform(df[numerical_features])
        
        logger.info(f"Preprocessed data shape: {scaled_data.shape}")
        return df, scaled_data, numerical_features
    except Exception as e:
        logger.error(f"Error in data preprocessing: {str(e)}")
        raise

def create_sequences(data_array: np.ndarray, window_size: int = 10) -> np.ndarray:
    """Create sequences for LSTM processing."""
    try:
        sequences = []
        for i in range(len(data_array) - window_size):
            sequences.append(data_array[i:i+window_size])
        return np.array(sequences)
    except Exception as e:
        logger.error(f"Error creating sequences: {str(e)}")
        raise

def build_and_train_model(sequences: np.ndarray, window_size: int, input_dim: int) -> Model:
    """Build and train the LSTM autoencoder model."""
    try:
        inputs = Input(shape=(window_size, input_dim))
        encoded = LSTM(64, activation='relu', return_sequences=True)(inputs)
        encoded = Dropout(0.2)(encoded)
        encoded = LSTM(32, activation='relu', return_sequences=False)(encoded)
        encoded = Dropout(0.2)(encoded)

        decoded = RepeatVector(window_size)(encoded)
        decoded = LSTM(64, activation='relu', return_sequences=True)(decoded)
        decoded = Dropout(0.2)(decoded)
        decoded = TimeDistributed(Dense(input_dim))(decoded)

        autoencoder = Model(inputs, decoded)
        autoencoder.compile(optimizer='adam', loss='mse')
        
        early_stop = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
        
        logger.info("Training model...")
        autoencoder.fit(
            sequences, sequences,
            epochs=25,
            batch_size=32,
            validation_split=0.1,
            callbacks=[early_stop],
            verbose=1
        )
        logger.info("Model training completed")
        
        return autoencoder
    except Exception as e:
        logger.error(f"Error in model building/training: {str(e)}")
        raise

def generate_plot(anomaly_df: pd.DataFrame, threshold: float) -> str:
    """Generate and save the anomaly detection plot."""
    try:
        severity_colors = {'normal': 'green', 'medium': 'orange', 'high': 'red'}
        plt.figure(figsize=(12,6))
        plt.scatter(anomaly_df.index, anomaly_df['reconstruction_error'],
                   c=anomaly_df['severity'].map(severity_colors), alpha=0.7, edgecolor='k')
        plt.axhline(threshold, color='red', linestyle='--', linewidth=2, label='Anomaly Threshold')
        plt.title("Anomaly Severity Classification", fontsize=16)
        plt.xlabel("Time", fontsize=14)
        plt.ylabel("Reconstruction Error", fontsize=14)
        plt.legend(fontsize=12)
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()

        buf = BytesIO()
        plt.savefig(buf, format='png', dpi=300, bbox_inches='tight')
        plt.close()
        buf.seek(0)
        image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        buf.close()
        
        return image_base64
    except Exception as e:
        logger.error(f"Error generating plot: {str(e)}")
        raise

def analyze_network_logs(file_path: str) -> Dict[str, Any]:
    """Main function to analyze network logs."""
    try:
        # Load and preprocess data
        df, scaled_data, numerical_features = load_and_preprocess_data(file_path)
        
        # Create sequences
        window_size = 10
        sequences = create_sequences(scaled_data, window_size)
        logger.info(f"Created sequences with shape: {sequences.shape}")

        # Build and train model
        input_dim = len(numerical_features)
        autoencoder = build_and_train_model(sequences, window_size, input_dim)

        # Generate reconstructions and calculate MSE
        reconstructions = autoencoder.predict(sequences)
        mse = np.mean(np.power(sequences - reconstructions, 2), axis=(1, 2))
        threshold = np.percentile(mse, 65)
        logger.info(f"Anomaly Detection Threshold (65th percentile): {threshold:.4f}")

        # Classify anomalies
        anomaly_df = df.iloc[window_size:].copy()
        anomaly_df['reconstruction_error'] = mse
        anomaly_df['severity'] = 'normal'
        anomaly_df.loc[anomaly_df['reconstruction_error'] > threshold, 'severity'] = 'high'
        medium_threshold = np.percentile(mse, 60)
        anomaly_df.loc[(anomaly_df['reconstruction_error'] > medium_threshold) &
                       (anomaly_df['reconstruction_error'] <= threshold), 'severity'] = 'medium'
        logger.info("Anomaly Severity Classification:")
        logger.info(anomaly_df[['reconstruction_error', 'severity']].head())

        # Generate plot
        image_base64 = generate_plot(anomaly_df, threshold)

        # Filter anomalies
        filtered_anomalies = anomaly_df[anomaly_df['severity'] == 'high']
        num_anomalies = filtered_anomalies.shape[0]
        logger.info(f"Number of Anomalies Detected: {num_anomalies}")

        # Prepare output data
        output_data = {
            'total_logs': len(df),
            'malicious_events': num_anomalies,
            'alert_level': 'High' if num_anomalies > ((int) (len(df)*0.1)) else 'Medium' if num_anomalies > ((int) (len(df)*0.05)) else 'Low',
            "sourceIp": "\n,".join(filtered_anomalies["source_ip"].tolist()),
            'log_type': "Network Traffic Logs",
            'graph_data': image_base64
        }

        logger.info("Analysis completed successfully")
        return output_data
    except Exception as e:
        logger.error(f"Error in network log analysis: {str(e)}")
        logger.error(traceback.format_exc())
        raise

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python firewall_analysis.py <input_file_path>"}))
        sys.exit(1)
    
    try:
        input_file = sys.argv[1]
        result = analyze_network_logs(input_file)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc()
        }))
        sys.exit(1)