import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import sys
from io import BytesIO
import base64
import logging
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('endpoint_security.log'),
        logging.StreamHandler()
    ]
)

def analyze_endpoint_logs(input_file):
    try:
        logging.info(f"Starting endpoint security log analysis with input file: {input_file}")
        
        # Load dataset
        df = pd.read_csv(input_file, parse_dates=['Timestamp'])
        df.set_index('Timestamp', inplace=True)
        logging.info(f"Loaded {len(df)} records from dataset")
        
        # Feature Engineering
        severity_map = {'INFO': 1, 'WARNING': 2, 'CRITICAL': 3}
        df['severity_score'] = df['Severity'].map(severity_map)
        
        event_dummies = pd.get_dummies(df['Event_Type'], prefix='event')
        df = pd.concat([df, event_dummies], axis=1)
        
        action_map = {
            'NO_ACTION': 0, 'ALLOWED': 1, 'REPORTED': 2, 
            'QUARANTINED': 3, 'BLOCKED': 4
        }
        df['action_score'] = df['Action_Taken'].map(action_map)
        
        # Select numerical columns for analysis
        numerical_columns = ['severity_score', 'action_score'] + list(event_dummies.columns)
        df_numeric = df[numerical_columns]
        
        # Detect anomalies
        scaler = StandardScaler()
        df_scaled = scaler.fit_transform(df_numeric)
        
        iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        anomalies = iso_forest.fit_predict(df_scaled)
        
        # Create visualization
        plt.figure(figsize=(16, 8))
        plt.plot(df.index, iso_forest.score_samples(df_scaled), 
                label='Anomaly Score', color='blue', linewidth=1.5)
        plt.scatter(df.index[anomalies == -1], 
                   iso_forest.score_samples(df_scaled)[anomalies == -1],
                   color='red', marker='o', label='Anomalies', s=50)
        plt.xlabel('Timestamp', fontsize=14)
        plt.ylabel('Anomaly Score', fontsize=14)
        plt.title('Endpoint Security Anomaly Detection', fontsize=16)
        plt.legend(fontsize=12)
        plt.grid(True, linestyle='--', alpha=0.6)

        # Save plot to base64
        buf = BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        plt.close()

        # Count anomalies and get suspicious IPs
        num_anomalies = np.sum(anomalies == -1)
        suspicious_ips = df['Source_IP'][anomalies == -1].unique().tolist()

        return {
            'total_logs': len(df),
            'malicious_events': int(num_anomalies),
            'alert_level': 'High' if num_anomalies > (len(df)*0.1) else 
                         'Medium' if num_anomalies > (len(df)*0.05) else 'Low',
            'sourceIp': "\n".join(map(str, suspicious_ips)) if suspicious_ips else "No suspicious IPs detected",
            'log_type': "Endpoint Security Logs",
            'graph_data': image_base64
        }

    except Exception as e:
        logging.error(f"Error during analysis: {str(e)}", exc_info=True)
        return {
            "error": str(e),
            "traceback": traceback.format_exc()
        }

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python endpoint_security.py <input_file_path>"}))
        sys.exit(1)
    
    try:
        input_file = sys.argv[1]
        result = analyze_endpoint_logs(input_file)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "traceback": traceback.format_exc()
        }))
        sys.exit(1)