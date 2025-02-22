import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import sys
from io import BytesIO
import base64
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('firewall_analysis.log'),
        logging.StreamHandler()
    ]
)

def analyze_firewall_logs(input_file):
    """
    Analyzes firewall logs and returns analysis results as a JSON object
    Args:
        input_file: Path to input csv file containing analysis parameters
    Returns:
        dict: Analysis results as a JSON-serializable dictionary
    """
    try:
        logging.info(f"Starting firewall log analysis with input file: {input_file}")
        
        
        
        # Load dataset
        logging.info(f"Loading dataset from file_path: {input_file}")
        df = pd.read_csv(input_file)
        logging.info(f"Loaded {len(df)} records from dataset")
        
        # Convert Timestamp to datetime
        df["Timestamp"] = pd.to_datetime(df["Timestamp"])

        # Encode categorical variables
        label_encoders = {}
        for col in ["Protocol", "Action", "Threat_Level"]:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            label_encoders[col] = le

        # Select numerical features for anomaly detection
        features = ["Source_Port", "Destination_Port", "Protocol", "Action", "Bytes_Transferred", "Threat_Level"]
        X = df[features]

        # Train Isolation Forest model
        logging.info("Training Isolation Forest model")
        iso_forest = IsolationForest(contamination=0.05, random_state=42)
        df["Anomaly"] = iso_forest.fit_predict(X)
        df["Anomaly"] = df["Anomaly"].apply(lambda x: 1 if x == -1 else 0)
        
        # Create visualization
        logging.info("Generating visualization")
        plt.figure(figsize=(12, 6))
        sns.lineplot(x=df["Timestamp"], y=df["Bytes_Transferred"], label="Log Count", marker="o")
        sns.scatterplot(
            x=df[df["Anomaly"] == 1]["Timestamp"],
            y=df[df["Anomaly"] == 1]["Bytes_Transferred"],
            color="red",
            label="Anomalies",
            marker="x",
            s=100
        )
        plt.xlabel("Timestamp")
        plt.ylabel("Bytes Transferred")
        plt.title("Firewall Anomaly Detection")
        plt.legend()
        plt.xticks(rotation=45)
        
        # Save plot to bytes
        buf = BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_bytes = buf.getvalue()
        plt.close()  # Close the figure to free memory
        
        # Calculate number of anomalies
        num_anomalies = df[df["Anomaly"] == 1].shape[0]
        logging.info(f"Detected {num_anomalies} anomalies")
        
        image_base64 = base64.b64encode(image_bytes).decode('utf-8')
        
        # Prepare output data
        output_data = {
            'total_logs': len(df),
            'malicious_events': num_anomalies,
            'alert_level': 'High' if num_anomalies > ((int) (len(df)*0.1)) else 'Medium' if num_anomalies > ((int) (len(df)*0.05)) else 'Low',
            "sourceIp": "\n,".join(df[df["Anomaly"] == 1]["Source_IP"].tolist()),
            'log_type': "Firewall Logs",
            'graph_data': image_base64
        }
        
        logging.info("Analysis completed successfully")
        return output_data

    except Exception as e:
        logging.error(f"Error during analysis: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python firewall_analysis.py <input_file_path>"}))
        sys.exit(1)
    
    try:
        input_file = sys.argv[1]
        result = analyze_firewall_logs(input_file)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({
            "error": str(e),
            "traceback": logging.format_exc()
        }))
        sys.exit(1)
