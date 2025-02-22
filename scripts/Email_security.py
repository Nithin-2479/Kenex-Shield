import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import sys
from io import BytesIO
import base64
import logging
import json
from typing import Dict, Any, Optional

# Configure logging with more detailed formatting
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('email_analysis.log'),
        logging.StreamHandler()
    ]
)

def load_and_preprocess_data(file_path: str) -> tuple[pd.DataFrame, Optional[str]]:
    """Load and preprocess email log data."""
    try:
        df = pd.read_csv(file_path)
        logging.info(f"Successfully loaded data from {file_path} with {len(df)} records")
        
        # Detect timestamp column
        timestamp_col = next(
            (col for col in df.columns if any(keyword in col.lower() for keyword in ['time', 'date'])), 
            None
        )
        
        if timestamp_col:
            df[timestamp_col] = pd.to_datetime(df[timestamp_col], errors='coerce')
            if df[timestamp_col].isna().any():
                logging.warning(f"Some timestamp values could not be parsed in column '{timestamp_col}'")
        
        # Encode categorical variables
        categorical_cols = df.select_dtypes(include=['object']).columns.tolist()
        for col in categorical_cols:
            try:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
            except Exception as e:
                logging.error(f"Error encoding column '{col}': {str(e)}")
                raise ValueError(f"Failed to encode categorical column: {col}")
                
        return df, timestamp_col
        
    except Exception as e:
        logging.error(f"Error in load_and_preprocess_data: {str(e)}")
        raise

def detect_anomalies(df: pd.DataFrame, contamination: float = 0.05) -> pd.DataFrame:
    """Detect anomalies using Isolation Forest."""
    try:
        num_cols = df.select_dtypes(include=['number']).columns.tolist()
        num_cols = [col for col in num_cols if col != 'Anomaly']
        
        if not num_cols:
            raise ValueError("No numerical features found for anomaly detection")
            
        X = df[num_cols]
        iso_forest = IsolationForest(contamination=contamination, random_state=42)
        df['Anomaly'] = iso_forest.fit_predict(X)
        df['Anomaly'] = df['Anomaly'].apply(lambda x: 1 if x == -1 else 0)
        
        num_anomalies = df['Anomaly'].sum()
        logging.info(f"Detected {num_anomalies} anomalies ({(num_anomalies/len(df))*100:.2f}%)")
        
        return df
        
    except Exception as e:
        logging.error(f"Error in detect_anomalies: {str(e)}")
        raise

def plot_anomalies(df: pd.DataFrame, timestamp_col: str) -> Optional[str]:
    """Generate anomaly visualization plot."""
    try:
        if not timestamp_col or timestamp_col not in df.columns:
            logging.warning("Cannot plot anomalies: No timestamp column available")
            return None
            
        num_cols = df.select_dtypes(include=['number']).columns.tolist()
        metric_col = next((col for col in num_cols if col not in ['Anomaly']), None)
        
        if not metric_col:
            logging.warning("Cannot plot anomalies: No suitable numeric column found")
            return None
            
        plt.figure(figsize=(12, 6))
        sns.lineplot(x=df[timestamp_col], y=df[metric_col], label=metric_col, marker='o')
        sns.scatterplot(
            x=df[df['Anomaly'] == 1][timestamp_col],
            y=df[df['Anomaly'] == 1][metric_col],
            color='red',
            label='Anomalies',
            marker='x',
            s=100
        )
        plt.xlabel('Timestamp')
        plt.ylabel(metric_col)
        plt.title(f'Email Log Anomaly Detection ({metric_col})')
        plt.legend()
        plt.xticks(rotation=45)
        
        buf = BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_bytes = buf.getvalue()
        plt.close()
        
        return base64.b64encode(image_bytes).decode('utf-8')
        
    except Exception as e:
        logging.error(f"Error in plot_anomalies: {str(e)}")
        plt.close()
        return None

def analyse_email_logs(file_path: str) -> Dict[str, Any]:
    """Main analysis function with improved error handling."""
    try:
        df, timestamp_col = load_and_preprocess_data(file_path)
        df = detect_anomalies(df)
        image_base64 = plot_anomalies(df, timestamp_col)
        
        num_anomalies = int(df['Anomaly'].sum())
        total_logs = len(df)
        
        output_data = {
            'total_logs': total_logs,
            'malicious_events': num_anomalies,
            'alert_level': 'High' if num_anomalies > (total_logs * 0.1) else 
                          'Medium' if num_anomalies > (total_logs * 0.05) else 'Low',
            'sourceIp': "",
            'log_type': "Email Security Logs",
            'graph_data': image_base64
        }
        
        logging.info(f"Analysis completed successfully. Alert level: {output_data['alert_level']}")
        return output_data
        
    except Exception as e:
        logging.error(f"Analysis failed: {str(e)}", exc_info=True)
        raise

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(json.dumps({"error": "Usage: python email_security.py <input_file_path>"}))
        sys.exit(1)
    
    try:
        result = analyse_email_logs(sys.argv[1])
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
