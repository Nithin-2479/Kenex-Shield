import sys
import json
import os
import base64
import logging
from typing import Dict, Any
import subprocess
from datetime import datetime
import mysql.connector
from mysql.connector import Error


import base64
from PIL import Image
import io

# Add database configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'Shield_db',
    'password': 'Shield_db',
    'database': 'Shield_db'
}

# Set up logging
logging.basicConfig(
    filename='log_analyzer.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class LogAnalyzerMaster:
    def __init__(self):
        self.base_path = os.path.dirname(os.path.abspath(__file__))
        self.temp_dir = os.path.join(os.path.dirname(self.base_path),"temp")
        self.analysis_scripts = {
            "Network Traffic Logs": "Network_security.py",
            "Firewall Logs": "Firewall_analysis.py",
            "DNS Query Logs": "DNS_analysis.py",
            "Email Security Logs": "Email_security.py",
            "Application Logs": "Application_logs.py",
            "Endpoint Security Logs": "Endpoint_security.py"
        }
        self._setup_environment()

    def _setup_environment(self):
        """Create necessary directories and validate environment"""
        try:
            os.makedirs(self.temp_dir, exist_ok=True)
            logging.info(f"Temporary directory confirmed: {self.temp_dir}")
            
            # Validate all analysis scripts exist
            for script_name in self.analysis_scripts.values():
                script_path = os.path.join(self.base_path, script_name)
                if not os.path.exists(script_path):
                    logging.warning(f"Analysis script not found: {script_path}")
        except Exception as e:
            logging.error(f"Environment setup failed: {str(e)}")
            raise

    # def _decode_base64(self, base64_data: str) -> bytes:
    #     """Decode base64 data with proper padding and validation"""
    #     try:
    #         data = base64_data
    #         missing_padding = len(data) % 4
    #         if missing_padding != 0:
    #             data += '=' * (4 - missing_padding)
    #         return base64.b64decode(data)
            
    #     except Exception as e:
    #         logging.error(f"Base64 decoding error: {str(e)}")
    #         logging.debug(f"Base64 string length: {len(base64_data)}")
    #         logging.debug(f"First 100 chars of base64 data: {base64_data[:100]}")
    #         raise ValueError(f"Invalid base64 data: {str(e)}")

    def _save_temp_file(self, file_data: str, log_type: str) -> str:
        """Save base64 encoded file data to a temporary file"""
        try:
            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            temp_filename = f"temp_{log_type.replace(' ', '_')}_{timestamp}.csv"
            temp_file_path = os.path.join(self.temp_dir, temp_filename)
            
            logging.info(f"Saving temporary file: {temp_file_path}")
            
            # # Decode base64 data
            # try:
            #     decoded_data = self._decode_base64(file_data)
            #     logging.info("Successfully decoded base64 data")
            # except ValueError as e:
            #     logging.error(f"Base64 decoding failed: {str(e)}")
            #     raise
                
            # Write decoded data to temporary file
            # with open(temp_file_path, 'wb') as f:
            #     f.write(decoded_data)

            with open(temp_file_path, 'wb') as f:
                f.write(file_data)
            
            logging.info(f"Successfully saved temporary file: {temp_file_path}")
            return temp_file_path
            
        except Exception as e:
            logging.error(f"Failed to save temporary file: {str(e)}")
            raise

    def analyze_logs(self, log_type: str, file_data: str) -> Dict[str, Any]:
        """Execute log analysis for the specified log type"""
        if log_type not in self.analysis_scripts:
            error_msg = f"Unsupported log type: {log_type}"
            logging.error(error_msg)
            return {"success": False, "error": error_msg}

        temp_file = None
        try:
            logging.info("File data length is: " + str(len(file_data)))
            # Save incoming data to temporary file
            temp_file = self._save_temp_file(file_data, log_type)
            
            # Get analysis script path
            script_name = self.analysis_scripts[log_type]
            script_path = os.path.join(self.base_path, script_name)
            
            logging.info(f"Executing analysis script: {script_path} with file: {temp_file}")
            
            # Execute analysis script with log file path as argument
            result = subprocess.run(
                ['python', script_path, temp_file],
                capture_output=True,
                text=True,
                check=True
            )
            
           

            json_output = result.stdout.strip().split('\n')[-1]  # Get last line
            logging.info(f"Analysis script output:\n{json_output}")
            
            # Parse JSON output from the analysis script
            try:
                analysis_results = json.loads(json_output)
                return {
                    "success": True,
                    "log_type": log_type,
                    "results": analysis_results
                }
            except json.JSONDecodeError as e:
                raise Exception(f"Failed to parse analysis results: {str(e)}\nOutput: {result.stdout}")

        except subprocess.CalledProcessError as e:
            error_msg = f"Analysis script failed with exit code {e.returncode}: {e.stderr}"
            logging.error(error_msg)
            return {
                "success": False,
                "log_type": log_type,
                "error": error_msg
            }
        except Exception as e:
            error_msg = f"Analysis failed for {log_type}: {str(e)}"
            logging.error(error_msg)
            return {
                "success": False,
                "log_type": log_type,
                "error": error_msg
            }
        finally:
            # Clean up temporary file
            if temp_file and os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                    logging.info(f"Temporary file removed: {temp_file}")
                except Exception as e:
                    logging.warning(f"Failed to remove temporary file {temp_file}: {str(e)}")

def get_file_content_from_db(log_id: int) -> str:
    """Retrieve file content from database"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor(dictionary=True)
        
        query = "SELECT filedata FROM UploadLogs WHERE id = %s"
        cursor.execute(query, (log_id,))
        result = cursor.fetchone()
        
        if not result:
            raise Exception(f"No log file found with ID: {log_id}")
        
        # Validate base64 content
        filedata = result['filedata']
        logging.info(f"Retrieved base64 data length: {len(filedata)}")
        logging.debug(f"First 100 chars of retrieved data: {filedata[:100]}")
            
        return filedata
        
    except Error as e:
        raise Exception(f"Database error: {str(e)}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()


def display_base64_image(base64_string):
    try:
        # Remove the data URI prefix if present
        if ',' in base64_string:
            base64_string = base64_string.split(',')[1]
        
        # Decode base64 string to bytes
        image_bytes = base64.b64decode(base64_string)
        
        # Create an image object from bytes
        image = Image.open(io.BytesIO(image_bytes))
        
        # Display the image
        # image.show()
        
        # Optional: print image details
        print(f"Image size: {image.size}")
        print(f"Image format: {image.format}")
        
    except Exception as e:
        print(f"Error displaying image: {str(e)}")


def main():
    """Main entry point for the script"""
    try:
        if len(sys.argv) != 3:
            error_msg = "Required arguments: log_type log_id"
            logging.error(error_msg)
            print(json.dumps({"success": False, "error": error_msg}))
            sys.exit(1)

        # Get arguments passed from PHP
        log_type = sys.argv[1].strip('"\'')
        log_id = int(sys.argv[2].strip('"\''))
        
        logging.info(f"Received request to analyze {log_type} logs with ID: {log_id}")
        
        # Retrieve file content from database
        try:
            file_data = get_file_content_from_db(log_id)
        except Exception as e:
            raise Exception(f"Failed to retrieve file content: {str(e)}")
        
        # Initialize analyzer and process logs
        analyzer = LogAnalyzerMaster()
        results = analyzer.analyze_logs(log_type, file_data)
        
        # Return results as JSON
        if("results" not in results):
            raise Exception("Analysis failed: No results returned")
        
        print("Keys in results:", list(results["results"].keys()))
        display_base64_image(results["results"]["graph_data"])
        print(json.dumps(results, ensure_ascii=False))
        sys.exit(0 if results["success"] else 1)
        
    except Exception as e:
        error_msg = f"Analysis failed: {str(e)}"
        logging.error(error_msg)
        print(json.dumps({
            "success": False,
            "error": error_msg
        }))
        sys.exit(1)

if __name__ == "__main__":
    main()