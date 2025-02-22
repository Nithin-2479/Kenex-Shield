<?php
ini_set('max_execution_time', 60); // Set to 1 minute
ini_set('display_errors', 1);
error_reporting(E_ALL);
session_start();
include 'database.php';

define('DB_HOST', 'localhost');
define('DB_USER', 'Shield_db');
define('DB_PASS', 'Shield_db');
define('DB_NAME', 'Shield_db');

if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_plan'])) {
    header("Location: login.php");
    exit();
}

// Plan configurations
$planLimits = [
    'Essential' => 3,
    'Professional' => 5,
    'Enterprise' => 8
];

$logTypes = [
    "Firewall Logs" => "Firewall Logs",
    "DNS Query Logs" => "DNS Query Logs",
    "User Activity Logs" => "User Activity Logs",
    "Network Traffic Logs" => "Network Traffic Logs",
    "Email Security Logs" => "Email Security Logs",
    "Application Logs" => "Application Logs",
    "Endpoint Security Logs" => "Endpoint Security Logs",
    "SIEM Systems Aggregated Logs" => "SIEM Systems Aggregated Logs"
];
error_reporting(E_ALL);
ini_set('display_errors', 1);
// Validate user plan and log upload limits
$userPlan = $_SESSION['user_plan'];
$maxLogs = $planLimits[$userPlan] ?? 3;

// Add debug logging
error_log("User Plan: " . $userPlan);
error_log("Max Logs: " . $maxLogs);

// Ensure proper case for plan names
$userPlan = ucfirst(strtolower($userPlan));

// Validate the plan and set the correct number of logs
if (!isset($planLimits[$userPlan])) {
    error_log("Invalid plan detected: " . $userPlan);
    // If plan is not recognized, default to Essential
    $userPlan = 'Essential';
    $maxLogs = $planLimits['Essential'];
} else {
    $maxLogs = $planLimits[$userPlan];
    error_log("Plan recognized: " . $userPlan . " with " . $maxLogs . " logs");
}
// Add helper functions
// function encodeFileData($data) {
//     return base64_encode($data);
// }

// Modify the handleFileUpload function
function handleFileUpload($file, $logType)
{

    error_log("handleFileUpload called with logType: " . $logType);
    // error_log("This is the file contents: " . $file['tmp_name']);

    try {
        // Validate file first
        if (!isset($file) || !is_array($file)) {
            throw new Exception('No file uploaded');
        }

        if ($file['error'] !== UPLOAD_ERR_OK) {
            $errors = [
                UPLOAD_ERR_INI_SIZE => 'File exceeds INI size limit',
                UPLOAD_ERR_FORM_SIZE => 'File exceeds form size limit',
                UPLOAD_ERR_PARTIAL => 'Partial upload',
                UPLOAD_ERR_NO_FILE => 'No file uploaded',
                UPLOAD_ERR_NO_TMP_DIR => 'No temporary directory',
                UPLOAD_ERR_CANT_WRITE => 'Cannot write to disk',
                UPLOAD_ERR_EXTENSION => 'PHP extension blocked upload',
            ];
            throw new Exception($errors[$file['error']] ?? 'Unknown upload error');
        }

        error_log("Handle File Upload: File is valid");

        // Read and validate file content
        $fileContent = @file_get_contents($file['tmp_name']);
        if ($fileContent === false) {
            throw new Exception('Failed to read uploaded file: ' . error_get_last()['message']);
        }

        error_log("Handle File Upload: These are file contents: " . $fileContent);

        // Convert file content to base64
        // $base64Content = encodeFileData($fileContent);
        // error_log("File encoded to base64");

        // Database connection with proper error handling
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed: ' . $conn->connect_error);
        }

        try {
            $conn->begin_transaction();

            $stmt = $conn->prepare("INSERT INTO UploadLogs (UserID, LogType, filename, filedata,TimeStamps) VALUES (?, ?, ?, ?, NOW())");
            if (!$stmt) {
                throw new Exception('Prepare failed: ' . $conn->error);
            }

            $userId = $_SESSION['user_id'];
            $fileName = $file['name'];

            $stmt->bind_param("isss", $userId, $logType, $fileName, $fileContent);

            if (!$stmt->execute()) {
                throw new Exception('Execute failed: ' . $stmt->error);
            }

            $logId = $conn->insert_id;
            $conn->commit();

            $stmt->close();
            $conn->close();

            return [
                'success' => true,
                'message' => 'File uploaded successfully',
                'logId' => $logId
            ];

        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }

    } catch (Exception $e) {
        error_log('Upload error details: ' . $e->getMessage());
        return [
            'success' => false,
            'message' => $e->getMessage(),
            'debug' => DEBUG ? $e->getTraceAsString() : null
        ];
    }
}

// Modify the analyze function to pass base64 data directly
function analyzeLogFile($logId, $logType) {
    // Execute Python script with log type and log ID
    $pythonScript = dirname(__FILE__) . '\script1\master.py';
    error_log("Calling master Python script path: " . $pythonScript);
    
    // Escape the arguments for command line
    $escapedLogType = escapeshellarg($logType);
    $escapedLogId = escapeshellarg($logId);

    error_log("Escaped log type: " . $escapedLogType);
    error_log("Escaped log ID: " . $escapedLogId);
    
    // Build command with just log type and log ID
    $command = "python \"$pythonScript\" $escapedLogType $escapedLogId";

    error_log("Executing command: " . $command);
    
    $output = [];
    $returnVar = 0;

    exec($command, $output, $returnVar);

    error_log("Command output: " . print_r($output, true));
    error_log("Command return value: " . $returnVar);

    // Process Python script output
    $analysisResults = [];
    if ($output && count($output) > 0) {
        try {
            $analysisResults = json_decode($output[3], true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                error_log("JSON decode error: " . json_last_error_msg());
                return ['success' => false, 'message' => 'Invalid analysis results format'];
            }
            // place data into database
            $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
            if ($conn->connect_error) {
                throw new Exception('Database connection failed: ' . $conn->connect_error);
            }
    
            try{
                $conn->begin_transaction();
    
                $stmt = $conn->prepare("INSERT INTO log_analysis (LogID, Total_logs, Malicious_Events, GraphData, Alert_level, Source_Ip, Log_Type) VALUES (?, ?, ?, ?, ?, ?, ?)");
                if (!$stmt) {
                    throw new Exception('Prepare failed: ' . $conn->error);
                }

                // Add this validation before binding parameters
                if (!isset($analysisResults["results"]["total_logs"]) ||
                !isset($analysisResults["results"]["malicious_events"]) ||
                !isset($analysisResults["results"]["graph_data"]) ||
                !isset($analysisResults["results"]["alert_level"]) ||
                !isset($analysisResults["results"]["sourceIp"]) ||
                !isset($analysisResults["results"]["log_type"])) {
                throw new Exception('Missing required analysis results fields');
}
    
            
                $totalLogs = $analysisResults["results"]["total_logs"];
                $maliciousEvents = $analysisResults["results"]["malicious_events"];
                $graphData = $analysisResults["results"]["graph_data"];
                $alertLevel = $analysisResults["results"]["alert_level"];
                $sourceIp = $analysisResults["results"]["sourceIp"];
                $logType = $analysisResults["results"]["log_type"];
    
                $stmt->bind_param("iiissss", $logId, $totalLogs, $maliciousEvents, $graphData, $alertLevel, $sourceIp, $logType);
    
                if (!$stmt->execute()) {
                    throw new Exception('Execute failed: ' . $stmt->error);
                }
    
                // Store the ID of the newly inserted row
                // This will be used to retrieve the analysis results later
                $analysisId = $conn->insert_id;
                $conn->commit();
    
                $stmt->close();
                $conn->close();
                
            return [
                'success' => true,
                'message' => 'File Analysis complete',
                'analysisId' => $analysisId
            ];

        } catch (Exception $e) {
            $conn->rollback();
            throw $e;
        }



        } catch (Exception $e) {
            error_log("Error parsing analysis results: " . $e->getMessage());
            return ['success' => false, 'message' => 'Failed to parse analysis results'];
        }
    }

    return [
        'success' => $returnVar === 0,
        'message' => '😒',
        'results' => $analysisResults
    ];
}

// Function to retrieve analysis results

function getAnalysisResults($logId) {
    try {
        // Add debug logging
        error_log("Starting getAnalysisResults for LogID: " . $logId);
        
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed: ' . $conn->connect_error);
        }

        // Query using LogID
        $stmt = $conn->prepare("SELECT * FROM log_analysis WHERE LogID = ?");
        if (!$stmt) {
            throw new Exception('Prepare failed: ' . $conn->error);
        }

        $stmt->bind_param("i", $logId);
        
        if (!$stmt->execute()) {
            throw new Exception('Execute failed: ' . $stmt->error);
        }

        $result = $stmt->get_result();
        
        // Check if we got results
        if ($result->num_rows === 0) {
            throw new Exception("No analysis results found for LogID: {$logId}");
        }
        
        $analysis = $result->fetch_assoc();
        
        // Log what we found
        error_log("Found analysis result: " . json_encode($analysis));

        // Format the response
        $response = [
            'success' => true,
            'results' => [
                'total_logs' => (int)$analysis['Total_logs'],
                'malicious_events' => (int)$analysis['Malicious_Events'],
                'graph_data' => $analysis['GraphData'],
                'alert_level' => $analysis['Alert_level'],
                'sourceIp' => $analysis['Source_Ip'],
                'log_type' => $analysis['Log_Type']
            ]
        ];

        return $response;
    } catch (Exception $e) {
        error_log("Error in getAnalysisResults: " . $e->getMessage());
        return [
            'success' => false,
            'message' => $e->getMessage()
        ];
    } finally {
        if (isset($stmt)) {
            $stmt->close();
        }
        if (isset($conn)) {
            $conn->close();
        }
    }
}

// Modify the request handler to handle both upload and analyze requests
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    header('Content-Type: application/json');
    
    // Handle JSON input for analysis
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (isset($_FILES['logFile'])) {
        // Handle file upload
        if (!isset($_POST['logType']) || empty($_POST['logType'])) {
            echo json_encode([
                'success' => false,
                'message' => 'Log type not specified'
            ]);
            exit;
        }
        
        $result = handleFileUpload($_FILES['logFile'], $_POST['logType']);
        echo json_encode($result);
        exit;
    } 
    else if (isset($input['analyze']) && isset($input['logId']) && isset($input['logType'])) {
        // Handle analysis request from JSON body
        error_log("Analyze request received for logId: " . $input['logId'] . " and logType: " . $input['logType']);
        $result = analyzeLogFile($input['logId'], $input['logType']);
        echo json_encode($result);
        exit;
    }
    else if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['logid'])) {
        // Handle analysis results retrieval
        header('Content-Type: application/json');
        $result = getAnalysisResults($_GET['logid']);
        echo json_encode($result);
        exit;
    }
}
// At the beginning of your PHP script, before the HTML
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['logid'])) {
    // Explicitly set content type
    header('Content-Type: application/json');
    
    // Add debug logging
    error_log("Analysis results request received for logid: " . $_GET['logid']);
    
    try {
        $result = getAnalysisResults($_GET['logid']);
        echo json_encode($result);
    } catch (Exception $e) {
        echo json_encode([
            'success' => false,
            'message' => $e->getMessage()
        ]);
    }
    exit; // Important: prevent the rest of the page from executing
}

?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Log Analysis Dashboard</title>
    <style>
        :root {
            --primary-color: #ff6b01;
            --dark-bg: #2d2d2d;
            --light-gray: #e0e0e0;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
        }

        header {
            background-color: white;
            padding: 1rem;
            border-bottom: 2px solid var(--primary-color);
            display: grid;
            grid-template-columns: auto 1fr auto;
            align-items: center;
            gap: 1rem;
        }

        .logo {
            height: 80px;
            margin: 0 auto;
        }

        .header-left {
            justify-self: start;
        }

        .header-right {
            justify-self: end;
        }

        .subscription-status {
            padding: 0.5rem 1rem;
            background-color: var(--primary-color);
            color: white;
            border-radius: 4px;
        }

        .container {
            display: flex;
            min-height: calc(100vh - 70px);
        }

        .sidebar {
            width: 450px;
            background-color: var(--dark-bg);
            padding: 1rem;
            color: white;
        }

        .log-types {
            display: flex;
            flex-direction: column;
            gap: 1rem;
            margin: 1rem 0;
        }

        .log-type-item {
            background-color: white;
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 8px;
            display: flex;
            flex-direction: column;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .log-type-item:hover {
            transform: translateY(-2px);
            transition: transform 0.2s ease;
        }

        .log-type-item input[type="checkbox"] {
            margin-right: 10px;
        }

        .log-type-item label {
            cursor: pointer;
            color: #333;
        }

        .log-type-item label.disabled {
            color: #999;
            cursor: not-allowed;
        }

        .log-type-item.disabled {
            background-color: #f5f5f5;
            opacity: 0.8;
        }

        .premium-badge {
            background-color: var(--primary-color);
            color: white;
            font-size: 0.6rem;
            padding: 2px 4px;
            border-radius: 2px;
            margin-left: 5px;
        }

        #selectedLogTypeDisplay {
            margin-bottom: 10px;
            padding: 8px;
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }

        .upgrade-tooltip {
            display: none;
            position: absolute;
            background: #333;
            color: white;
            padding: 5px 10px;
            border-radius: 4px;
            font-size: 12px;
            z-index: 100;
        }

        .main-content {
            flex: 1;
            padding: 1rem;
        }

        .stats-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .stat-box {
            background-color: white;
            padding: 1rem;
            border-radius: 4px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }

        .graph-container {
            background-color: white;
            padding: 1rem;
            border-radius: 4px;
            margin-bottom: 1rem;
            height: 400px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th,
        td {
            padding: 0.8rem;
            text-align: left;
            border-bottom: 1px solid var(--light-gray);
        }

        .upload-section {
            margin-top: 1rem;
            padding: 1rem;
            background-color: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }

        #uploadBtn {
            width: 100%;
            padding: 0.8rem;
            margin-top: 0.5rem;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .log-btn.active {
            background-color: var(--primary-color);
            color: white;
        }

        .user-controls {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .logout-btn {
            padding: 1rem 2rem;
            /* Increased padding */
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        .logout-btn:hover {
            background-color: #bb2d3b;
        }

        .logout-form {
            margin: 0;
        }

        .view-btn {
            margin-left: auto;
            padding: 5px 10px;
            background-color: var(--primary-color);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .view-btn:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

        .logs-viewer {
            display: none;
            margin-top: 1rem;
            padding: 1rem;
            background-color: white;
            border-radius: 4px;
            max-height: 300px;
            overflow-y: auto;
        }

        .logs-viewer.active {
            display: block;
        }

        .button-group {
            margin-left: auto;
            display: flex;
            gap: 5px;
        }

        .analyze-btn {
            padding: 5px 10px;
            background-color: #4CAF50;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .analyze-btn:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

        .back-btn {
            padding: 1rem 2rem;
            /* Increased padding */
            background-color: #4a4a4a;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
            text-decoration: none;
            display: inline-block;
            margin-right: 1rem;
        }

        .back-btn:hover {
            background-color: var(--primary-color);
            /* Changes to orange (#ff6b01) on hover */
        }

        .log-type-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 10px;
        }

        .upload-controls {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #eee;
        }

        .upload-form {
            display: flex;
            flex-direction: column;
            gap: 10px;
            background-color: rgb(231, 72, 9);
        }

        .file-input {
            width: 100%;
        }

        .upload-status {
            margin-top: 5px;
            padding: 5px;
            border-radius: 4px;
            font-size: 0.9em;
        }

        .upload-status.success {
            background-color: #d4edda;
            color: #155724;
        }

        .upload-status.error {
            background-color: #f8d7da;
            color: #721c24;
        }
        .canvas-card {
            background-color: white;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: center;
            align-items: center;
        }

        #analysisCanvas {
            width: 100%;
            height: 600px;
            border-radius: 4px;
        }
    </style>
</head>

<body>
    <header>
        <div class="header-left">
            <a href="dashboard.php" class="back-btn">← Back to Dashboard</a>
        </div>
        <img src="Logo.png" alt="KeneXoft Technologies" class="logo">
        <div class="header-right user-controls">
            <div class="subscription-status">
                <span id="subscriptionBadge"><?php echo htmlspecialchars($userPlan); ?> Plan </span>
            </div>
            <form method="POST" action="logout.php" class="logout-form">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
    </header>

    <div class="container">
        <div class="sidebar">
            <div class="log-types">
                <?php
                $accessibleLogTypes = array_slice(array_keys($logTypes), 0, $maxLogs);
                $lockedLogTypes = array_slice(array_keys($logTypes), $maxLogs);

                foreach ($logTypes as $typeKey => $typeName):
                    $isDisabled = in_array($typeKey, $lockedLogTypes);
                    ?>
                    <div class="log-type-item">
                        <div class="log-type-header">
                            <input type="radio" id="<?php echo $typeKey; ?>" name="logTypeRadio"
                                value="<?php echo $typeKey; ?>" <?php echo $isDisabled ? 'disabled' : ''; ?>>
                            <label for="<?php echo $typeKey; ?>" class="<?php echo $isDisabled ? 'disabled' : ''; ?>">
                                <?php echo $typeName; ?>
                                <?php if ($isDisabled): ?>
                                    <span class="premium-badge">Premium</span>
                                <?php endif; ?>
                            </label>
                        </div>

                        <div class="upload-controls" style="display: none;">
                            <form class="upload-form" method="POST" enctype="multipart/form-data">
                                <input type="file" name="logFile" accept=".log,.txt,.csv,.arff" class="file-input">
                                <input type="hidden" name="logType" value="<?php echo $typeKey; ?>">
                                <div class="button-group">
                                    <button type="submit" class="upload-btn" disabled>Upload</button>
                                    <button type="button" class="analyze-btn" disabled>Analyze</button>
                                    <button type="button" class="view-btn" disabled>View</button>
                                </div>
                                <div class="upload-status"></div>
                            </form>
                        </div>
                    </div>
                <?php endforeach; ?>
            </div>
        </div>

        <div class="main-content">
            <div class="stats-container">
                <div class="stat-box">
                    <h4>Total Logs</h4>
                    <span id="totalLogs">0</span>
                </div>
                <div class="stat-box">
                    <h4>Malicious Events</h4>
                    <span id="maliciousEvents">0</span>
                </div>
                <div class="stat-box">
                    <h4>Alert Level</h4>
                    <span id="alertLevel">Low</span>
                </div>
            </div>

            <div class="canvas-card">
                <canvas id="analysisCanvas"></canvas>
            </div>

            <div class="stats-container">
                <div class="stat-box">
                    <h4>Source IP</h4>
                    <span id="sourceIp">N/A</span>
                </div>
                <div class="stat-box">
                    <h4>Log Type</h4>
                    <span id="logType">N/A</span>
                </div>
            </div>
        </div>
    </div>

    <script>


document.addEventListener("DOMContentLoaded", function () {
            const logTypes = document.querySelectorAll('.log-type-item');

            // Hide all upload controls initially
            document.querySelectorAll('.upload-controls').forEach(control => {
                control.style.display = 'none';
            });
    logTypes.forEach(logType => {
        const radio = logType.querySelector('input[type="radio"]');
        const uploadControls = logType.querySelector('.upload-controls');
        const uploadForm = logType.querySelector('.upload-form');
        const fileInput = uploadForm?.querySelector('.file-input');
        const uploadBtn = uploadForm?.querySelector('.upload-btn');
        const analyzeBtn = uploadForm?.querySelector('.analyze-btn');
        const viewBtn = uploadForm?.querySelector('.view-btn');
        const statusDiv = uploadForm?.querySelector('.upload-status');

        // Handle radio change
        radio?.addEventListener('change', function () {
            document.querySelectorAll('.upload-controls').forEach(control => {
                control.style.display = 'none';
            });
            if (this.checked) {
                uploadControls.style.display = 'block';
            }
        });

        // Enable upload button when file is selected
        fileInput?.addEventListener('change', function () {
            uploadBtn.disabled = !this.files.length;
        });

        // Handle form submission for upload
        uploadForm?.addEventListener('submit', async function (e) {
            e.preventDefault();
            if (!fileInput.files.length) return;

            try {
                uploadBtn.disabled = true;
                statusDiv.textContent = 'Uploading...';
                
                const formData = new FormData();
                formData.append('logFile', fileInput.files[0]);
                formData.append('logType', this.querySelector('input[name="logType"]').value);

                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();
                
                if (result.success) {
                    statusDiv.textContent = result.message;
                    statusDiv.className = 'upload-status success';
                    analyzeBtn.disabled = false;
                    viewBtn.disabled = false;
                    analyzeBtn.dataset.logId = result.logId;
                } else {
                    throw new Error(result.message || 'Upload failed');
                }
            } catch (error) {
                console.error('Upload error:', error);
                statusDiv.textContent = 'Upload failed: ' + error.message;
                statusDiv.className = 'upload-status error';
            } finally {
                uploadBtn.disabled = false;
            }
        });

        // Handle analyze button click
        analyzeBtn?.addEventListener('click', async function () {
            console.log("Analyze button is clicked!!")
            const logId = this.dataset.logId;
            const logType = uploadForm.querySelector('input[name="logType"]').value;
            
            if (!logId) {
                alert('No log file selected for analysis');
                return;
            }

            try {
                this.disabled = true;
                statusDiv.textContent = 'Analyzing...';
                
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        analyze: true,
                        logId: logId,
                        logType: logType
                    })
                });

                const result = await response.json();
                
                if (result.success) {
                    statusDiv.textContent = 'Analysis complete';
                    statusDiv.className = 'upload-status success';
                    updateAnalysisResults(result.results);
                    viewBtn.dataset.analysisId = result.analysisId;
                } else {
                    throw new Error(result.message || 'Analysis failed');
                }
            } catch (error) {
                console.error('Analysis error:', error);
                statusDiv.textContent = 'Analysis failed: ' + error.message;
                statusDiv.className = 'upload-status error';
            } finally {
                this.disabled = false;
            }
        });
        // Update the view button click handler
        viewBtn?.addEventListener('click', async function() {
            console.log("View button is clicked!!")
            // Get logId from the analyze button instead of analysisId
            const logId = analyzeBtn.dataset.logId;
            if (!logId) {
                alert('No analysis results available. Please analyze the file first.');
                return;
            }

            try {
                this.disabled = true;
                statusDiv.textContent = 'Loading analysis results...';

                // const response = await fetch(`${window.location.href}?logid=${logId}`);
                // if (!response.ok) {
                //     throw new Error('Failed to fetch analysis results');
                // }
                const baseUrl = window.location.pathname; // Gets just the path part (upload.php)
                    const response = await fetch(`${baseUrl}?logid=${logId}`);
                    
                    if (!response.ok) {
                        throw new Error(`Server error: ${response.status}`);
                    }

                const contentType = response.headers.get('content-type');
                if (!contentType || !contentType.includes('application/json')) {
                    throw new Error('Server returned non-JSON response');
                }

                const data = await response.json();
                if (data.success) {
                    updateAnalysisResults(data);
                    statusDiv.textContent = 'Analysis results loaded';
                    statusDiv.className = 'upload-status success';
                } else {
                    throw new Error(data.message || 'Failed to load analysis results');
                }
            } catch (error) {
                console.error('View error:', error);
                statusDiv.textContent = 'Failed to load analysis: ' + error.message;
                statusDiv.className = 'upload-status error';
            } finally {
                this.disabled = false;
            }
        });
    });
});

// Add helper function to update analysis results
function updateAnalysisResults(results) {
    if (!results || !results.results) return;
    
    const data = results.results || results;
    
    // Update statistics
    document.getElementById('totalLogs').textContent = (data.total_logs || data.results.total_logs || '0');
    document.getElementById('maliciousEvents').textContent = (data.malicious_events ||data.results.malicious_events || '0');
    document.getElementById('alertLevel').textContent = (data.alert_level ||data.results.alert_level || 'Low');
    document.querySelector('#sourceIp').textContent = (data.sourceIp ||data.results.sourceIp || 'N/A');
    document.querySelector('#logType').textContent = (data.log_type || data.results.log_type || 'N/A');

    // Display the graph
    if (data.graph_data) {
        const img = new Image();
        img.onload = function() {
            const canvas = document.getElementById('analysisCanvas');
            const ctx = canvas.getContext('2d');
            
            // Set canvas dimensions to match image while maintaining aspect ratio
            const containerWidth = canvas.parentElement.offsetWidth;
            const scale = containerWidth / img.width;
            canvas.width = containerWidth;
            canvas.height = img.height * scale;
            
            // Draw image on canvas
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        };
        img.src = 'data:image/png;base64,' + data.graph_data;
    }
}

    </script>
</body>

</html>