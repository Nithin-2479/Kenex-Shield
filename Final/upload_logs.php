<?php
session_start();


// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'Shield_db');
define('DB_PASS', 'Shield_db');
define('DB_NAME', 'Shield_db');
define('ENCRYPTION_KEY', 'AES-256-CBC');

// Plan configurations
$planLimits = [
    'Essential' => 3,
    'Professional' => 5,
    'Enterprise' => 8
];

$logTypes = [
    "Firewall Logs",
    "DNS Query Logs",
    "User Activity Logs",
    "Network Traffic Logs",
    "Email Security Logs",
    "Application Logs",
    "Endpoint Security Logs",
    "SIEM Systems Aggregated Logs"
];

// Debug information
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Verify user plan
$userPlan = $_SESSION['user_plan'];
$maxLogs = $planLimits[$userPlan] ?? 3; // Default to Essential if plan not found

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

// Rest of your helper functions remain the same
function compressData($data) {
    return gzcompress($data);
}

function encryptData($data) {
    $ivlen = openssl_cipher_iv_length($cipher = "AES-256-CBC");
    $iv = openssl_random_pseudo_bytes($ivlen);
    $encrypted = openssl_encrypt($data, $cipher, ENCRYPTION_KEY, OPENSSL_RAW_DATA, $iv);
    return base64_encode($iv . $encrypted);
}

function handleFileUpload($file, $logType) {
    try {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            throw new Exception('File upload failed');
        }

        if (pathinfo($file['name'], PATHINFO_EXTENSION) != 'csv') {
            throw new Exception('Only CSV files are allowed');
        }

        $fileContent = file_get_contents($file['tmp_name']);
        $compressedContent = compressData($fileContent);
        $encryptedContent = encryptData($compressedContent);

        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed');
        }

        $stmt = $conn->prepare("INSERT INTO UploadLogs (UserID, LogType, filedata) VALUES (?, ?, ?)");
        $userId = $_SESSION['user_id'];
        $stmt->bind_param("iss", $userId, $logType, $encryptedContent);
        
        if (!$stmt->execute()) {
            throw new Exception('Failed to save to database');
        }

        $stmt->close();
        $conn->close();
        
        return ['success' => true, 'message' => 'File uploaded successfully'];

    } catch (Exception $e) {
        return ['success' => false, 'message' => $e->getMessage()];
    }
}

// Handle file upload requests
$response = ['success' => false, 'message' => ''];
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_FILES['logFile'])) {
    $logType = $_POST['logType'] ?? '';
    if (!empty($logType)) {
        $result = handleFileUpload($_FILES['logFile'], $logType);
        $response = $result;
    }
    // Send JSON response for AJAX requests
    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Logs - <?php echo htmlspecialchars($userPlan); ?> Plan</title>
    <style>
        /* Previous styles remain the same */
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f9f9f9;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
            color: #000;
            overflow-y: auto;
        }

        .upload-container {
            background-color: #fff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.3);
            width: 100%;
            max-width: 700px;
            text-align: center;
            max-height: 90vh;
            overflow-y: auto;
        }
        .upload-container h2 {
            margin-bottom: 20px;
            color: #E5450B;
            font-size: 20px;
            align-items: center;
        }
        


        .feature-row {
            border: 1px solid #ddd;
            margin: 10px 0;
            padding: 15px;
            border-radius: 5px;
        }

        .feature-row.disabled {
            background-color: #f5f5f5;
            opacity: 0.7;
        }

        /* New styles for checkbox and file upload */
        .log-checkbox-label {
            display: flex;
            align-items: center;
            cursor: pointer;
        }

        .log-checkbox {
            margin-right: 10px;
            cursor: pointer;
        }

        .file-upload-section {
            margin-left: 25px;
            margin-top: 10px;
            display: none; /* Hidden by default */
        }

        .file-upload-section.visible {
            display: block;
        }

        .feature-details {
            margin-top: 15px;
        }

        .upload-status {
            margin-top: 10px;
            padding: 10px;
            border-radius: 5px;
        }

        .success { background-color: #d4edda; color: #155724; }
        .error { background-color: #f8d7da; color: #721c24; }

        .btn-upload {
            background-color: #E5450B;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            margin-top: 10px;
        }

        .btn-upload:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

        .plan-info {
            margin-bottom: 20px;
            padding: 10px;
            background-color: #e9ecef;
            border-radius: 5px;
        }

        .upgrade-message {
            color: #856404;
            background-color: #fff3cd;
            padding: 10px;
            border-radius: 5px;
            margin-top: 5px;
            font-size: 0.9em;
        }

        .checkbox-container {
            display: flex;
            align-items: center;
            margin-bottom: 10px;
        }
        .actions {
            display: flex;
            justify-content: space-between;
            margin-top: 20px;
        }

        .actions button {
            width: 48%;
            padding: 10px;
            border: none;
            border-radius: 5px;
            font-size: 14px;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }

        .actions .secondary {
            background-color: #F0F0F0;
            color: #333;
        }

        .actions .secondary:hover {
            background-color: #E0E0E0;
        }

        .actions .primary {
            background-color: #f65634;
            color: white;
        }

        .actions .primary:hover {
            background-color: #f5350c;
        }

        .actions .primary:disabled {
            background-color: #ccc;
            cursor: not-allowed;
        }

    </style>
</head>
<body>
    <div class="upload-container">
        <h2><?php echo htmlspecialchars($userPlan); ?> Plan - Upload Logs</h2>
        
        <div class="plan-info">
            Available Log Types: <?php echo $maxLogs; ?> of <?php echo count($logTypes); ?>
        </div>
        
        <div id="features-container">
            <?php foreach ($logTypes as $index => $logType): ?>
                <div class="feature-row <?php echo ($index >= $maxLogs) ? 'disabled' : ''; ?>">
                    <div class="checkbox-container">
                        <input 
                            type="checkbox" 
                            id="checkbox-<?php echo $index; ?>" 
                            class="log-checkbox" 
                            <?php echo ($index >= $maxLogs) ? 'disabled' : ''; ?>
                            data-log-type="<?php echo htmlspecialchars($logType); ?>"
                        >
                        <label for="checkbox-<?php echo $index; ?>" class="log-checkbox-label">
                            <?php echo htmlspecialchars($logType); ?>
                        </label>
                    </div>
                    
                    <div class="file-upload-section" id="upload-section-<?php echo $index; ?>">
                        <form class="upload-form" data-log-type="<?php echo htmlspecialchars($logType); ?>">
                            <input type="file" name="logFile" accept=".csv" <?php echo ($index >= $maxLogs) ? 'disabled' : ''; ?> required>
                            <button type="submit" class="btn-upload" <?php echo ($index >= $maxLogs) ? 'disabled' : ''; ?>>Upload</button>
                            <div class="upload-status"></div>
                        </form>
                    </div>
                    
                    <?php if ($index >= $maxLogs): ?>
                        <div class="upgrade-message">
                            Upgrade your plan to unlock this log type
                        </div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
        <div class="actions">
            <button class="secondary" href="dashboard.php"> Back</button>
            <button class="primary">Next</button>
        </div>

    </div>
        <script>
    document.addEventListener('DOMContentLoaded', function() {
        // Handle checkbox changes
        document.querySelectorAll('.log-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', function() {
                const index = this.id.split('-')[1];
                const uploadSection = document.getElementById(`upload-section-${index}`);
                
                if (this.checked) {
                    uploadSection.classList.add('visible');
                } else {
                    uploadSection.classList.remove('visible');
                }
            });
        });

        // Handle form submissions
        document.querySelectorAll('.upload-form').forEach(form => {
            const isDisabled = form.closest('.feature-row').classList.contains('disabled');
            
            if (!isDisabled) {
                form.addEventListener('submit', async (e) => {
                    e.preventDefault();
                    const formData = new FormData();
                    const file = form.querySelector('input[type="file"]').files[0];
                    const logType = form.dataset.logType;
                    const statusDiv = form.querySelector('.upload-status');
                    const submitButton = form.querySelector('.btn-upload');

                    // Disable the submit button while uploading
                    submitButton.disabled = true;
                    
                    formData.append('logFile', file);
                    formData.append('logType', logType);

                    try {
                        const response = await fetch(window.location.href, {
                            method: 'POST',
                            body: formData
                        });

                        const result = await response.json();
                        statusDiv.textContent = result.message;
                        statusDiv.className = 'upload-status ' + (result.success ? 'success' : 'error');
                        
                        if (result.success) {
                            form.reset();
                        }
                    } catch (error) {
                        statusDiv.textContent = 'Upload failed. Please try again.';
                        statusDiv.className = 'upload-status error';
                    } finally {
                        // Re-enable the submit button after upload completes
                        submitButton.disabled = false;
                    }
                });
            }
        });

        // Add support for multiple selections
        let selectedCount = 0;
        const maxSelections = <?php echo $maxLogs; ?>;

        document.querySelectorAll('.log-checkbox').forEach(checkbox => {
            checkbox.addEventListener('change', function() {
                if (this.checked) {
                    selectedCount++;
                    if (selectedCount > maxSelections) {
                        this.checked = false;
                        selectedCount--;
                        alert(`You can only select up to ${maxSelections} log types with your current plan.`);
                        return;
                    }
                } else {
                    selectedCount--;
                }
            });
        });
    });
    </script>
</body>
</html>