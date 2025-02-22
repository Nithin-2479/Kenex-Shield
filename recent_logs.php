<?php
session_start();
include 'database.php';

define('DB_HOST', 'localhost');
define('DB_USER', 'Shield_db');
define('DB_PASS', 'Shield_db');
define('DB_NAME', 'Shield_db');

// Check if user is logged in
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_plan'])) {
    header("Location: login.php");
    exit();
}

// Update storage limits based on plan (in bytes)
$storageLimits = [
    'ESSENTIAL' => 2147483648,     // 2GB
    'PROFESSIONAL' => 5368709120,  // 5GB
    'ENTERPRISE' => 10737418240    // 10GB
];

// Get user's plan and validate it
$userPlan = strtoupper($_SESSION['user_plan']);
if (!isset($storageLimits[$userPlan])) {
    error_log("Invalid plan detected: " . $userPlan);
    $userPlan = 'ESSENTIAL';
}

// Set storage limit based on plan
$storageLimit = $storageLimits[$userPlan];

// Unified function for analysis results
function getAnalysisResults($logId) {
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed');
        }

        $userId = $_SESSION['user_id'];
        
        // Get file info and analysis results in one query
        $stmt = $conn->prepare("
            SELECT 
                u.filename,
                u.filedata,
                u.LogType,
                COALESCE(a.Total_logs, 0) as total_logs,
                COALESCE(a.Malicious_Events, 0) as malicious_events,
                COALESCE(a.Alert_level, 'Low') as alert_level,
                COALESCE(a.Source_Ip, 'Unknown') as source_ip,
                COALESCE(a.GraphData, '') as graph_data
            FROM UploadLogs u
            LEFT JOIN log_analysis a ON u.ID = a.LogID
            WHERE u.ID = ? AND u.UserID = ?
        ");
        
        if (!$stmt) {
            throw new Exception('Query preparation failed: ' . $conn->error);
        }

        $stmt->bind_param("ii", $logId, $userId);
        
        if (!$stmt->execute()) {
            throw new Exception('Query execution failed: ' . $stmt->error);
        }

        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception("No data found for log ID: $logId");
        }
        
        $data = $result->fetch_assoc();
        
        return [
            'success' => true,
            'results' => [
                'filename' => $data['filename'],
                'total_logs' => (int)$data['total_logs'],
                'malicious_events' => (int)$data['malicious_events'],
                'alert_level' => $data['alert_level'],
                'sourceIp' => $data['source_ip'],
                'log_type' => $data['LogType'],
                'graph_data' => $data['graph_data']
            ]
        ];
    } catch (Exception $e) {
        error_log("Analysis error: " . $e->getMessage());
        return ['success' => false, 'message' => $e->getMessage()];
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
    }
}

// Handle file deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_file'])) {
    header('Content-Type: application/json');
    $fileId = intval($_POST['file_id']);
    $userId = $_SESSION['user_id'];
    
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed');
        }

        $conn->begin_transaction();

        // First delete from log_analysis if exists
        $stmt = $conn->prepare("DELETE FROM log_analysis WHERE LogID = ?");
        if ($stmt) {
            $stmt->bind_param("i", $fileId);
            $stmt->execute();
            $stmt->close();
        }

        // Then delete from UploadLogs
        $stmt = $conn->prepare("DELETE FROM UploadLogs WHERE ID = ? AND UserID = ?");
        if (!$stmt) {
            throw new Exception('Query preparation failed');
        }

        $stmt->bind_param("ii", $fileId, $userId);
        if (!$stmt->execute()) {
            throw new Exception('Delete failed');
        }

        if ($stmt->affected_rows === 0) {
            throw new Exception('File not found or access denied');
        }

        $conn->commit();
        
        // Get updated file list
        $userStorage = getUserStorageInfo($userId);
        
        echo json_encode([
            'success' => true,
            'files' => $userStorage['files']
        ]);
    } catch (Exception $e) {
        if (isset($conn)) $conn->rollback();
        echo json_encode([
            'success' => false,
            'error' => $e->getMessage()
        ]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
    }
    exit();
}

// Add this new endpoint for getting storage info
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['get_storage'])) {
    header('Content-Type: application/json');
    $userStorage = getUserStorageInfo($_SESSION['user_id']);
    $percentage = ($userStorage['storage_used'] / $userStorage['limit']) * 100;
    
    echo json_encode([
        'used' => $userStorage['storage_used'],
        'total' => $userStorage['limit'],
        'percentage' => round($percentage, 1),
        'plan' => $userStorage['plan'],
        'status' => $percentage >= 90 ? 'critical' : 
                    ($percentage >= 75 ? 'warning' : 'good')
    ]);
    exit();
}

// Add new endpoint for getting updated file list
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['get_files'])) {
    header('Content-Type: application/json');
    $userStorage = getUserStorageInfo($_SESSION['user_id']);
    echo json_encode(['files' => $userStorage['files']]);
    exit();
}

// Get user's storage info
function getUserStorageInfo($userId) {
    global $storageLimits, $userPlan;
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        return [
            'storage_used' => 0, 
            'files' => [],
            'plan' => $userPlan,
            'limit' => $storageLimits[$userPlan]
        ];
    }
    
    // Modified query to include plan information
    $stmt = $conn->prepare("
        SELECT 
            ul.ID, 
            ul.LogType, 
            ul.filename, 
            LENGTH(ul.filedata) as file_size, 
            ul.TimeStamps,
            (SELECT COALESCE(SUM(LENGTH(filedata)), 0) 
             FROM UploadLogs 
             WHERE UserID = ?) as total_size,
            u.plan
        FROM UploadLogs ul
        JOIN users u ON ul.UserID = u.id
        WHERE ul.UserID = ?
        ORDER BY ul.TimeStamps DESC 
        LIMIT 10
    ");
    
    if (!$stmt) {
        return [
            'storage_used' => 0, 
            'files' => [],
            'plan' => $userPlan,
            'limit' => $storageLimits[$userPlan]
        ];
    }
    
    $stmt->bind_param("ii", $userId, $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $files = [];
    $storage_used = 0;
    $userPlanFromDb = $userPlan; // default value
    
    while ($row = $result->fetch_assoc()) {
        $storage_used = $row['total_size'];
        $userPlanFromDb = strtoupper($row['plan']);
        unset($row['total_size'], $row['plan']);
        $files[] = $row;
    }
    
    $conn->close();
    
    // Validate and set storage limit based on plan from database
    $actualPlan = isset($storageLimits[$userPlanFromDb]) ? $userPlanFromDb : 'ESSENTIAL';
    $actualLimit = $storageLimits[$actualPlan];
    
    return [
        'storage_used' => $storage_used,
        'files' => $files,
        'plan' => $actualPlan,
        'limit' => $actualLimit
    ];
}

// Get user's current storage info
$userStorage = getUserStorageInfo($_SESSION['user_id']);
$storagePercentage = ($userStorage['storage_used'] / $userStorage['limit']) * 100;

// Handle analysis view request
if ($_SERVER["REQUEST_METHOD"] == "GET" && isset($_GET['view_analysis'])) {
    header('Content-Type: application/json');
    echo json_encode(getAnalysisResults(intval($_GET['view_analysis'])));
    exit();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recent Log Files - Shield</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        /* Base styles from upload.php */
        :root {
            --primary-color: #ff6b01;
            --dark-bg: #2d2d2d;
            --light-gray: #e0e0e0;
            --storage-color: #4caf50;
        }

        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }

        .storage-info {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .storage-bar {
            background: #e0e0e0;
            height: 20px;
            border-radius: 10px;
            margin: 10px 0;
            overflow: hidden;
        }

        .storage-used {
            background: var(--primary-color);
            height: 100%;
            transition: width 0.3s ease;
        }

        .storage-text {
            display: flex;
            justify-content: space-between;
            color: #666;
        }

        .files-table {
            width: 100%;
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--light-gray);
        }

        th {
            background-color: #f8f9fa;
            color: #333;
        }

        .delete-btn {
            background: #dc3545;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
        }

        .delete-btn:hover {
            background: #bb2d3b;
        }

        .alert {
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
        }

        .alert-warning {
            background-color: #fff3cd;
            color: #856404;
        }

        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
        }



        .search-bar {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .search-input {
            flex: 1;
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .filter-dropdown {
            padding: 0.5rem;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        .sort-header {
            cursor: pointer;
            user-select: none;
        }

        .sort-header:hover {
            background-color: #f0f0f0;
        }

        .sort-header i {
            margin-left: 5px;
            color: #999;
        }

        .file-row {
            transition: background-color 0.2s;
        }

        .file-row:hover {
            background-color: #f8f9fa;
        }

        .file-preview-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            width: 80%;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
        }

        .close-modal {
            position: absolute;
            top: 1rem;
            right: 1rem;
            color: white;
            font-size: 2rem;
            cursor: pointer;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        .fade-in {
            animation: fadeIn 0.3s ease-in;
        }

        /* Enhanced button styles */
        .action-btn {
            padding: 6px 12px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }

        .view-btn {
            background: var(--primary-color);
            color: white;
        }

        .view-btn:hover {
            background: #e65600;
        }

        /* Progress ring for storage indicator */
        .storage-ring {
            position: relative;
            width: 120px;
            height: 120px;
            margin: 1rem auto;
        }

        .storage-ring-circle {
            transform: rotate(-90deg);
            transform-origin: 50% 50%;
        }

        .storage-ring-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            font-size: 1rem;
        }

        header {
            background-color: white;
            padding: 1.5rem;
            border-bottom: 2px solid var(--primary-color);
            display: grid;
            grid-template-columns: auto 1fr auto;
            align-items: center;
            gap: 1rem;
            margin: 1rem;
            border-radius: 15px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .header-left {
            justify-self: start;
        }

        .header-right {
            justify-self: end;
            display: flex;
            gap: 1rem;
            align-items: center;
        }

        .subscription-status {
            padding: 0.5rem 1.5rem;
            background-color: var(--primary-color);
            color: white;
            border-radius: 25px;
            font-weight: 500;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .back-btn {
            padding: 0.8rem 1.5rem;
            background-color: #4a4a4a;
            color: white;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .back-btn:hover {
            background-color: var(--primary-color);
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }

        .logout-btn {
            padding: 0.8rem 1.5rem;
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 25px;
            cursor: pointer;
            transition: all 0.3s ease;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .logout-btn:hover {
            background-color: #bb2d3b;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.2);
        }

        .logo {
            height: 80px;
            margin: 0 auto;
            transition: transform 0.3s ease;
        }

        .logo:hover {
            transform: scale(1.05);
        }

        /* Updated container to account for header margin */
        .container {
            display: flex;
            min-height: calc(100vh - 140px);
            margin: 0 1rem;
        }

        /* New styles for recent logs page */
        .main-content {
            flex: 1;
            padding: 2rem;
            background-color: #f5f5f5;
        }

        .storage-section {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            margin: 0 auto 2rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            max-width: 800px;
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 2rem;
            align-items: center;
            border-top: 4px solid var(--primary-color);
        }

        .storage-details h2 {
            color: var(--dark-bg);
            margin-bottom: 1rem;
            font-size: 1.5rem;
        }

        /* Color coding for storage percentages */
        .storage-ring-circle {
            stroke: var(--storage-color, var(--primary-color));
            transition: stroke 0.3s ease;
        }

        .storage-ring-text {
            color: var(--storage-color, var(--primary-color));
            font-weight: bold;
            font-size: 1.2rem;
        }

        /* Storage usage color indicators */
        .storage-status {
            display: inline-block;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-weight: bold;
            margin-bottom: 1rem;
        }

        .storage-status.low {
            background-color: #e8f5e9;
            color: #2e7d32;
            --storage-color: #4caf50;
        }

        .storage-status.medium {
            background-color: #fff3e0;
            color: #f57c00;
            --storage-color: #ff9800;
        }

        .storage-status.high {
            background-color: #fdecea;
            color: #d32f2f;
            --storage-color: #f44336;
        }

        .storage-text {
            margin-top: 1rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 0.9rem;
        }

        .storage-text span {
            display: block;
            margin-bottom: 0.5rem;
            color: #666;
        }

        .storage-text span:last-child {
            margin-bottom: 0;
            font-weight: bold;
            color: var(--dark-bg);
        }

        .files-container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .subscription-status {
            padding: 0.5rem 1rem;
            background-color: var(--primary-color);
            color: white;
            border-radius: 4px;
        }

        .file-preview-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }

        .modal-content {
            background-color: white;
            padding: 2rem;
            border-radius: 8px;
            width: 80%;
            max-width: 800px;
            max-height: 80vh;
            margin: 50px auto;
            overflow-y: auto;
        }

        .close-modal {
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: #333;
        }

        .close-modal:hover {
            color: var(--primary-color);
        }

        #previewContent {
            white-space: pre-wrap;
            font-family: monospace;
            margin-top: 1rem;
        }

        #previewTitle {
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--primary-color);
        }
        .modal-header {
            position: relative;
            padding-bottom: 1rem;
            margin-bottom: 1rem;
            border-bottom: 2px solid var(--primary-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-content {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            width: 90%;
            max-width: 800px;
            max-height: 90vh;
            overflow-y: auto;
            position: relative;
        }

        .close-btn {
            position: absolute;
            top: 1rem;
            right: 1rem;
            padding: 0.5rem 1rem;
            background: #dc3545;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }

        .close-btn:hover {
            background-color: #bb2d3b;
        }

        .analysis-content {
            margin-top: 2rem;
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
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .canvas-card {
            background-color: white;
            border-radius: 8px;
            padding: 1rem;
            margin: 1rem 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            display: flex;
            justify-content: center;
            align-items: center;
        }

        #modalAnalysisCanvas {
            width: 100%;
            height: 400px;
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
                <span id="subscriptionBadge"><?php echo htmlspecialchars($userStorage['plan']); ?> PLAN</span>
            </div>
            <form method="POST" action="logout.php" class="logout-form">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
</header>

    <div class="container">
        <div class="main-content">
            <div class="storage-section">
                <div class="storage-ring">
                    <svg width="120" height="120" viewBox="0 0 120 120">
                        <circle cx="60" cy="60" r="54" fill="none" stroke="#e0e0e0" stroke-width="12"/>
                        <circle class="storage-ring-circle" cx="60" cy="60" r="54" 
                                fill="none" stroke-width="12" 
                                stroke-dasharray="339.292"
                                stroke-dashoffset="<?php echo (339.292 * (100 - $storagePercentage)) / 100; ?>"/>
                    </svg>
                    <div class="storage-ring-text">
                        <?php echo round($storagePercentage, 1); ?>%
                    </div>
                </div>
                <div class="storage-details">
                    <h2>Storage Usage</h2>
                    <?php
                    $statusClass = $storagePercentage >= 90 ? 'high' : 
                                  ($storagePercentage >= 75 ? 'medium' : 'low');
                    $statusText = $storagePercentage >= 90 ? 'Critical' : 
                                 ($storagePercentage >= 75 ? 'Warning' : 'Good');
                    ?>
                    <div class="storage-status <?php echo $statusClass; ?>">
                        Status: <?php echo $statusText; ?>
                    </div>
                    <div class="storage-text">
                        <?php if ($userStorage['storage_used'] >= 1073741824): ?>
                            <span>Used: <?php echo round($userStorage['storage_used'] / 1073741824, 2); ?> GB</span>
                        <?php else: ?>
                            <span>Used: <?php echo round($userStorage['storage_used'] / 1048576, 2); ?> MB</span>
                        <?php endif; ?>

                        <?php if ($userStorage['limit'] >= 1073741824): ?>
                            <span>Total: <?php echo round($userStorage['limit'] / 1073741824, 2); ?> GB</span>
                        <?php else: ?>
                            <span>Total: <?php echo round($userStorage['limit'] / 1048576, 2); ?> MB</span>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <div class="files-container">
                <div class="table-header">
                    <h2>Recent Files</h2>
                    <div class="search-bar">
                        <input type="text" id="searchInput" class="search-input" placeholder="Search files...">
                    </div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th class="sort-header" data-sort="filename">Filename <i class="fas fa-sort"></i></th>
                            <th>Type</th>
                            <th>Size</th>
                            <th>Upload Date</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($userStorage['files'] as $file): ?>
                        <tr class="file-row" data-file-id="<?php echo $file['ID']; ?>">
                            <td><?php echo htmlspecialchars($file['filename']); ?></td>
                            <td><?php echo htmlspecialchars($file['LogType']); ?></td>
                            <td><?php echo round($file['file_size'] / 1024, 2); ?> KB</td>
                            <td><?php echo $file['TimeStamps']; ?></td>
                            <td>
                                <button class="view-btn" onclick="showFilePreview(<?php echo $file['ID']; ?>)">View</button>
                                <button class="delete-btn" onclick="deleteFile(<?php echo $file['ID']; ?>, this.closest('tr'))">Delete</button>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <div id="filePreviewModal" class="file-preview-modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 id="previewTitle"></h2>
                <button class="close-btn">Close</button>
            </div>
            <div class="analysis-content">
                <div class="stats-container">
                    <div class="stat-box">
                        <h4>Total Logs</h4>
                        <span id="modalTotalLogs">0</span>
                    </div>
                    <div class="stat-box">
                        <h4>Malicious Events</h4>
                        <span id="modalMaliciousEvents">0</span>
                    </div>
                    <div class="stat-box">
                        <h4>Alert Level</h4>
                        <span id="modalAlertLevel">Low</span>
                    </div>
                </div>

                <div class="canvas-card">
                    <canvas id="modalAnalysisCanvas"></canvas>
                </div>

                <div class="stats-container">
                    <div class="stat-box">
                        <h4>Source IP</h4>
                        <span id="modalSourceIp">N/A</span>
                    </div>
                    <div class="stat-box">
                        <h4>Log Type</h4>
                        <span id="modalLogType">N/A</span>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
       // Replace everything between <script> tags with this code
        document.addEventListener('DOMContentLoaded', () => {
            // Cache DOM elements
            const modal = document.getElementById('filePreviewModal');
            const closeBtn = modal.querySelector('.close-btn');
            const searchInput = document.getElementById('searchInput');
            const elements = {
                ringText: document.querySelector('.storage-ring-text'),
                ringCircle: document.querySelector('.storage-ring-circle'),
                status: document.querySelector('.storage-status'),
                storageText: document.querySelector('.storage-text')
            };

            // Utility functions
            const formatStorage = (bytes) => {
                const units = ['B', 'KB', 'MB', 'GB'];
                let value = bytes;
                let unitIndex = 0;
                
                while (value >= 1024 && unitIndex < units.length - 1) {
                    value /= 1024;
                    unitIndex++;
                }
                
                return `${value.toFixed(2)} ${units[unitIndex]}`;
            };

            const escapeHtml = (unsafe) => {
                return unsafe
                    .replace(/&/g, "&amp;")
                    .replace(/</g, "&lt;")
                    .replace(/>/g, "&gt;")
                    .replace(/"/g, "&quot;")
                    .replace(/'/g, "&#039;");
            };

            const showError = (message, duration = 5000) => {
                const errorDiv = document.createElement('div');
                errorDiv.className = 'alert alert-danger fade-in';
                errorDiv.textContent = message;
                
                const container = document.querySelector('.main-content');
                if (container) {
                    container.prepend(errorDiv);
                    setTimeout(() => {
                        errorDiv.style.opacity = '0';
                        setTimeout(() => errorDiv.remove(), 300);
                    }, duration);
                }
            };

            // Storage management
            async function updateStorageInfo() {
                try {
                    const response = await fetch('/Shield/get_storage_info.php');
                    if (!response.ok) throw new Error('Failed to fetch storage info');
                    
                    const data = await response.json();
                    if (!data.success) throw new Error('Invalid storage data');
                    
                    // Update storage ring
                    const ringText = document.querySelector('.storage-ring-text');
                    const ringCircle = document.querySelector('.storage-ring-circle');
                    ringText.textContent = `${data.percentage}%`;
                    ringCircle.style.strokeDashoffset = (339.292 * (100 - data.percentage)) / 100;
                    
                    // Update status
                    const status = document.querySelector('.storage-status');
                    const statusClass = data.percentage >= 90 ? 'high' : 
                                      data.percentage >= 75 ? 'medium' : 'low';
                    const statusText = data.percentage >= 90 ? 'Critical' : 
                                      data.percentage >= 75 ? 'Warning' : 'Good';
                    
                    status.className = `storage-status ${statusClass}`;
                    status.textContent = `Status: ${statusText}`;
                    
                    // Update plan badge
                    const planBadge = document.getElementById('subscriptionBadge');
                    if (planBadge) {
                        planBadge.textContent = `${data.plan} PLAN`;
                    }
                    
                    // Update storage text
                    const storageText = document.querySelector('.storage-text');
                    const usedGB = (data.used / (1024 * 1024 * 1024)).toFixed(2);
                    const totalGB = (data.total / (1024 * 1024 * 1024)).toFixed(2);
                    storageText.innerHTML = `
                        <span>Used: ${usedGB} GB</span>
                        <span>Total: ${totalGB} GB</span>
                    `;
                    
                    // Update color scheme
                    document.documentElement.style.setProperty(
                        '--storage-color',
                        data.percentage >= 90 ? '#f44336' : 
                        data.percentage >= 75 ? '#ff9800' : '#4caf50'
                    );
                } catch (error) {
                    console.error('Storage update failed:', error);
                    showError('Failed to update storage information');
                }
            }

            // Add periodic storage updates
            setInterval(updateStorageInfo, 30000); // Update every 30 seconds

            // Call immediately on page load
            document.addEventListener('DOMContentLoaded', updateStorageInfo);

            // File management
            async function deleteFile(fileId, row) {
                if (!confirm('Are you sure you want to delete this file?')) {
                    return;
                }

                try {
                    row.style.opacity = '0.5';
                    row.style.pointerEvents = 'none';
                    
                    const response = await fetch(window.location.href, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                        body: `delete_file=1&file_id=${fileId}`
                    });

                    if (!response.ok) throw new Error('Network response was not ok');
                    const result = await response.json();
                    
                    if (result.success) {
                        await Promise.all([
                            updateTableContent(result.files),
                            updateStorageInfo()
                        ]);
                    } else {
                        throw new Error(result.error || 'Delete operation failed');
                    }
                } catch (error) {
                    console.error('Delete failed:', error);
                    showError('Failed to delete file');
                    row.style.opacity = '1';
                    row.style.pointerEvents = 'auto';
                }
            }

            // File preview functionality
            async function showFilePreview(fileId) {
                try {
                    modal.style.display = 'flex';
                    document.getElementById('previewTitle').textContent = 'Loading analysis results...';

                    const response = await fetch(`${window.location.pathname}?view_analysis=${fileId}`);
                    if (!response.ok) throw new Error('Failed to fetch analysis results');

                    const data = await response.json();
                    if (!data.success) throw new Error(data.message || 'Failed to load analysis results');

                    updateModalContent(data.results);
                } catch (error) {
                    console.error('Preview error:', error);
                    showError('Failed to load preview: ' + error.message);
                    modal.style.display = 'none';
                }
            }

            function updateModalContent(results) {
                if (!results) return;

                const elements = {
                    title: document.getElementById('previewTitle'),
                    totalLogs: document.getElementById('modalTotalLogs'),
                    maliciousEvents: document.getElementById('modalMaliciousEvents'),
                    alertLevel: document.getElementById('modalAlertLevel'),
                    sourceIp: document.getElementById('modalSourceIp'),
                    logType: document.getElementById('modalLogType'),
                    canvas: document.getElementById('modalAnalysisCanvas')
                };

                elements.title.textContent = `Analysis Results for ${results.filename || 'Log File'}`;
                elements.totalLogs.textContent = results.total_logs.toLocaleString();
                elements.maliciousEvents.textContent = results.malicious_events.toLocaleString();
                elements.alertLevel.textContent = results.alert_level;
                elements.sourceIp.textContent = results.sourceIp || 'N/A';
                elements.logType.textContent = results.log_type || 'N/A';

                if (results.graph_data) {
                    renderGraphToCanvas(elements.canvas, results.graph_data);
                }
            }

            function renderGraphToCanvas(canvas, graphData) {
                const img = new Image();
                img.onload = () => {
                    const container = canvas.parentElement;
                    const containerWidth = container.offsetWidth - 40;
                    const scale = containerWidth / img.width;
                    
                    canvas.width = containerWidth;
                    canvas.height = img.height * scale;
                    
                    const ctx = canvas.getContext('2d');
                    ctx.clearRect(0, 0, canvas.width, canvas.height);
                    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
                };
                img.src = 'data:image/png;base64,' + graphData;
            }

            // Table management
            function updateTableContent(files) {
                const tbody = document.querySelector('tbody');
                if (!tbody) return;

                tbody.innerHTML = files.map(file => `
                    <tr class="file-row" data-file-id="${file.ID}">
                        <td>${escapeHtml(file.filename)}</td>
                        <td>${escapeHtml(file.LogType)}</td>
                        <td>${(file.file_size / 1024).toFixed(2)} KB</td>
                        <td>${file.TimeStamps}</td>
                        <td>
                            <button class="view-btn action-btn" onclick="showFilePreview(${file.ID})">
                                <i class="fas fa-eye"></i> View
                            </button>
                            <button class="delete-btn action-btn" onclick="deleteFile(${file.ID}, this.closest('tr'))">
                                <i class="fas fa-trash"></i> Delete
                            </button>
                        </td>
                    </tr>
                `).join('');

                if (searchInput?.value) {
                    filterFiles(searchInput.value);
                }
            }

            async function refreshFileList() {
                try {
                    const response = await fetch(`${window.location.pathname}?get_files=1`);
                    if (!response.ok) throw new Error('Failed to fetch files');
                    
                    const data = await response.json();
                    updateTableContent(data.files);
                } catch (error) {
                    console.error('File list refresh failed:', error);
                    showError('Failed to refresh file list');
                }
            }

            // Search functionality
            function filterFiles(searchTerm) {
                const rows = document.querySelectorAll('.file-row');
                const term = searchTerm.toLowerCase();
                
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(term) ? '' : 'none';
                });
            }

            // Event listeners
            if (searchInput) {
                searchInput.addEventListener('input', (e) => filterFiles(e.target.value));
            }

            closeBtn?.addEventListener('click', () => {
                modal.style.display = 'none';
            });

            modal?.addEventListener('click', (e) => {
                if (e.target === modal) modal.style.display = 'none';
            });

            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && modal?.style.display === 'flex') {
                    modal.style.display = 'none';
                }
            });

            // Handle window resize
            let resizeTimeout;
            window.addEventListener('resize', () => {
                clearTimeout(resizeTimeout);
                resizeTimeout = setTimeout(() => {
                    const canvas = document.getElementById('modalAnalysisCanvas');
                    if (canvas && modal?.style.display === 'flex') {
                        const currentSrc = canvas.toDataURL();
                        renderGraphToCanvas(canvas, currentSrc);
                    }
                }, 250);
            });

            // Initialize periodic updates
            updateStorageInfo();
            setInterval(() => {
                Promise.all([
                    updateStorageInfo(),
                    refreshFileList()
                ]).catch(console.error);
            }, 30000);

            // Make functions globally available
            window.showFilePreview = showFilePreview;
            window.deleteFile = deleteFile;
        });

        function updatePlanInfo(planData) {
            const planBadge = document.getElementById('subscriptionBadge');
            if (planBadge) {
                planBadge.textContent = `${planData.plan} PLAN`;
                
                // Update storage limit display
                const storageText = document.querySelector('.storage-text');
                if (storageText) {
                    const usedGB = (planData.used / (1024 * 1024 * 1024)).toFixed(2);
                    const totalGB = (planData.total / (1024 * 1024 * 1024)).toFixed(2);
                    storageText.innerHTML = `
                        <span>Used: ${usedGB} GB</span>
                        <span>Total: ${totalGB} GB</span>
                    `;
                }
            }
        }
    </script>
</body>
</html>