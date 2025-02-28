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

// Add this function after the database connection constants
function calculateUserStorage($userId) {
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed');
        }

        // Calculate total storage from UploadLogs table
        $stmt = $conn->prepare("
            SELECT 
                COUNT(*) as total_files,
                SUM(LENGTH(filedata)) as total_storage,
                MAX(TimeStamps) as last_upload
            FROM UploadLogs 
            WHERE UserID = ?
        ");

        if (!$stmt) {
            throw new Exception('Query preparation failed');
        }

        $stmt->bind_param("i", $userId);
        if (!$stmt->execute()) {
            throw new Exception('Query execution failed');
        }

        $result = $stmt->get_result();
        $data = $result->fetch_assoc();

        $storageLimit = getStorageLimit($_SESSION['user_plan']);
        $usedStorage = $data['total_storage'] ?? 0;
        $percentageUsed = ($usedStorage / $storageLimit) * 100;

        return [
            'total_files' => $data['total_files'] ?? 0,
            'total_storage' => $usedStorage,
            'last_upload' => $data['last_upload'] ?? null,
            'formatted_storage' => formatStorageSize($usedStorage),
            'storage_limit' => $storageLimit,
            'formatted_limit' => formatStorageSize($storageLimit),
            'percentage_used' => round($percentageUsed, 2),
            'can_upload' => $usedStorage < $storageLimit
        ];

    } catch (Exception $e) {
        error_log("Storage calculation error: " . $e->getMessage());
        return [
            'total_files' => 0,
            'total_storage' => 0,
            'last_upload' => null,
            'formatted_storage' => '0 B',
            'storage_limit' => getStorageLimit($_SESSION['user_plan']),
            'formatted_limit' => formatStorageSize(getStorageLimit($_SESSION['user_plan'])),
            'percentage_used' => 0,
            'can_upload' => true
        ];
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
    }
}

function getStorageLimit($userPlan) {
    // Storage limits in bytes
    $limits = [
        'ESSENTIAL' => 2147483648,    // 2 GB
        'PROFESSIONAL' => 5368709120, //  5 GB
        'ENTERPRISE' => 10737418240    //  10 GB
    ];
    
    return $limits[strtoupper($userPlan)] ?? $limits['ESSENTIAL'];
}

function formatStorageSize($bytes) {
    if ($bytes === 0) return '0 B';
    
    $units = ['B', 'KB', 'MB', 'GB', 'TB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    $pow = min($pow, count($units) - 1);
    
    return round($bytes / (1024 ** $pow), 2) . ' ' . $units[$pow];
}

// Add this line before the HTML output to get storage info
$userStorage = calculateUserStorage($_SESSION['user_id']);

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
        $files = getRecentFiles($userId);
        
        echo json_encode([
            'success' => true,
            'files' => $files
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

// Add new endpoint for getting updated file list
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['get_files'])) {
    header('Content-Type: application/json');
    $files = getRecentFiles($_SESSION['user_id']);
    echo json_encode(['files' => $files]);
    exit();
}

// Add new download endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['download'])) {
    $fileId = intval($_GET['download']);
    $userId = $_SESSION['user_id'];
    
    try {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            throw new Exception('Database connection failed');
        }

        $stmt = $conn->prepare("SELECT filename, filedata, LogType FROM UploadLogs WHERE ID = ? AND UserID = ?");
        if (!$stmt) {
            throw new Exception('Query preparation failed');
        }

        $stmt->bind_param("ii", $fileId, $userId);
        if (!$stmt->execute()) {
            throw new Exception('Query execution failed');
        }

        $result = $stmt->get_result();
        if ($result->num_rows === 0) {
            throw new Exception('File not found or access denied');
        }

        $file = $result->fetch_assoc();
        
        // Set headers for download
        header('Content-Type: text/plain');
        header('Content-Disposition: attachment; filename="' . $file['filename'] . '"');
        header('Content-Length: ' . strlen($file['filedata']));
        header('Cache-Control: no-cache, must-revalidate');
        header('Pragma: public');
        
        echo $file['filedata'];
        exit();

    } catch (Exception $e) {
        header('HTTP/1.1 404 Not Found');
        echo json_encode(['error' => $e->getMessage()]);
    } finally {
        if (isset($stmt)) $stmt->close();
        if (isset($conn)) $conn->close();
    }
    exit();
}

// Get recent files
function getRecentFiles($userId) {
    $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if ($conn->connect_error) {
        return [];
    }
    
    $stmt = $conn->prepare("
        SELECT 
            ul.ID, 
            ul.LogType, 
            ul.filename, 
            LENGTH(ul.filedata) as file_size, 
            ul.TimeStamps
        FROM UploadLogs ul
        WHERE ul.UserID = ?
        ORDER BY ul.TimeStamps DESC 
        LIMIT 10
    ");
    
    if (!$stmt) {
        return [];
    }
    
    $stmt->bind_param("i", $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $files = [];
    while ($row = $result->fetch_assoc()) {
        $files[] = $row;
    }
    
    $conn->close();
    return $files;
}

// Get recent files for initial display
$recentFiles = getRecentFiles($_SESSION['user_id']);

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
        }

        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
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

        .download-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 6px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin: 0 5px;
        }

        .download-btn:hover {
            background: #218838;
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

        .storage-info {
            background-color: #f8f9fa;
            padding: 0.5rem 1rem;
            border-radius: 25px;
            display: flex;
            align-items: center;
            gap: 0.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .storage-label {
            color: #666;
            font-size: 0.9rem;
        }

        .storage-value {
            color: var(--primary-color);
            font-weight: bold;
            font-size: 0.9rem;
        }

        .storage-warning {
            color: #dc3545;
            font-weight: bold;
            margin-left: 0.5rem;
        }

        .storage-progress {
            width: 100px;
            height: 6px;
            background-color: #e9ecef;
            border-radius: 3px;
            margin-left: 0.5rem;
            overflow: hidden;
        }

        .storage-progress-bar {
            height: 100%;
            background-color: var(--primary-color);
            transition: width 0.3s ease;
        }

        .storage-progress-bar.warning {
            background-color: #dc3545;
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
            <div class="storage-info">
                <span class="storage-label">Storage Used:</span>
                <span class="storage-value">
                    <?php 
                    echo $userStorage['formatted_storage'] . ' / ' . $userStorage['formatted_limit'];
                    if ($userStorage['percentage_used'] >= 90) {
                        echo ' <span class="storage-warning">Storage almost full!</span>';
                    }
                    ?>
                </span>
            </div>
            <div class="subscription-status">
                <span id="subscriptionBadge"><?php echo htmlspecialchars($_SESSION['user_plan']); ?> PLAN</span>
            </div>
            <form method="POST" action="logout.php" class="logout-form">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
</header>

    <div class="container">
        <div class="main-content">
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
                        <?php foreach ($recentFiles as $file): ?>
                        <tr class="file-row" data-file-id="<?php echo $file['ID']; ?>">
                            <td><?php echo htmlspecialchars($file['filename']); ?></td>
                            <td><?php echo htmlspecialchars($file['LogType']); ?></td>
                            <td><?php echo round($file['file_size'] / 1024, 2); ?> KB</td>
                            <td><?php echo $file['TimeStamps']; ?></td>
                            <td>
                                <button class="view-btn" onclick="showFilePreview(<?php echo $file['ID']; ?>)">View</button>
                                <button class="download-btn action-btn" onclick="downloadFile(<?php echo $file['ID']; ?>)">
                                    <i class="fas fa-download"></i> Download
                                </button>
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
                            updateTableContent(result.files)
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
                            <button class="download-btn action-btn" onclick="downloadFile(${file.ID})">
                                <i class="fas fa-download"></i> Download
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

            // Add download function
            async function downloadFile(fileId) {
                try {
                    const response = await fetch(`${window.location.pathname}?download=${fileId}`);
                    if (!response.ok) throw new Error('Download failed');
                    
                    const blob = await response.blob();
                    const filename = response.headers.get('Content-Disposition')?.split('filename=')[1]?.replace(/"/g, '') || 'log_file.txt';
                    
                    // Create download link
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.style.display = 'none';
                    a.href = url;
                    a.download = filename;
                    
                    // Trigger download
                    document.body.appendChild(a);
                    a.click();
                    
                    // Cleanup
                    window.URL.revokeObjectURL(url);
                    a.remove();
                } catch (error) {
                    console.error('Download failed:', error);
                    showError('Failed to download file');
                }
            }

            // Make download function globally available
            window.downloadFile = downloadFile;

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
            setInterval(() => {
                Promise.all([
                    refreshFileList()
                ]).catch(console.error);
            }, 30000);

            // Make functions globally available
            window.showFilePreview = showFilePreview;
            window.deleteFile = deleteFile;
        });
    </script>
</body>
</html>