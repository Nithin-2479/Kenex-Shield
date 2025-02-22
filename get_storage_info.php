<?php
session_start();
include 'database.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    exit;
}

$userId = $_SESSION['user_id'];

// Get user's current plan from database
$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    http_response_code(500);
    exit;
}

$stmt = $conn->prepare("SELECT plan FROM users WHERE id = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();
$userPlan = strtoupper($result->fetch_assoc()['plan']);

$storageLimits = [
    'ESSENTIAL' => 2147483648,     // 2GB
    'PROFESSIONAL' => 5368709120,  // 5GB
    'ENTERPRISE' => 10737418240    // 10GB
];

$storageLimit = $storageLimits[$userPlan] ?? $storageLimits['ESSENTIAL'];

// Get current storage usage
$stmt = $conn->prepare("SELECT COALESCE(SUM(LENGTH(filedata)), 0) as total_size FROM UploadLogs WHERE UserID = ?");
$stmt->bind_param("i", $userId);
$stmt->execute();
$storageUsed = $stmt->get_result()->fetch_assoc()['total_size'];

$percentage = ($storageUsed / $storageLimit) * 100;

header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'used' => $storageUsed,
    'total' => $storageLimit,
    'percentage' => round($percentage, 1),
    'plan' => $userPlan,
    'status' => $percentage >= 90 ? 'critical' : 
                ($percentage >= 75 ? 'warning' : 'good')
]);

$stmt->close();
$conn->close();
