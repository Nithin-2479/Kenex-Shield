<?php
session_start();
include 'database.php';

// Add plan configurations at the top after session start
$planLimits = [
    'ESSENTIAL' => [
        'max_logs' => 3,
        'types' => [
            ["Firewall Logs" => "Firewall Logs"],
            ["Dns Query Logs" => "DNS Query Logs"],
            ["User Activity Logs" => "User Activity Logs"]
        ]
    ],
    'PROFESSIONAL' => [
        'max_logs' => 5,
        'types' => [
            ["Firewall Logs" => "Firewall Logs"],
            ["Dns Query Logs" => "DNS Query Logs"],
            ["User Activity Logs" => "User Activity Logs"],
            ["Network Traffic Logs" => "Network Traffic Logs"],
            ["Email Security Logs" => "Email Security Logs"]
        ]
    ],
    'ENTERPRISE' => [
        'max_logs' => 8,
        'types' => [
            ["Firewall Logs" => "Firewall Logs"],
            ["Dns Query Logs" => "DNS Query Logs"],
            ["User Activity Logs" => "User Activity Logs"],
            ["Network Traffic Logs" => "Network Traffic Logs"],
            ["Email Security Logs" => "Email Security Logs"],
            ["Application Logs" => "Application Logs"],
            ["Endpoint Security Logs" => "Endpoint Security Logs"],
            ["SIEM Systems Aggregated Logs" => "SIEM Systems Aggregated Logs"]
        ]
    ]
];

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Get user info from session
$username = $_SESSION['username'];
$userPlan = strtoupper($_SESSION['user_plan']);

// Fetch user profile data
$stmt = $pdo->prepare("
    SELECT FirstName, LastName, Email, CompanyName, Address, PhoneNumber 
    FROM UserDetails 
    WHERE UserID = :userId
");
$stmt->execute([':userId' => $_SESSION['user_id']]);
$userProfile = $stmt->fetch(PDO::FETCH_ASSOC);

// Update query to use UploadLogs table
$stmt = $pdo->prepare("
    SELECT 
        LogType,
        filedata,
        DATE_FORMAT(TimeStamps, '%a, %d %b %Y') as FormattedDate 
    FROM UploadLogs 
    WHERE UserID = :userId 
    ORDER BY TimeStamps DESC 
    LIMIT 5
");
$stmt->execute([':userId' => $_SESSION['user_id']]);
$recentLogs = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Add plan expiration query
$stmt = $pdo->prepare("
    SELECT EndDate, DATEDIFF(EndDate, CURDATE()) as DaysRemaining, Status
    FROM Plan 
    WHERE UserID = :userId AND Status = 'active'
");
$stmt->execute([':userId' => $_SESSION['user_id']]);
$planInfo = $stmt->fetch(PDO::FETCH_ASSOC);

// Add helper function for file size formatting
function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}

// Add this function after the formatFileSize function
function getAvailableLogTypes($userPlan, $planLimits) {
    $userPlan = strtoupper($userPlan);
    return $planLimits[$userPlan]['types'] ?? $planLimits['ESSENTIAL']['types'];
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #ff7730;
            --secondary-color: #fff5f0;
            --text-color: #2d2d2d;
            --shadow: 0 2px 10px rgba(255, 119, 48, 0.1);
            --navbar-bg: #ffffff;
            --content-bg: linear-gradient(135deg, #fff5f0 0%, #ffdac8 100%);
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--content-bg);
            background-attachment: fixed;
            position: relative;
            color: var(--text-color);
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }

        body::before {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #fff5f0 0%,rgb(205, 205, 205) 100%);
            pointer-events: none;
        }

        .card {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            padding: 1.5rem;
            box-shadow: 0 8px 32px 0 rgba(31, 38, 135, 0.15);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px 0 rgba(31, 38, 135, 0.25);
        }

        .navbar {
            background: var(--navbar-bg) !important;
            box-shadow: 0 2px 15px rgba(255, 119, 48, 0.15);
            padding: 0.5rem 2rem;
            position: relative;
            border-bottom: 3px solid var(--primary-color);
            display: grid;
            grid-template-columns: 1fr auto 1fr;
            align-items: center;
        }

        .navbar-brand {
            justify-self: center;
            grid-column: 2;
        }

        .navbar-nav {
            justify-self: start;
        }

        .avatar-section {
            justify-self: end;
        }

        .main-content {
            background: var(--content-bg);
            position: relative;
            z-index: 1;
            padding: 2rem;
            max-width: 1200px;
            max-height: 1500px;
            margin: 2rem auto;
            border-radius: 15px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
        }

        .dashboard-header {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
            border-left: 4px solid var(--primary-color);
        }

        .welcome-text h1 {
            margin-bottom: 0.5rem;
            color: var(--text-color);
            font-size: 2rem;
        }

        .plan-badge {
            display: inline-block;
            background: var(--primary-color);
            color: white;
            padding: 0.5rem 1.5rem;
            border-radius: 25px;
            font-size: 1.2rem;
            font-weight: 600;
            margin-top: 0.5rem;
            box-shadow: 0 2px 10px rgba(255, 119, 48, 0.2);
            transition: transform 0.2s ease;
        }

        .plan-badge:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(255, 119, 48, 0.3);
        }

        .navbar-brand {
            font-weight: 600;
            color: var(--primary-color) !important;
            margin-right: 2rem;
        }

        .navbar-brand img {
            height: 60px; /* Increased from 40px */
            width: auto;
            transition: transform 0.3s ease;
        }

        .navbar-brand img:hover {
            transform: scale(1.05);
        }

        .navbar-toggler {
            position: absolute;
            right: 1rem;
            top: 50%;
            transform: translateY(-50%);
        }

        .nav-link {
            color: var(--text-color) !important;
            font-weight: 500;
            transition: color 0.3s ease;
        }

        .nav-link:hover {
            color: var(--primary-color) !important;
        }

        .avatar-section {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .avatar-section img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            box-shadow: var(--shadow);
        }

        .dashboard-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }

        .upload-btn {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 0.8rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            transition: transform 0.2s ease;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .upload-btn:hover {
            transform: translateY(-2px);
            background-color: #ff8d4d;
        }

        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 2rem;
        }

        .card.full-width {
            grid-column: 1 / -1;
        }

        .profile-info {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }

        .profile-item {
            padding: 0.5rem 0;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }

        .profile-label {
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 0.25rem;
        }

        .profile-value {
            color: var(--text-color);
        }

        @media (max-width: 768px) {
            .dashboard-grid {
                grid-template-columns: 1fr;
            }
            
            .profile-info {
                grid-template-columns: 1fr;
            }
            
            .navbar {
                padding: 1rem;
            }
            
            .main-content {
                margin: 1rem;
                padding: 1rem;
            }

            .navbar-brand img {
                height: 45px; /* Adjusted for mobile */
            }
        }

        .log-info {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .log-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.8rem 0;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }

        .text-muted {
            color: #6c757d;
        }

        .me-2 {
            margin-right: 0.5rem;
        }

        .ms-2 {
            margin-left: 0.5rem;
        }

        .plan-status {
            padding: 1rem;
        }

        .days-remaining {
            font-size: 1.2rem;
            margin-bottom: 0.5rem;
            color: var(--primary-color);
        }

        .days-remaining.urgent {
            color: #dc3545;
            animation: pulse 2s infinite;
        }

        .expiry-date {
            color: #666;
            margin-bottom: 1rem;
        }

        .renewal-alert {
            background: #fff3cd;
            color: #856404;
            padding: 0.5rem;
            border-radius: 4px;
            margin: 1rem 0;
        }

        .renew-btn {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
            transition: all 0.3s ease;
        }

        .renew-btn:hover {
            background: #ff8d4d;
            transform: translateY(-2px);
        }

        .no-plan {
            color: #dc3545;
            text-align: center;
            padding: 1rem;
        }

        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
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

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .card-title {
            margin: 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .upload-btn.recent-logs {
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
            background-color: var(--primary-color);
            margin-left: auto; /* Pushes button to the right */
        }

        .profile-link {
            color: var(--text-color);
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .profile-link:hover {
            color: var(--primary-color);
        }

        .upload-summary {
            padding: 1rem;
            margin-bottom: 1rem;
        }

        .summary-item {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
            transition: transform 0.3s ease;
        }

        .summary-item:hover {
            transform: translateY(-2px);
            background: var(--primary-color);
            color: white;
        }

        .summary-item i {
            font-size: 2rem;
        }

        .summary-details {
            display: flex;
            flex-direction: column;
        }

        .summary-label {
            font-size: 0.875rem;
            color: inherit;
        }

        .summary-count {
            font-size: 1.5rem;
            font-weight: 600;
        }

        .stat-badge {
            background: #f0f0f0;
            padding: 0.25rem 0.75rem;
            border-radius: 15px;
            font-size: 0.875rem;
            margin-left: 0.5rem;
        }

        .view-all-btn {
            width: 100%;
            padding: 0.75rem;
            background: transparent;
            border: 1px solid var(--primary-color);
            color: var(--primary-color);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
        }

        .view-all-btn:hover {
            background: var(--primary-color);
            color: white;
        }

        @media (max-width: 768px) {
            .upload-summary {
                grid-template-columns: 1fr;
            }
            
            .stat-badge {
                display: none;
            }
        }

        .recent-logs-content {
            max-height: 300px;
            overflow-y: auto;
        }

        .recent-logs-content::-webkit-scrollbar {
            width: 6px;
        }

        .recent-logs-content::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 3px;
        }

        .recent-logs-content::-webkit-scrollbar-thumb {
            background: var(--primary-color);
            border-radius: 3px;
        }

        .recent-logs-content::-webkit-scrollbar-thumb:hover {
            background: #ff8d4d;
        }

        .available-logs {
            margin-bottom: 1.5rem;
        }

        .available-logs h4 {
            font-size: 1rem;
            color: var(--text-color);
            margin-bottom: 1rem;
            padding-left: 0.5rem;
        }

        .log-types-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1rem;
        }

        .log-type-item {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 1rem;
            background: #f8f9fa;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-align: center;
        }

        .log-type-item:hover {
            background: var(--primary-color);
            color: white;
            transform: translateY(-2px);
        }

        .log-type-item i {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }

        .log-type-item span {
            font-size: 0.875rem;
            font-weight: 500;
        }

        @media (max-width: 768px) {
            .log-types-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .log-types-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .log-type-row {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.75rem;
            background: #f8f9fa;
            border-radius: 8px;
            transition: background-color 0.2s ease;
        }

        .log-type-row:hover {
            background: #f0f0f0;
        }

        .log-type-row i {
            color: var(--primary-color);
            font-size: 1.25rem;
            width: 24px;
            text-align: center;
        }

        .log-type-name {
            font-size: 0.95rem;
            color: var(--text-color);
        }

        .plan-indicator {
            font-size: 0.875rem;
            color: var(--primary-color);
            font-weight: 500;
        }

        .upgrade-notice {
            margin-top: 1rem;
            padding: 0.75rem;
            background: #fff3cd;
            color: #856404;
            border-radius: 4px;
            font-size: 0.875rem;
            text-align: center;
        }

        .log-types-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
        }

        .log-type-row {
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.75rem;
            background: #f8f9fa;
            border-radius: 8px;
            transition: all 0.3s ease;
        }

        .log-type-row:hover {
            background: var(--primary-color);
            color: white;
        }

        .log-type-row i {
            width: 24px;
            text-align: center;
        }

        .log-type-name {
            font-weight: 500;
        }

        .upload-button-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 1rem;
            margin-top: 1.5rem;
            padding-top: 1.5rem;
            border-top: 1px solid rgba(0, 0, 0, 0.1);
        }

        .upload-button-container .upload-btn {
            width: auto;
            min-width: 200px;
        }

        .upgrade-link {
            color: var(--primary-color);
            font-size: 0.875rem;
            text-decoration: none;
            transition: color 0.3s ease;
        }

        .upgrade-link:hover {
            text-decoration: underline;
            color: #ff8d4d;
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg">
        <div class="navbar-nav me-auto">
            <a class="nav-link" href="#">Home</a>
            <a class="nav-link" href="https://kenexoft.com/kenexoft/#contact-us">Contact</a>
            <a class="nav-link sign-out" href="logout.php">Sign Out</a>
        </div>
        
        <a class="navbar-brand" href="#">
            <img src="Logo.png" alt="Shield Logo">
        </a>
        
        <div class="avatar-section">
            <i class="fas fa-user"></i>
            <span><?php echo htmlspecialchars($username); ?></span>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="main-content">
        <div class="dashboard-header">
            <div class="welcome-text">
                <h1>Welcome, <?php echo htmlspecialchars($username); ?>!</h1>
                <div class="plan-badge">
                    <?php echo htmlspecialchars($userPlan); ?> PLAN
                </div>
            </div>

        </div>

        <div class="dashboard-grid">
            <!-- User Profile Card -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-user"></i>
                        <a href="userProfile.php" class="profile-link">User Profile</a>
                    </h3>
                </div>
                <div class="card-content">
                    <div class="profile-info">
                        <div class="profile-item">
                            <div class="profile-label">Name</div>
                            <div class="profile-value">
                                <?php echo htmlspecialchars($userProfile['FirstName'] . ' ' . $userProfile['LastName']); ?>
                            </div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Email</div>
                            <div class="profile-value">
                                <?php echo htmlspecialchars($userProfile['Email']); ?>
                            </div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Company</div>
                            <div class="profile-value">
                                <?php echo htmlspecialchars($userProfile['CompanyName'] ?? 'Not specified'); ?>
                            </div>
                        </div>
                        <div class="profile-item">
                            <div class="profile-label">Phone</div>
                            <div class="profile-value">
                                <?php echo htmlspecialchars($userProfile['PhoneNumber'] ?? 'Not specified'); ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Plan Status Card -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-tasks"></i>
                    <h3 class="card-title">Plan Status</h3>
                </div>
                <div class="card-content">
                    <?php if ($planInfo): ?>
                        <div class="plan-status">
                            <div class="plan-info">
                                <div class="days-remaining <?php echo $planInfo['DaysRemaining'] <= 7 ? 'urgent' : ''; ?>">
                                    <i class="fas fa-clock me-2"></i>
                                    <strong><?php echo $planInfo['DaysRemaining']; ?></strong> days remaining
                                </div>
                                <div class="expiry-date">
                                    Expires on: <?php echo date('F j, Y', strtotime($planInfo['EndDate'])); ?>
                                </div>
                                <?php if ($planInfo['DaysRemaining'] <= 7): ?>
                                    <div class="renewal-alert">
                                        <i class="fas fa-exclamation-triangle me-2"></i>
                                        Time to renew your plan!
                                    </div>
                                <?php endif; ?>
                            </div>
                            <?php if ($planInfo['DaysRemaining'] <= 30): ?>
                                <button class="renew-btn" onclick="window.location.href='renewal.php'">
                                    Renew Now
                                </button>
                            <?php endif; ?>
                        </div>
                    <?php else: ?>
                        <div class="no-plan">
                            <i class="fas fa-exclamation-circle me-2"></i>
                            No active plan found
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Upload Logs Summary -->
            <div class="card">
                <div class="card-header">
                    <h3 class="card-title">
                        <i class="fas fa-list"></i>
                        Available Log Types
                    </h3>
                    <div class="plan-type">
                        <span class="plan-indicator"><?php echo htmlspecialchars($userPlan); ?> PLAN</span>
                    </div>
                </div>
                <div class="card-content">
                    <div class="log-types-list">
                        <?php 
                        $availableTypes = getAvailableLogTypes($userPlan, $planLimits);
                        foreach ($availableTypes as $logType): 
                            $typeName = array_values($logType)[0];
                        ?>
                            <div class="log-type-row">
                                <i class="fas fa-file-code"></i>
                                <span class="log-type-name"><?php echo htmlspecialchars($typeName); ?></span>
                            </div>
                        <?php endforeach; ?>
                    </div>
                    
                    <div class="upload-button-container">
                        <button class="upload-btn" onclick="window.location.href='upload.php'">
                            <i class="fas fa-upload"></i>
                            Upload Logs
                        </button>
                        <?php if (count($availableTypes) < count($planLimits['ENTERPRISE']['types'])): ?>
                            <div class="upgrade-notice">
                                <a href="upgrade.php" class="upgrade-link">Upgrade your plan for more log types</a>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>

            <!-- Recent Logs Card (moved beside Upload Logs Summary) -->
            <div class="card">
                <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-history"></i>
                        <h3><a href="recent_logs.php" class="profile-link">Recent Uploads</a></h3>
                    </div>
                </div>
                <div class="card-content recent-logs-content">
                    <?php if ($recentLogs): ?>
                        <?php foreach ($recentLogs as $log): ?>
                            <div class="log-item">
                                <div class="log-info">
                                    <i class="fas fa-file-alt me-2"></i>
                                    <span><?php echo htmlspecialchars($log['LogType']); ?></span>
                                </div>
                                <span class="log-date"><?php echo htmlspecialchars($log['FormattedDate']); ?></span>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="log-item">
                            <span>No logs uploaded yet</span>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>