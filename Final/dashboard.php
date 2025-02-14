<?php
session_start();
include 'database.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit();
}

// Get user info from session
$username = $_SESSION['username'];
$userPlan = $_SESSION['user_plan'];

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
            background: url('data:image/svg+xml,<svg width="20" height="20" xmlns="http://www.w3.org/2000/svg"><rect width="20" height="20" fill="none"/><path d="M0 0h4v4H0V0zm8 0h4v4H8V0zm8 0h4v4h-4V0zM4 4h4v4H4V4zm8 0h4v4h-4V4zM0 8h4v4H0V8zm8 0h4v4H8V8zm8 0h4v4h-4V8zM4 12h4v4H4v-4zm8 0h4v4h-4v-4zM0 16h4v4H0v-4zm8 0h4v4H8v-4zm8 0h4v4h-4v-4z" fill="rgba(0,0,0,0.03)"/></svg>') repeat;
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
        }

        .main-content {
            background: var(--content-bg);
            position: relative;
            z-index: 1;
            padding: 2rem;
            max-width: 1200px;
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
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg">
        <div class="container-fluid">
            <a class="navbar-brand" href="#">
                <img src="Logo.png" alt="Shield Logo">
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav me-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#">Home</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#">Contact</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link sign-out" href="logout.php">Sign Out</a>
                    </li>
                </ul>
                <div class="avatar-section">
                <i class="fas fa-user"></i>
                    <span><?php echo htmlspecialchars($username); ?></span>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <div class="main-content">
        <div class="dashboard-header">
            <div class="welcome-text">
                <h1>Welcome, <?php echo htmlspecialchars($username); ?>!</h1>
                <div class="plan-badge">
                    <?php echo htmlspecialchars($userPlan); ?> Plan
                </div>
            </div>
            <button class="upload-btn" onclick="window.location.href='upload.php'">
                <i class="fas fa-upload"></i>
                Upload Logs
            </button>
        </div>

        <div class="dashboard-grid">
            <!-- User Profile Card -->
            <div class="card">
                <div class="card-header">
                    <i class="fas fa-user"></i>
                    <h3 class="card-title">User Profile</h3>
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

            <!-- Todo List Card -->
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

            <!-- Recent Logs Card - Full Width -->
            <div class="card full-width">
                <div class="card-header">
                    <i class="fas fa-history"></i>
                    <h3 class="card-title">Recent Uploads</h3>
                </div>
                <div class="card-content">
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

            <!-- Recent Activity Card - Full Width -->
            <div class="card full-width">
                <div class="card-header">
                    <i class="fas fa-chart-line"></i>
                    <h3 class="card-title">Recent Activity</h3>
                </div>
                <div class="card-content">
                    <!-- Add activity content here -->
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>