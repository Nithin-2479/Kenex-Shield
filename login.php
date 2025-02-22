<?php

session_start();
include 'database.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    
    if (!empty($username) && !empty($password)) {
        // Fetch user details and plan
        $stmt = $pdo->prepare("
            SELECT u.UserID, u.Username, u.PasswordHash, p.PlanName 
            FROM UserDetails u 
            LEFT JOIN Plan p ON u.UserID = p.UserID 
            WHERE u.Username = :username AND p.Status = 'active'
        ");
        $stmt->execute([':username' => $username]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['PasswordHash'])) {
            // Set session variables
            $_SESSION['user_id'] = $user['UserID'];
            $_SESSION['username'] = $user['Username'];
            $_SESSION['user_plan'] = $user['PlanName'];
            
            // Redirect to dashboard
            header("Location: dashboard.php");
            exit();
        } else {
            $error_message = "Invalid username or password";
        }
    } else {
        $error_message = "Please enter both username and password";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f2f5;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgb(245, 130, 22);
            width: 400px;
            height: Auto;
            padding: 30px;
            text-align: center;
        }
        .logo {
            margin-bottom: 20px;
        }
        .logo img {
            max-width: 200px;
        }
        .input-group {
            margin-bottom: 15px;
            position: relative;
        }
        .input-group input {
            width: 85%;
            padding: 10px 40px 10px 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .input-group .icon {
            position: absolute;
            right: 10px;
            top: 50%;
            transform: translateY(-50%);
            color: #888;
        }
        .login-btn {
            width: 100%;
            padding: 10px;
            background-color:rgb(252, 124, 4);
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            cursor: pointer;
        }
        .forgot-password {
            color: #dc3545;
            text-decoration: none;
            margin-top: 10px;
            display: inline-block;
        }
        .header {
            color: #007bff;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <img src="Logo.png" alt="Shield Logo">
        </div>
        <h2 class="header">Login</h2>
        <?php if (!empty($error_message)): ?>
            <div class="error-message" style="color: #dc3545; margin-bottom: 15px;">
                <?php echo htmlspecialchars($error_message); ?>
            </div>
        <?php endif; ?>
        <form method="POST" action="login.php">
            <div class="input-group">
                <input type="text" name="username" placeholder="Username" required>
                <span class="icon">👤</span>
            </div>
            <div class="input-group">
                <input type="password" name="password" placeholder="Password" required>
                <span class="icon">🔒</span>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
            <a href="#" class="forgot-password">I forgot my password</a>
            <p><a href="registration.php">Don't have an account? </a></p>
        </form>
    </div>
</body>
</html>
