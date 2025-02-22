<?php
session_start();
include 'database.php';

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Get user details
function getUserDetails($pdo, $userId) {
    $stmt = $pdo->prepare("SELECT * FROM UserDetails WHERE UserID = :userId");
    $stmt->execute(['userId' => $userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

// Update user details with password change
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['update_profile'])) {
        $userId = $_SESSION['user_id'];
        $firstName = trim($_POST['firstName']);
        $lastName = trim($_POST['lastName']);
        $countryCode = trim($_POST['countryCode']);
        $areaCode = trim($_POST['areaCode']);
        $phoneNumber = trim($_POST['phoneNumber']);
        $email = trim($_POST['email']);
        $address = trim($_POST['address']);

        $stmt = $pdo->prepare("UPDATE UserDetails 
                          SET FirstName=:firstName, LastName=:lastName, 
                              CountryCode=:countryCode, AreaCode=:areaCode, 
                              PhoneNumber=:phoneNumber, Email=:email, 
                              Address=:address 
                          WHERE UserID=:userId");
        
        $params = [
            'firstName' => $firstName,
            'lastName' => $lastName,
            'countryCode' => $countryCode,
            'areaCode' => $areaCode,
            'phoneNumber' => $phoneNumber,
            'email' => $email,
            'address' => $address,
            'userId' => $userId
        ];
        
        if ($stmt->execute($params)) {
            $successMessage = "Profile updated successfully!";
        } else {
            $errorMessage = "Error updating profile: " . implode(", ", $stmt->errorInfo());
        }
    }

    // Handle password change
    if (isset($_POST['change_password'])) {
        $currentPassword = $_POST['current_password'];
        $newPassword = $_POST['new_password'];
        $confirmPassword = $_POST['confirm_password'];

        // Verify current password
        $stmt = $pdo->prepare("SELECT PasswordHash FROM UserDetails WHERE UserID = :userId");
        $stmt->execute(['userId' => $_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (password_verify($currentPassword, $user['PasswordHash'])) {
            if ($newPassword === $confirmPassword) {
                $newPasswordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE UserDetails SET PasswordHash = :passwordHash WHERE UserID = :userId");
                
                if ($stmt->execute([
                    'passwordHash' => $newPasswordHash,
                    'userId' => $_SESSION['user_id']
                ])) {
                    $successMessage = "Password updated successfully!";
                } else {
                    $errorMessage = "Error updating password.";
                }
            } else {
                $errorMessage = "New passwords do not match.";
            }
        } else {
            $errorMessage = "Current password is incorrect.";
        }
    }
}

$userDetails = getUserDetails($pdo, $_SESSION['user_id']);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Profile</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
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
            display: flex;
            align-items: center;
            gap: 1rem;
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
            margin-right: 1rem; /* Add spacing between plan and logout button */
        }

        .container {
            display: flex;
            min-height: calc(100vh - 70px);
            padding: 2rem;
        }

        .profile-form {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            color: var(--primary-color);
            font-weight: 600;
            margin-bottom: 0.5rem;
            display: block;
        }

        .form-control {
            background: rgba(255, 255, 255, 0.9);
            border: 1px solid rgba(255, 107, 1, 0.2);
            border-radius: 8px;
            padding: 0.8rem;
            transition: all 0.3s ease;
        }

        .form-control:focus {
            box-shadow: 0 0 0 3px rgba(255, 107, 1, 0.2);
            border-color: var(--primary-color);
            outline: none;
        }

        .back-btn {
            padding: 1rem 2rem;
            background-color: #4a4a4a;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
            text-decoration: none;
            display: inline-block;
        }

        .back-btn:hover {
            background-color: var(--primary-color);
        }

        .btn-update {
            background: var(--primary-color);
            color: white;
            padding: 0.8rem 2rem;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-update:hover {
            transform: translateY(-2px);
            background: #ff8533;
            box-shadow: 0 4px 15px rgba(255, 107, 1, 0.3);
        }

        .alert {
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1.5rem;
            border: none;
        }

        .alert-success {
            background: rgba(25, 135, 84, 0.1);
            color: #198754;
        }

        .alert-danger {
            background: rgba(220, 53, 69, 0.1);
            color: #dc3545;
        }

        .logout-btn {
            padding: 0.5rem 1.5rem;
            background-color: #dc3545;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.3s ease;
            height: fit-content;
        }

        .logout-btn:hover {
            background-color: #bb2d3b;
            transform: translateY(-2px);
        }

        .btn-password {
            background: #4a4a4a;
            color: white;
            padding: 0.8rem 2rem;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .btn-password:hover {
            transform: translateY(-2px);
            background: #333333;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
    </style>
</head>
<body>
    <header>
        <div class="header-left">
            <a href="dashboard.php" class="back-btn">← Back to Dashboard</a>
        </div>
        <img src="Logo.png" alt="Shield" class="logo">
        <div class="header-right">
            <div class="subscription-status">
                <?php echo htmlspecialchars($_SESSION['user_plan']); ?> PLAN
            </div>
            <form method="POST" action="logout.php" style="margin: 0;">
                <button type="submit" class="logout-btn">Logout</button>
            </form>
        </div>
    </header>

    <div class="container">
        <div class="profile-form">
            <?php if (isset($successMessage)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle me-2"></i>
                    <?php echo $successMessage; ?>
                </div>
            <?php endif; ?>
            
            <?php if (isset($errorMessage)): ?>
                <div class="alert alert-danger">
                    <i class="fas fa-exclamation-circle me-2"></i>
                    <?php echo $errorMessage; ?>
                </div>
            <?php endif; ?>

            <form method="POST" action="">
                <div class="row">
                    <div class="col-md-6">
                        <div class="form-group">
                            <label class="form-label">First Name</label>
                            <input type="text" class="form-control" name="firstName" 
                                   value="<?php echo htmlspecialchars($userDetails['FirstName']); ?>" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Last Name</label>
                            <input type="text" class="form-control" name="lastName" 
                                   value="<?php echo htmlspecialchars($userDetails['LastName']); ?>" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Email</label>
                            <input type="email" class="form-control" name="email" 
                                   value="<?php echo htmlspecialchars($userDetails['Email']); ?>" required>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Username</label>
                            <input type="text" class="form-control" value="<?php echo htmlspecialchars($userDetails['Username']); ?>" readonly>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Company Name</label>
                            <input type="text" class="form-control" value="<?php echo htmlspecialchars($userDetails['CompanyName']); ?>" readonly>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="form-group">
                            <label class="form-label">Country Code</label>
                            <input type="text" class="form-control" name="countryCode" 
                                   value="<?php echo htmlspecialchars($userDetails['CountryCode']); ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Area Code</label>
                            <input type="text" class="form-control" name="areaCode" 
                                   value="<?php echo htmlspecialchars($userDetails['AreaCode']); ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Phone Number</label>
                            <input type="text" class="form-control" name="phoneNumber" 
                                   value="<?php echo htmlspecialchars($userDetails['PhoneNumber']); ?>">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Address</label>
                            <textarea class="form-control" name="address" rows="4"><?php echo htmlspecialchars($userDetails['Address']); ?></textarea>
                        </div>
                    </div>
                </div>
                
                <div class="mt-4 border-top pt-4">
                    <h4 class="mb-3">Change Password</h4>
                    <div class="row">
                        <div class="col-md-4">
                            <div class="form-group">
                                <label class="form-label">Current Password</label>
                                <input type="password" class="form-control" name="current_password">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-group">
                                <label class="form-label">New Password</label>
                                <input type="password" class="form-control" name="new_password">
                            </div>
                        </div>
                        <div class="col-md-4">
                            <div class="form-group">
                                <label class="form-label">Confirm New Password</label>
                                <input type="password" class="form-control" name="confirm_password">
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="text-end mt-4">
                    <button type="submit" name="update_profile" class="btn-update me-2">
                        <i class="fas fa-save me-2"></i>
                        Update Profile
                    </button>
                    <button type="submit" name="change_password" class="btn-password">
                        <i class="fas fa-key me-2"></i>
                        Change Password
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
