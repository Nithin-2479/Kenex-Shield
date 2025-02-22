<?php
include 'database.php';


if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $response = ['success' => false, 'message' => ''];

    try {
        // Validate and sanitize input
        $firstName = filter_input(INPUT_POST, 'first-name', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $lastName = filter_input(INPUT_POST, 'last-name', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $countryCode = filter_input(INPUT_POST, 'country-code', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $areaCode = filter_input(INPUT_POST, 'area-code', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $phoneNumber = filter_input(INPUT_POST, 'phone', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
        $username = filter_input(INPUT_POST, 'username', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $password = $_POST['password'] ?? '';
        $confirmPassword = $_POST['confirm-password'] ?? '';
        $companyName = filter_input(INPUT_POST, 'company', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $address = filter_input(INPUT_POST, 'address', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $plan = filter_input(INPUT_POST, 'plan', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        $billingCycle = filter_input(INPUT_POST, 'billing', FILTER_SANITIZE_FULL_SPECIAL_CHARS);

        // Calculate dates based on billing cycle
        $startDate = date('Y-m-d'); // Today's date
        $endDate = '';
        
        if ($billingCycle === 'monthly') {
            $endDate = date('Y-m-d', strtotime('+1 month -1 day'));
        } else if ($billingCycle === 'yearly') {
            $endDate = date('Y-m-d', strtotime('+1 year -1 day'));
        }

        // Validate required fields
        if (!$firstName || !$lastName || !$email || !$username || !$password || !$confirmPassword) {
            throw new Exception("All required fields must be filled out");
        }

        // Validate email
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new Exception("Invalid email format");
        }

        // Validate password
        if (strlen($password) < 8) {
            throw new Exception("Password must be at least 8 characters long");
        }

        if ($password !== $confirmPassword) {
            throw new Exception("Passwords do not match");
        }

        // Start transaction
        $pdo->beginTransaction();

        // Check existing user
        $stmt = $pdo->prepare("SELECT COUNT(*) FROM UserDetails WHERE Username = ? OR Email = ?");
        $stmt->execute([$username, $email]);
        
        if ($stmt->fetchColumn() > 0) {
            throw new Exception("Username or email already exists");
        }

        // Insert user
        $stmt = $pdo->prepare("INSERT INTO UserDetails (FirstName, LastName, CountryCode, 
            AreaCode, PhoneNumber, Email, Username, PasswordHash, CompanyName, Address) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        $stmt->execute([
            $firstName, 
            $lastName, 
            $countryCode, 
            $areaCode, 
            $phoneNumber,
            $email, 
            $username, 
            password_hash($password, PASSWORD_DEFAULT),
            $companyName, 
            $address
        ]);

        $userId = $pdo->lastInsertId();

        // Insert plan with billing cycle dates
        $stmt = $pdo->prepare("INSERT INTO Plan (UserID, PlanName, BillingCycle, 
            StartDate, EndDate, Status) VALUES (?, ?, ?, ?, ?, 'active')");

        $stmt->execute([
            $userId,
            $plan,
            $billingCycle,
            $startDate,
            $endDate
        ]);

        $pdo->commit();
        $response['success'] = true;
        $response['message'] = 'Registration successful';

    } catch (Exception $e) {
        if ($pdo && $pdo->inTransaction()) {
            $pdo->rollBack();
        }
        error_log("Registration Error: " . $e->getMessage());
        $response['message'] = $e->getMessage();
    }

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
    <title>Kenexoft SHIELD - Registration</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f4f4f4;
        }
        .container {
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 6px 8px rgb(255, 119, 0);
            margin-bottom: 30px;
        }
        header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            max-width: 200px;
            height: auto;
        }
        .plans-wrapper {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .plan-card {
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            background-color: white;
            transition: transform 0.2s;
        }
        .plan-card:hover {
            transform: scale(1.05);
        }
        .registration-form {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
        }
        .form-group {
            margin-bottom: 15px;
        }
        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }

        .form-group.row {
                    display: flex;
                    gap: 10px;
                }
        
                .form-group.row input {
                    flex: 1;
                }
       
        .form-group input,
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
            box-sizing: border-box;
        }
        .form-group input[readonly] {
            background-color: #f5f5f5;
            cursor: not-allowed;
        }
        .phone-container {
            display: grid;
            grid-template-columns: 80px 80px 1fr;
            gap: 10px;
        }
        .billing-options {
            display: flex;
            gap: 20px;
            margin-top: 5px;
        }
        .billing-options label {
            display: inline-flex;
            align-items: center;
            cursor: pointer;
        }
        .date-container {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
        }
        .form-actions {
            grid-column: span 2;
            padding-top: 20px;
            border-top: 1px solid #ddd;
        }
        .register-button {
            background-color: #2c5282;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }
        .register-button:hover {
            background-color:rgb(255, 119, 0);
        }
        .error-message {
            color: #c53030;
            font-size: 0.9em;
            margin-top: 5px;
        }
        .success-message {
            color: #2f855a;
            font-size: 0.9em;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <img src="Logo.png" alt="Kenexoft Logo" class="logo">
            <h1>Kenexoft - SHIELD</h1>
            <p>Secure Hybrid Intelligent Engine for Layered Defense</p>
        </header>

        <form id="registration-form" method="POST">
            <div class="registration-form">
                <!-- Left column -->
                <div class="form-column">
                    <div class="form-group">
                        <label for="first-name">First Name *</label>
                        <input type="text" id="first-name" name="first-name" required>
                    </div>
                    <div class="form-group">
                        <label for="last-name">Last Name *</label>
                        <input type="text" id="last-name" name="last-name" required>
                    </div>
                    <div class="form-group">
                        <label for="username">Username *</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password *</label>
                        <input type="password" id="password" name="password" required minlength="8">
                        <div class="error-message" id="password-error"></div>
                    </div>
                    <div class="form-group">
                        <label for="confirm-password">Confirm Password *</label>
                        <input type="password" id="confirm-password" name="confirm-password" required>
                        <div class="error-message" id="confirm-password-error"></div>
                    </div>
                </div>

                <!-- Right column -->
                <div class="form-column">
                    <div class="form-group">
                        <label for="email">Email *</label>
                        <input type="email" id="email" name="email" required>
                        <div class="error-message" id="email-error"></div>
                    </div>
                    <div class="form-group">
                        
                        <div class="form-group row">
                                <div>
                                    <label for="country-code">Country Code:</label>
                                    <input type="text" id="country-code" name="country-code" required>
                                </div>
                                <div>
                                    <label for="area-code">Area Code:</label>
                                    <input type="text" id="area-code" name="area-code" required>
                                </div>
                                <div>
                                    <label for="phone">Phone Number:</label>
                                    <input type="text" id="phone" name="phone" required>
                                </div>
                                
                            </div>
                    </div>
                    <div class="form-group">
                        <label for="company">Company Name</label>
                        <input type="text" id="company" name="company">
                    </div>
                    <div class="form-group">
                        <label for="address">Company Address</label>
                        <textarea id="address" name="address" rows="3"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="plan">Select Plan *</label>
                        <select id="plan" name="plan" required>
                            <option value="">Select a Plan</option>
                            <option value="essential">SHIELD - Essential ($50/mo)</option>
                            <option value="professional">SHIELD - Professional ($45/mo)</option>
                            <option value="enterprise">SHIELD - Enterprise ($70/mo)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Billing Cycle *</label>
                        <div class="billing-options">
                            <label>
                                <input type="radio" name="billing" value="monthly" checked>
                                Monthly
                            </label>
                            <label>
                                <input type="radio" name="billing" value="yearly">
                                Yearly
                            </label>
                        </div>
                    </div>
                    <div class="date-container">
                        <div class="form-group">
                            <label>Start Date</label>
                            <input type="date" id="start-date" name="start-date" readonly>
                        </div>
                        <div class="form-group">
                            <label>End Date</label>
                            <input type="date" id="end-date" name="end-date" readonly>
                        </div>
                    </div>
                </div>

                <div class="form-actions">
                    <div class="form-group">
                        <input type="checkbox" id="terms" name="terms" required>
                        <label for="terms">I agree to Terms of Service *</label>
                    </div>
                    <button type="submit" class="register-button">Register</button>
                    <div class="error-message" id="form-error"></div>
                    <div class="success-message" id="form-success"></div>
                </div>
                <div>
                    <p >Already have an account? <a href="login.php"><u>Login</u></a></p>
                </div>
            </div>
        </form>
    </div>

    <script>
   document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('registration-form');
    const startDateInput = document.getElementById('start-date');
    const endDateInput = document.getElementById('end-date');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm-password');
    const formError = document.getElementById('form-error');
    const formSuccess = document.getElementById('form-success');
    const planSelect = document.getElementById('plan');
    const billingInputs = document.getElementsByName('billing');

    const PRICES = {
        Essential: { monthly: 50, yearly: 500 },
        Professional: { monthly: 45, yearly: 450 },
        Enterprise: { monthly: 70, yearly: 700 }
    };

    // Set initial dates
    function updateDates() {
        const today = new Date();
        startDateInput.value = today.toISOString().split('T')[0];
        
        const selectedBilling = document.querySelector('input[name="billing"]:checked').value;
        const endDate = new Date(today);
        
        if (selectedBilling === 'monthly') {
            endDate.setMonth(endDate.getMonth() + 1);
            endDate.setDate(endDate.getDate() - 1);
        } else {
            endDate.setFullYear(endDate.getFullYear() + 1);
            endDate.setDate(endDate.getDate() - 1);
        }
        
        endDateInput.value = endDate.toISOString().split('T')[0];
    }

    // Update dates when billing cycle changes
    document.querySelectorAll('input[name="billing"]').forEach(input => {
        input.addEventListener('change', updateDates);
    });

    // Password validation
    function validatePassword() {
        const password = passwordInput.value;
        const passwordError = document.getElementById('password-error');
        
        if (password.length < 8) {
            passwordError.textContent = 'Password must be at least 8 characters long';
            return false;
        }
        
        if (!/[A-Z]/.test(password)) {
            passwordError.textContent = 'Password must contain at least one uppercase letter';
            return false;
        }
        
        if (!/[a-z]/.test(password)) {
            passwordError.textContent = 'Password must contain at least one lowercase letter';
            return false;
        }
        
        if (!/[0-9]/.test(password)) {
            passwordError.textContent = 'Password must contain at least one number';
            return false;
        }
        
        passwordError.textContent = '';
        return true;
    }

    // Confirm password validation
    function validateConfirmPassword() {
        const confirmPasswordError = document.getElementById('confirm-password-error');
        
        if (passwordInput.value !== confirmPasswordInput.value) {
            confirmPasswordError.textContent = 'Passwords do not match';
            return false;
        }
        
        confirmPasswordError.textContent = '';
        return true;
    }

    // Email validation
    function validateEmail() {
        const email = document.getElementById('email').value;
        const emailError = document.getElementById('email-error');
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (!emailRegex.test(email)) {
            emailError.textContent = 'Please enter a valid email address';
            return false;
        }
        
        emailError.textContent = '';
        return true;
    }

    // Phone number validation
    function validatePhone() {
        const countryCode = document.getElementById('country-code').value;
        const areaCode = document.getElementById('area-code').value;
        const phone = document.getElementById('phone').value;
        
        return countryCode && areaCode && phone;
    }

    // Form submission handler
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Clear previous messages
        formError.textContent = '';
        formSuccess.textContent = '';

        // Validate all fields
        if (!validatePassword() || !validateConfirmPassword() || !validateEmail() || !validatePhone()) {
            formError.textContent = 'Please correct the errors in the form';
            return;
        }

        try {
            const formData = new FormData(form);
            const response = await fetch(window.location.href, {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (result.success) {
                formSuccess.textContent = result.message;
                form.reset();
                updateDates();
            } else {
                formError.textContent = result.message || 'Registration failed. Please try again.';
            }
        } catch (error) {
            formError.textContent = 'An error occurred. Please try again later.';
            console.error('Registration error:', error);
        }
    });

    // Add input event listeners for real-time validation
    passwordInput.addEventListener('input', validatePassword);
    confirmPasswordInput.addEventListener('input', validateConfirmPassword);
    document.getElementById('email').addEventListener('input', validateEmail);

    // Initialize dates on page load
    updateDates();
});
</script>
</body>
</html>