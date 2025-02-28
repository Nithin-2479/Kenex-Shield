-- Create UserDetails table
CREATE TABLE UserDetails (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    FirstName VARCHAR(50) NOT NULL,
    LastName VARCHAR(50) NOT NULL,
    CountryCode VARCHAR(5),
    AreaCode VARCHAR(6),
    PhoneNumber VARCHAR(15),
    Email VARCHAR(100) UNIQUE NOT NULL,
    Username VARCHAR(50) UNIQUE NOT NULL,
    PasswordHash VARCHAR(255) NOT NULL,
    CompanyName VARCHAR(100),
    Address TEXT,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Plan table
CREATE TABLE Plan (
    PlanID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    PlanName VARCHAR(50) NOT NULL,
    BillingCycle VARCHAR(10) NOT NULL,
    StartDate DATE NOT NULL,
    EndDate DATE NOT NULL,
    Status VARCHAR(20) NOT NULL,
    FOREIGN KEY (UserID) REFERENCES UserDetails(UserID)
);

-- Create UploadLogs table
CREATE TABLE UploadLogs (
    ID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    LogType VARCHAR(50) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    filedata LONGBLOB,
    TimeStamps VARCHAR(255),
    FOREIGN KEY (UserID) REFERENCES UserDetails(UserID)
);

-- Create log_Analysis table
CREATE TABLE log_Analysis (
    id INT PRIMARY KEY AUTO_INCREMENT,
    LogID INT NOT NULL,
    Total_logs INT NOT NULL,
    Malicious_Events INT NOT NULL,
    GraphData LONGBLOB,
    Alert_level ENUM('Low', 'Medium', 'High') NOT NULL,
    Source_Ip LONGBLOB,
    Log_Type VARCHAR(50) NOT NULL,
    FOREIGN KEY (LogID) REFERENCES UploadLogs(ID)
);

DELIMITER //

CREATE EVENT UpdatePlanStatus
ON SCHEDULE EVERY 1 DAY
DO
BEGIN
    UPDATE Plan
    SET Status = 
        CASE 
            WHEN CURDATE() < StartDate THEN 'inactive'
            WHEN CURDATE() BETWEEN StartDate AND EndDate THEN 'active'
            WHEN CURDATE() > EndDate THEN 'expired'
        END;
END //

DELIMITER ;