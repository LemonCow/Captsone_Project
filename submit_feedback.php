<?php
// Database connection parameters
$servername = "localhost";
$username = "reader";
$password = "checkout";
$database = "sakila";

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get form data
$username = $_POST['username'];
$email = $_POST['email'];
$helpful = $_POST['agree1'];
$reason = $_POST['message1'];
$easier = $_POST['agree2'];
$reason_easier = $_POST['message2'];
$suggestions = $_POST['message'];

// Prepare SQL statement
$sql = "INSERT INTO feedback (username, email, helpful, reason, easier, reason_easier, suggestions) VALUES (?, ?, ?, ?, ?, ?, ?)";
$stmt = $conn->prepare($sql);
$stmt->bind_param("sssssss", $username, $email, $helpful, $reason, $easier, $reason_easier, $suggestions);

// Execute SQL statement
if ($stmt->execute() === TRUE) {
    // Redirect to feedback page
    header("Location: https://www.savi-scanneronline.net/feedback.html");
    exit(); // Ensure the script stops executing after the redirect
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

// Close connection
$stmt->close();
$conn->close();
?>

