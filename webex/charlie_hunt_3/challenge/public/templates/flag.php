<?php
session_start();

// Check if user is logged in and is an admin
if (!is_logged_in() || !is_admin()) {
    // Redirect to login page if not authorized
    header('Location: login.php');
    exit();
}

// Only get flag if user is authorized
$FLAG = getenv('FLAG');
?>
<!DOCTYPE html>
<html>
<head>
    <title>Admin Messages [CONFIDENTIAL]</title>
    <link rel="stylesheet" type="text/css" href="/css/styles.css">
</head>
<body>
    <div class="container">
        <h1>Admin Messages Raw</h1>
        
        <div class="message-log">
            <div class="message">
                <span class="timestamp">2024-03-15 21:14:32</span>
                <span class="sender">Handler:</span> Charlie is secure. How are things going ?
            </div>
            
            <div class="message">
                <span class="timestamp">2024-03-15 21:15:01</span>
                <span class="sender">EvilTwin:</span> People still think I'm him. And Charlie never realized his own twin has come back for revenge.Keep him secure.
            </div>
            
            <div class="message">
                <span class="timestamp">2024-03-15 21:20:15</span>
                <span class="sender">Handler:</span> Don't worry. He's safely locked away at:
            </div>

            <?php
            if (isset($FLAG)) {
                echo "<div class='message flag'><span class='sender'>LOCATION:</span> " . htmlspecialchars($FLAG) . "</div>";
            } else {
                echo "<p class='error'>Error: Location data corrupted. Contact system administrator.</p>";
            }
            ?>
        </div>
        <a href="index.php" class="back-link">Back to Home</a>
    </div>
</body>
</html>