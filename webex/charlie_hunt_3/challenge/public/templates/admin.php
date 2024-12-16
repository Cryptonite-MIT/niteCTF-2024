<?php
session_start();


// Redirect if the user is not logged in or is not the original admin
if (!is_logged_in() || !is_original_admin()) {
    header('Location: index.php');
    exit;
}

template_header('Admin Panel');
?>

<h1>Admin Panel</h1>

<form method="post">
    <select name="user_id">
        <?php foreach ($users as $user): ?>
            <option value="<?php echo $user['id']; ?>"><?php echo htmlspecialchars($user['username']); ?></option>
        <?php endforeach; ?>
    </select>

    <select name="role">
        <option value="agent">Agent</option>
        <option value="admin">Admin</option>
    </select>

    <input type="submit" value="Update Role">
</form>

<?php
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userId = $_POST['user_id'] ?? '';
    $newRole = $_POST['role'] ?? '';

    if (isset($users[$userId])) {
        $users[$userId]['role'] = $newRole;
        $_SESSION['users'] = $users; 
        echo "User role updated successfully!";
    } else {
        echo "User not found.";
    }
}
?>

<p><a href="index.php">Back to Home</a></p>
<?php template_footer(); ?>
