<?php template_header('Login'); ?>
<h1>Login</h1>
<form action="index.php?route=login" method="POST">
    <div class="form-group">
        <label for="username">Username:</label>
        <input type="text" id="username" name="username" placeholder="Username" required>
    </div>
    
    <div class="form-group">
        <label for="password">Password:</label>
        <input type="password" id="password" name="password" placeholder="Password" required>
    </div>
    
    <div class="form-group">
        <input type="submit" value="Login">
    </div>
</form>

<p>Don't have an account? <a href="index.php?route=register">Register here</a>.</p>
<?php if (isset($error)): ?>
    <p style="color: red;"><?php echo $error; ?></p>
<?php endif; ?>
<?php template_footer(); ?>