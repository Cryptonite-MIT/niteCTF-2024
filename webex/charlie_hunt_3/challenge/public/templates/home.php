<?php template_header('Home'); ?>


<div style="background: linear-gradient(135deg, #47302B, #2E1810); min-height: 100vh; color: #FFECD9; font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center;">
    

    <div style="max-width: 1000px; width: 90%; margin: 20px; background-color: #FFECD9; color: #2E1810; border-radius: 8px; overflow: hidden; box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2); display: flex;">


        <aside style="width: 200px; background-color: #2E1810; color: #FFECD9; padding: 20px; box-shadow: inset -2px 0 4px rgba(0, 0, 0, 0.1);">
            <h3 style="color: #FFECD9; margin-bottom: 15px;">Menu</h3>
            <a href="index.php?route=settings" style="color: #FFE6CC; display: block; margin-bottom: 10px; text-decoration: none;">Settings</a>
            <a href="index.php?route=profile" style="color: #FFE6CC; display: block; margin-bottom: 10px; text-decoration: none;">Profile</a>
            <a href="index.php?route=help" style="color: #FFE6CC; display: block; margin-bottom: 10px; text-decoration: none;">Help</a>
        </aside>

   
        <div style="flex-grow: 1; padding: 20px;">


            <div style="display: flex; justify-content: space-between; margin-bottom: 20px; background-color: #47302B; padding: 10px 20px; color: #FFECD9; border-radius: 4px;">
                <span>Messaging App</span>
                <a href="index.php?route=logout" style="color: #FFECD9; text-decoration: none;">Logout</a>
            </div>


            <div style="background-color: #FFE6CC; padding: 20px; border-radius: 4px; border: 1px solid #8B4513;">
                <h1 style="color: #47302B; margin-bottom: 15px;">Welcome, <?php echo htmlspecialchars($users[$_SESSION['user_id']]['username']); ?></h1>
                <p>Your role: <?php echo htmlspecialchars($users[$_SESSION['user_id']]['role']); ?></p>
            </div>


            <?php
            $current_user_id = $_SESSION['user_id'] ?? null;

            if ($current_user_id !== null && isset($users[$current_user_id])) {
                $user = $users[$current_user_id];
                ?>
                <div style="background-color: #FFECD9; border: 1px solid #8B4513; border-radius: 4px; padding: 15px; margin-top: 20px; box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);">
                    <h3 style="color: #47302B; margin-bottom: 10px;">Your UserID</h3>
                    <small>User ID: <?php echo htmlspecialchars($current_user_id); ?></small>
                </div>
                <?php
            } else {
                echo "<p style='color: #47302B; background-color: #FFE6CC; padding: 8px; border-radius: 4px; margin-top: 20px;'>User not found or not logged in.</p>";
            }
            ?>

            <div style="display: flex; justify-content: space-between; margin-top: 20px;">
            <a href="index.php?route=message&user_id=<?php echo htmlspecialchars($_SESSION['user_id']); ?>" 
        style="background-color: #47302B; color: #FFECD9; padding: 10px 15px; text-decoration: none; border-radius: 4px; text-align: center; transition: background-color 0.3s ease;">
            Send a Message
            </a></div>


            <?php if (is_admin()): ?>
                <div style="display: flex; gap: 15px; justify-content: flex-end; margin-top: 10px;">
                    <?php if (is_original_admin()): ?>
                        <a href="index.php?route=admin" style="font-size: 0.9em; background-color: #FFE6CC; color: #2E1810; padding: 8px 15px; border: 1px solid #8B4513; border-radius: 4px; text-decoration: none; transition: background-color 0.3s ease;">Admin Panel</a>
                    <?php endif; ?>
                    <a href="index.php?route=flag" style="font-size: 0.9em; background-color: #FFE6CC; color: #2E1810; padding: 8px 15px; border: 1px solid #8B4513; border-radius: 4px; text-decoration: none; transition: background-color 0.3s ease;">Get Flag!</a>
                </div>
            <?php endif; ?>
        </div>
    </div>
</div>

<?php template_footer(); ?>