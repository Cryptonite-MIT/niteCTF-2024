<?php template_header('Edit/View Signature');?>
<h1><?php echo htmlspecialchars($target_user['username']); ?>'s Message</h1>
<?php if ($target_user_id === $_SESSION['user_id'] || is_bot_admin()): ?>
    <form method="post" enctype="multipart/form-data" onsubmit="return validateForm()">
        <div class="signature-form">
            <div class="message-box">
                <label for="message">Your Message:</label>
                <textarea
                    name="message"
                    id="message"
                    rows="5"
                    cols="2"
                    placeholder="Enter your message here"></textarea>
            </div>
            <label for="signature">Your Signature:</label>
            <textarea
                name="signature"
                id="signature"
                rows="2"
                cols="50"
            ><?php echo htmlspecialchars($target_user['signature']); ?></textarea>
            <div class="file-upload" style="display: none;">
                <label for="fileInput"></label>
                <input type="file" name="userfile" id="fileInput" accept=".md">
            </div>
            <input type="hidden" id="uploadedFileUrl" name="uploadedFileUrl">
            <input type="hidden" name="user_hash" value="<?php echo htmlspecialchars($_SESSION['user_id']); ?>">
            <div class="buttons">
                <input type="submit" value="Send your special message!">
                <a href="index.php" class="button">Back to Home</a>
            </div>
        </div>
    </form>
    <div id="uploadStatus" class="status-message"></div>
    <div class="signature-preview" style="margin-top: 20px;">
        <h3>Signature Preview:</h3>
        <div class="preview-box">
            <?php
echo $target_user['signature'] ?: '<em>No signature set</em>';
?>
        </div>
    </div>
<?php else: ?>
    <p><a href="index.php">Back to Home</a></p>
<?php endif;?>
<script>
function validateForm() {
    var fileInput = document.getElementById('fileInput');
    var signatureInput = document.getElementById('signature');
    var file = fileInput.files[0];


    if (!signatureInput.value.trim() && !file) {
        alert('Please fill required fields!');
        return false;
    }
    if (file) {

        var fileName = file.name;
        var fileExt = fileName.split('.').pop().toLowerCase();

        if (fileExt !== 'md') {
            alert('Only .md files are allowed!');
            return false;
        }

        if (file.size > 5120) {
            alert('File size must be under 5KB!');
            return false;
        }
    }

    return true;
}
</script>
<?php template_footer();?>
