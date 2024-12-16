<?php
session_start();
// At the beginning of your index.php
$env = parse_ini_file('.env');
$SALT = $env['SALT'];
$admin_username = getenv('ADMIN_USERNAME') ?: 'admin';
$admin_password = getenv('ADMIN_PASSWORD') ?: 'password';

$user_data_file = __DIR__ . '/user_data.json';

function generate_user_id($username)
{
    return hash('sha256', $username . time() . random_bytes(16));
}

function load_users()
{
    global $user_data_file;
    if (file_exists($user_data_file)) {
        $data = file_get_contents($user_data_file);
        return json_decode($data, true) ?: [];
    }
    return [];
}
$original_admin_id = hash('sha256', $admin_username . $SALT);

function is_original_admin()
{
    global $original_admin_id;
    return isset($_SESSION['user_id']) && $_SESSION['user_id'] === $original_admin_id;
}

function save_users($users)
{
    global $user_data_file;
    file_put_contents($user_data_file, json_encode($users));
}

function get_user_by_username($username)
{
    global $users;
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            return $user;
        }
    }
    return null;
}

$users = load_users();

function is_logged_in()
{
    return isset($_SESSION['user_id']);
}

function is_admin()
{
    global $users;
    return isset($_SESSION['user_id']) && $users[$_SESSION['user_id']]['role'] === 'admin';
}

function get_user($id)
{
    global $users;
    return $users[$id] ?? null;
}

function is_bot_admin()
{
    return is_original_admin(); // EDIT LOGIC FOR BOT ADMIN USER CHECK,
    return isset($_SESSION['user_id']) && isset($_GET['bot_token']) && $_GET['bot_token'] === 'special_bot_token';
}

function handleUploadError($error)
{
    switch ($error) {
        case UPLOAD_ERR_INI_SIZE:
            return "The uploaded file exceeds the upload_max_filesize directive in php.ini";
        case UPLOAD_ERR_FORM_SIZE:
            return "The uploaded file exceeds the MAX_FILE_SIZE directive in the HTML form";
        case UPLOAD_ERR_PARTIAL:
            return "The uploaded file was only partially uploaded";
        case UPLOAD_ERR_NO_FILE:
            return "No file was uploaded";
        case UPLOAD_ERR_NO_TMP_DIR:
            return "Missing a temporary folder";
        case UPLOAD_ERR_CANT_WRITE:
            return "Failed to write file to disk";
        case UPLOAD_ERR_EXTENSION:
            return "A PHP extension stopped the file upload";
        default:
            return "Unknown upload error";
    }
}

$route = $_GET['route'] ?? 'home';

header("Content-Security-Policy: script-src 'self'");

switch ($route) {
    case 'login':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            $user = get_user_by_username($username);
            if ($user && $user['password'] === $password) {
                $_SESSION['user_id'] = $user['id'];
                header('Location: index.php');
                exit;
            }
            $error = "Invalid credentials";
        }
        include 'templates/login.php';
        break;

    case 'register':
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $username = trim($_POST['username']);
            $password = trim($_POST['password']);

            // Load users and validate
            $users = load_users();
            $error = '';

            if (empty($username) || empty($password)) {
                $error = "Username and password are required.";
            } else {
                foreach ($users as $user) {
                    if ($user['username'] === $username) {
                        $error = "Username already exists.";
                        break;
                    }
                }
                if (!$error) {
                    $user_id = generate_user_id($username);
                    $users[$user_id] = [
                        'id' => $user_id,
                        'username' => $username,
                        'password' => $password,
                        'role' => 'agent',
                        'signature' => '',
                    ];

                    save_users($users);
                    $success = "Registration successful!";
                    header("Location: index.php?route=login");
                }
            }
        }
        include 'templates/register.php';
        break;

    case 'logout':
        session_destroy();
        header('Location: index.php');
        exit;

    case 'message':
        ob_start(); // Start output buffering

        if (!is_logged_in()) {
            header('Location: index.php?route=login');
            exit;
        }

        $requested_user_id = $_GET['user_id'] ?? null;
        $target_user_id = is_bot_admin() && $requested_user_id ? $requested_user_id : $_SESSION['user_id'];
        $target_user = get_user($target_user_id);

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $signature = $_POST['signature'] ?? '';
            $users[$_SESSION['user_id']]['signature'] = $signature;

            if (isset($_FILES['userfile'])) {
                if ($_FILES['userfile']['error'] === UPLOAD_ERR_OK) {
                    try {
                        $uploadDir = __DIR__ . '/uploads/';
                        $fileName = basename($_FILES['userfile']['name']);

                        // Append the first 10 characters of user_id to the file name
                        $user_id_prefix = substr($_SESSION['user_id'], 0, 10);
                        $newFileName = $user_id_prefix . '.' . $fileName;
                        $uploadFile = $uploadDir . $newFileName;

                        // Check if directory exists, if not create it
                        if (!is_dir($uploadDir)) {
                            mkdir($uploadDir, 0777, true);
                        }

                        // Check if file already exists
                        if (file_exists($uploadFile)) {
                            $uploadStatus = "A file with this name already exists.";
                        } else {
                            if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadFile)) {
                                chmod($uploadFile, 0444);
                                $users[$_SESSION['user_id']]['file'] = '/uploads/' . $newFileName;
                                $uploadStatus = "File uploaded successfully: " . $uploadFile;
                            } else {
                                throw new Exception("Failed to move uploaded file");
                            }
                        }
                    } catch (Exception $e) {
                        error_log("Upload error: " . $e->getMessage());
                        $uploadStatus = "Upload failed: " . $e->getMessage();
                    }
                } else {
                    $uploadStatus = handleUploadError($_FILES['userfile']['error']);
                }
            } else {
                $uploadStatus = "No file uploaded or there was an error.";
            }

            save_users($users);
            ob_end_clean(); // Clear output buffer
            header('Location: index.php');
            exit;
        }

        include 'templates/message.php';
        break;

    case 'admin':
        if (!is_original_admin()) {
            header('Location: index.php');
            exit;
        }
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $userId = $_POST['user_id'] ?? '';
            $newRole = $_POST['role'] ?? '';
            if (isset($users[$userId])) {
                $users[$userId]['role'] = $newRole;
                save_users($users);
                echo "User role updated";
            } else {
                echo "User not found";
            }
        }
        include 'templates/admin.php';
        break;

    case 'flag':
        if (!is_logged_in() || !is_admin()) {
            header('Location: index.php');
            exit;
        }
        include 'templates/flag.php';
        break;

    default:
        if (is_logged_in()) {
            $users = load_users();
            include 'templates/home.php';
        } else {
            header('Location: index.php?route=login');
        }
        break;
}

function template_header($title)
{
    echo "<!DOCTYPE html>
    <html>
    <head>
        <title>$title</title>
        <link rel='stylesheet' type='text/css' href='/css/styles.css'>
    </head>
    <body>";
}

function template_footer()
{
    echo "</body></html>";
}
