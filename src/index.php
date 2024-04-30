<?php

// Database configuration
$host = 'db';
$dbname = 'php_docker';
$user = 'php_docker';
$pass = 'php_docker';

// Establish database connection
try {
    $pdo = new PDO($dsn, $user, $pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("ERROR: Could not connect. " . $e->getMessage());
}

// Functions for user operations
function getUsers($pdo) {
    $stmt = $pdo->query("SELECT * FROM users");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getUserDetails($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function createUser($pdo, $username, $password) {
    $stmt = $pdo->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, $password]);
}

function deleteUser($pdo, $id) {
    $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
    $stmt->execute([$id]);
}

// Handle requests
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['create'])) {
        createUser($pdo, $_POST['username'], $_POST['password']);
        header('Location: user_manager.php');
        exit();
    } elseif (isset($_POST['delete'])) {
        deleteUser($pdo, $_POST['user_id']);
        header('Location: user_manager.php');
        exit();
    }
}

// Get all users to display
$users = getUsers($pdo);

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>User Manager</title>
</head>
<body>
    <h1>User Manager</h1>

    <h2>Create New User</h2>
    <form action="user_manager.php" method="post">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="hidden" name="create">
        <button type="submit">Create</button>
    </form>

    <h2>Current Users</h2>
    <ul>
        <?php foreach ($users as $user): ?>
            <li>
                <?= htmlspecialchars($user['username']) ?>
                - <form style="display: inline;" action="user_manager.php" method="post">
                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                    <input type="hidden" name="delete">
                    <button type="submit">Delete</button>
                </form>
            </li>
        <?php endforeach; ?>
    </ul>
</body>
</html>
