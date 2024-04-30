<?php

require_once "pdo.php";


// Functions for user operations
function getUsers($pdo) {
    $stmt = $pdo->query("SELECT * FROM user_keys");
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function getUserDetails($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM user_keys WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function createUser($pdo, $username, $password) {
    $password = md5($password);
    $stmt = $pdo->prepare("INSERT INTO user_keys (id, password) VALUES (?, ?)");
    $stmt->execute([$username, $password]);
}

function deleteUser($pdo, $id) {
    $stmt = $pdo->prepare("DELETE FROM user_keys WHERE id = ?");
    $stmt->execute([$id]);
}

// Handle requests
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    if (isset($_POST['username']) && isset($_POST['password'])) {
        createUser($pdo, $_POST['username'], $_POST['password']);
        header('Location: index.php');
        exit();
    } elseif (isset($_POST['delete'])) {
        deleteUser($pdo, $_POST['user_id']);
        header('Location: index.php');
        exit();
    }
}

// Get all user_keys to display
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
    <form action="index.php" method="post">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <input type="hidden" name="create">
        <button type="submit">Create</button>
    </form>

    <h2>Current User_keys</h2>
    <ul>
        <?php foreach ($users as $user): ?>
            <li>
                <?= htmlspecialchars($user['id']) ?>
                - <form style="display: inline;" action="index.php" method="post">
                    <input type="hidden" name="user_id" value="<?= $user['id'] ?>">
                    <input type="hidden" name="delete">
                    <button type="submit">Delete</button>
                </form>
            </li>
        <?php endforeach; ?>
    </ul>
</body>
</html>
