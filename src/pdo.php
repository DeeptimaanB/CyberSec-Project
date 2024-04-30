<?php

// Database configuration
$host = 'db';
$dbname = 'php_docker';
$user = 'php_docker';
$pass = 'php_docker';

$pdo = new PDO('mysql:host='.$host.';dbname='.$dbname, $user, $pass);
$pdo -> setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);