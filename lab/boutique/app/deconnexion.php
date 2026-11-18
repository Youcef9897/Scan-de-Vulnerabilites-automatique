<?php
require __DIR__ . '/inc/db.php';
$_SESSION = [];
session_destroy();
header('Location: index.php');
