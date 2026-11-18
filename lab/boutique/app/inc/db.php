<?php
// NetStock Lab : boutique de démonstration VOLONTAIREMENT VULNÉRABLE.
// Lab uniquement (127.0.0.1). Ne jamais déployer ce code sur un vrai serveur.
declare(strict_types=1);

session_start();

$config = require __DIR__ . '/../config.php';
$db = new PDO($config['dsn'], $config['utilisateur'] ?? null, $config['mot_de_passe'] ?? null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);
if (str_starts_with($config['dsn'], 'sqlite:')) {
    $db->sqliteCreateFunction('MD5', 'md5', 1);   // les tests automatiques utilisent SQLite
}

$_SESSION['panier'] ??= [];
$_SESSION['remises'] ??= [];

function e(mixed $texte): string
{
    return htmlspecialchars((string) $texte, ENT_QUOTES, 'UTF-8');
}

function euros(float $montant): string
{
    return number_format($montant, 2, ',', ' ') . ' €';
}

function client_connecte(): ?array
{
    return $_SESSION['client'] ?? null;
}

function total_panier(): float
{
    $total = 0.0;
    foreach ($_SESSION['panier'] as $ligne) {
        $total += $ligne['prix'] * $ligne['quantite'];
    }
    return $total - array_sum($_SESSION['remises']);
}
