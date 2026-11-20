<?php
// NetStock Lab : boutique de démonstration — VERSION CORRIGÉE (étape S7-B).
// Lab uniquement (127.0.0.1). Mêmes pages que la version vulnérable, failles corrigées.
declare(strict_types=1);

// En-têtes de sécurité (mêmes principes que l'Apache durci du site principal).
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; "
     . "style-src 'self'; script-src 'self'; form-action 'self'; frame-ancestors 'none'");

// Cookie de session protégé : inaccessible au JavaScript (HttpOnly) et non envoyé en cross-site (SameSite).
$https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params(['httponly' => true, 'samesite' => 'Lax', 'secure' => $https]);
session_start();

$config = require __DIR__ . '/../config.php';
$db = new PDO($config['dsn'], $config['utilisateur'] ?? null, $config['mot_de_passe'] ?? null, [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
]);

$_SESSION['panier'] ??= [];
$_SESSION['remises'] ??= [];
$_SESSION['codes_utilises'] ??= [];

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
    return max(0.0, $total - array_sum($_SESSION['remises']));
}

// --- Protection anti-CSRF : un secret par session, replacé dans chaque formulaire POST ---

function jeton_csrf(): string
{
    return $_SESSION['csrf'] ??= bin2hex(random_bytes(16));
}

function champ_csrf(): string
{
    return '<input type="hidden" name="csrf" value="' . e(jeton_csrf()) . '">';
}

function csrf_valide(): bool
{
    return isset($_POST['csrf']) && hash_equals($_SESSION['csrf'] ?? '', (string) $_POST['csrf']);
}
