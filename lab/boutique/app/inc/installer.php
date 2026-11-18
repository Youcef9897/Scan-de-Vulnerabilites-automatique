<?php
// Crée (ou remet à zéro) les tables et les données fictives. À lancer en ligne de commande uniquement :
//   php inc/installer.php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Interdit');
}

$config = require __DIR__ . '/../config.php';
$db = new PDO($config['dsn'], $config['utilisateur'] ?? null, $config['mot_de_passe'] ?? null,
              [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
$sqlite = str_starts_with($config['dsn'], 'sqlite:');
$cle = $sqlite ? 'INTEGER PRIMARY KEY AUTOINCREMENT' : 'INT AUTO_INCREMENT PRIMARY KEY';
$moteur = $sqlite ? '' : ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4';

foreach (['commandes', 'produits', 'clients'] as $table) {
    $db->exec("DROP TABLE IF EXISTS $table");
}
$db->exec("CREATE TABLE clients (id $cle, nom VARCHAR(80) NOT NULL, email VARCHAR(120) NOT NULL UNIQUE,
           mot_de_passe CHAR(32) NOT NULL, adresse VARCHAR(200) NOT NULL)$moteur");
$db->exec("CREATE TABLE produits (id $cle, nom VARCHAR(120) NOT NULL, description VARCHAR(255) NOT NULL,
           prix DECIMAL(8,2) NOT NULL, categorie VARCHAR(40) NOT NULL)$moteur");
$db->exec("CREATE TABLE commandes (id $cle, client_id INT NOT NULL, total DECIMAL(10,2) NOT NULL,
           detail TEXT NOT NULL, date_commande VARCHAR(19) NOT NULL)$moteur");

// Faille volontaire : mots de passe hachés en MD5, sans sel (corrigé en S7-B).
$clients = [
    ['Alice Martin', 'alice@netstock.lab', 'alice2027', '12 rue Fictive, 75000 Paris'],
    ['Bob Durand', 'bob@netstock.lab', 'bob2027', '8 avenue Imaginaire, 69000 Lyon'],
];
$ajout = $db->prepare('INSERT INTO clients (nom, email, mot_de_passe, adresse) VALUES (?, ?, ?, ?)');
foreach ($clients as [$nom, $email, $mdp, $adresse]) {
    $ajout->execute([$nom, $email, md5($mdp), $adresse]);
}

$produits = [
    ['Câble réseau RJ45 Cat 6, 3 m', 'Câble droit blindé, connecteurs plaqués or.', 6.90, 'Câblage'],
    ['Switch 8 ports Gigabit', 'Switch non administrable, boîtier métal.', 29.90, 'Réseau'],
    ['Carte réseau PCIe 2,5 Gb/s', 'Carte RJ45 pour poste fixe.', 24.90, 'Réseau'],
    ['Point d\'accès Wi-Fi 6', 'Point d\'accès plafonnier, alimentation PoE.', 89.90, 'Réseau'],
    ['Clavier mécanique', 'Clavier AZERTY, touches rétroéclairées.', 49.90, 'Poste de travail'],
    ['Disque SSD 1 To', 'SSD SATA 2,5 pouces.', 79.90, 'Stockage'],
];
$ajout = $db->prepare('INSERT INTO produits (nom, description, prix, categorie) VALUES (?, ?, ?, ?)');
foreach ($produits as $p) {
    $ajout->execute($p);
}

$commandes = [
    [2, 59.80, '2 × Switch 8 ports Gigabit', '2026-11-02 10:14:00'],
    [2, 13.80, '2 × Câble réseau RJ45 Cat 6, 3 m', '2026-11-09 18:40:00'],
    [1, 89.90, '1 × Point d\'accès Wi-Fi 6', '2026-11-12 09:05:00'],
];
$ajout = $db->prepare('INSERT INTO commandes (client_id, total, detail, date_commande) VALUES (?, ?, ?, ?)');
foreach ($commandes as $c) {
    $ajout->execute($c);
}
echo "Base NetStock Lab prête : 2 clients, 6 produits, 3 commandes.\n";
