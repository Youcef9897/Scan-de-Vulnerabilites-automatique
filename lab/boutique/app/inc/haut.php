<?php $client = client_connecte(); ?>
<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title><?= e($titre ?? 'NetStock Lab') ?> — NetStock Lab</title>
<link rel="stylesheet" href="style.css">
</head>
<body>
<p class="lab">Site de démonstration <strong>volontairement vulnérable</strong>, pour un lab de sécurité. Données fictives. Ne pas déployer.</p>
<header>
  <a class="marque" href="index.php">NetStock Lab</a>
  <nav>
    <a href="index.php">Catalogue</a>
    <a href="panier.php">Panier (<?= count($_SESSION['panier']) ?>)</a>
    <?php if ($client): ?>
      <a href="compte.php"><?= e($client['nom']) ?></a>
      <a href="deconnexion.php">Se déconnecter</a>
    <?php else: ?>
      <a href="connexion.php">Se connecter</a>
    <?php endif; ?>
  </nav>
</header>
<main>
