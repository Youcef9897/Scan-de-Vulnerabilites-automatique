<?php
require __DIR__ . '/inc/db.php';
$titre = 'Mon compte';
$client = client_connecte();
if (!$client) {
    header('Location: connexion.php');
    exit;
}
$requete = $db->prepare('SELECT id, total, date_commande FROM commandes WHERE client_id = ? ORDER BY id DESC');
$requete->execute([$client['id']]);
$commandes = $requete->fetchAll();
require __DIR__ . '/inc/haut.php';
?>
<h1>Mon compte</h1>
<p>Connecté en tant que <?= e($client['nom']) ?> (<?= e($client['email']) ?>).</p>
<h2>Mes commandes</h2>
<?php if (!$commandes): ?><p>Aucune commande.</p><?php endif; ?>
<ul>
<?php foreach ($commandes as $c): ?>
  <li><a href="commande.php?id=<?= (int) $c['id'] ?>">Commande n° <?= (int) $c['id'] ?></a>
      — <?= euros((float) $c['total']) ?> — <?= e($c['date_commande']) ?></li>
<?php endforeach; ?>
</ul>
<?php require __DIR__ . '/inc/bas.php';
