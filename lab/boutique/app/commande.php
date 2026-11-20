<?php
require __DIR__ . '/inc/db.php';
$titre = 'Commande';
$client = client_connecte();
if (!$client) {
    header('Location: connexion.php');
    exit;
}
// La commande n'est affichée que si elle appartient au client connecté (plus d'IDOR).
$requete = $db->prepare('SELECT c.*, cl.nom, cl.email, cl.adresse FROM commandes c
                         JOIN clients cl ON cl.id = c.client_id WHERE c.id = ? AND c.client_id = ?');
$requete->execute([(int) ($_GET['id'] ?? 0), (int) $client['id']]);
$commande = $requete->fetch();
require __DIR__ . '/inc/haut.php';
?>
<?php if (!$commande): ?>
  <h1>Commande introuvable</h1>
<?php else: ?>
  <h1>Commande n° <?= (int) $commande['id'] ?></h1>
  <div class="carte">
    <p><strong>Client :</strong> <?= e($commande['nom']) ?> (<?= e($commande['email']) ?>)</p>
    <p><strong>Livraison :</strong> <?= e($commande['adresse']) ?></p>
    <p><strong>Contenu :</strong> <?= e($commande['detail']) ?></p>
    <p><strong>Date :</strong> <?= e($commande['date_commande']) ?></p>
    <p class="prix">Total payé : <?= euros((float) $commande['total']) ?></p>
  </div>
<?php endif; ?>
<?php require __DIR__ . '/inc/bas.php';
