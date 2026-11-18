<?php
require __DIR__ . '/inc/db.php';
$titre = 'Commande';
if (!client_connecte()) {
    header('Location: connexion.php');
    exit;
}
// Faille volontaire (IDOR) : la commande est affichée sans vérifier qu'elle appartient au client connecté.
$requete = $db->prepare('SELECT c.*, cl.nom, cl.email, cl.adresse FROM commandes c
                         JOIN clients cl ON cl.id = c.client_id WHERE c.id = ?');
$requete->execute([(int) ($_GET['id'] ?? 0)]);
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
