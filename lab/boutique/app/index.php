<?php
require __DIR__ . '/inc/db.php';
$titre = 'Catalogue';
$q = $_GET['q'] ?? '';
if ($q !== '') {
    $requete = $db->prepare('SELECT * FROM produits WHERE nom LIKE ? ORDER BY id');
    $requete->execute(['%' . $q . '%']);
} else {
    $requete = $db->query('SELECT * FROM produits ORDER BY id');
}
$produits = $requete->fetchAll();
require __DIR__ . '/inc/haut.php';
?>
<h1>Catalogue</h1>
<form class="recherche" method="get" action="index.php">
  <input type="search" name="q" placeholder="Rechercher un produit" value="">
  <button>Rechercher</button>
</form>
<?php if ($q !== ''): ?>
  <!-- Faille volontaire (XSS réfléchi) : le texte recherché est réaffiché sans échappement. -->
  <p class="info">Résultats pour : <?= $q ?></p>
<?php endif; ?>
<div class="grille">
<?php foreach ($produits as $p): ?>
  <article class="produit">
    <?php $photo = 'img/produit-' . (int) $p['id'] . '.jpg'; ?>
    <?php if (is_file(__DIR__ . '/' . $photo)): ?>
      <img class="vignette" src="<?= $photo ?>" alt="<?= e($p['nom']) ?>" width="400" height="260">
    <?php else: ?>
      <div class="vignette"><?= e($p['categorie']) ?></div>
    <?php endif; ?>
    <h2><?= e($p['nom']) ?></h2>
    <p><?= e($p['description']) ?></p>
    <p class="prix"><?= euros((float) $p['prix']) ?></p>
    <form method="post" action="panier.php">
      <input type="hidden" name="action" value="ajouter">
      <input type="hidden" name="produit_id" value="<?= (int) $p['id'] ?>">
      <!-- Faille volontaire : le prix est envoyé par le navigateur, et le serveur le croit. -->
      <input type="hidden" name="prix" value="<?= e($p['prix']) ?>">
      <input type="number" name="quantite" value="1" min="1">
      <button>Ajouter au panier</button>
    </form>
  </article>
<?php endforeach; ?>
</div>
<?php if (!$produits): ?><p>Aucun produit trouvé.</p><?php endif; ?>
<?php require __DIR__ . '/inc/bas.php';
