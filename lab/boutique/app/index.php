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
  <input type="search" name="q" placeholder="Rechercher un produit" value="<?= e($q) ?>">
  <button>Rechercher</button>
</form>
<?php if ($q !== ''): ?>
  <!-- Le texte recherché est échappé avant affichage : il s'affiche, il ne s'exécute pas (plus de XSS). -->
  <p class="info">Résultats pour : <?= e($q) ?></p>
<?php endif; ?>
<div class="grille">
<?php foreach ($produits as $p): ?>
  <article class="produit">
    <?php
    $photo = 'img/produit-' . (int) $p['id'] . '.jpg';
    if (!is_file(__DIR__ . '/' . $photo)) {
        $photo = 'img/produit-' . (int) $p['id'] . '.svg';   // illustration maison quand il n'y a pas de photo libre
    }
    ?>
    <?php if (is_file(__DIR__ . '/' . $photo)): ?>
      <img class="vignette" src="<?= $photo ?>" alt="<?= e($p['nom']) ?>" width="400" height="260">
    <?php else: ?>
      <div class="vignette"><?= e($p['categorie']) ?></div>
    <?php endif; ?>
    <h2><?= e($p['nom']) ?></h2>
    <p><?= e($p['description']) ?></p>
    <p class="prix"><?= euros((float) $p['prix']) ?></p>
    <form method="post" action="panier.php">
      <?= champ_csrf() ?>
      <input type="hidden" name="action" value="ajouter">
      <input type="hidden" name="produit_id" value="<?= (int) $p['id'] ?>">
      <!-- Plus de prix envoyé par le navigateur : le serveur le relit dans la base à partir de l'identifiant. -->
      <input type="number" name="quantite" value="1" min="1">
      <button>Ajouter au panier</button>
    </form>
  </article>
<?php endforeach; ?>
</div>
<?php if (!$produits): ?><p>Aucun produit trouvé.</p><?php endif; ?>
<?php require __DIR__ . '/inc/bas.php';
