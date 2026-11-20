<?php
require __DIR__ . '/inc/db.php';
$titre = 'Panier';
$message = '';
$action = $_POST['action'] ?? '';

// Toute action du panier passe par un POST protégé par un jeton anti-CSRF.
if ($action !== '' && !csrf_valide()) {
    $action = '';
    $message = 'Session expirée, merci de réessayer.';
}

if ($action === 'ajouter') {
    // Le prix est relu dans la base à partir de l'identifiant : la valeur envoyée par le navigateur est ignorée.
    $requete = $db->prepare('SELECT id, nom, prix FROM produits WHERE id = ?');
    $requete->execute([(int) ($_POST['produit_id'] ?? 0)]);
    $produit = $requete->fetch();
    if ($produit) {
        $quantite = max(1, (int) ($_POST['quantite'] ?? 1));   // au moins 1 : plus de quantité négative
        $_SESSION['panier'][] = [
            'produit_id' => (int) $produit['id'],
            'nom' => $produit['nom'],
            'prix' => (float) $produit['prix'],                // prix de la base, jamais celui du navigateur
            'quantite' => $quantite,
        ];
        $message = 'Produit ajouté au panier.';
    }
} elseif ($action === 'code') {
    $code = strtoupper(trim($_POST['code'] ?? ''));
    if ($code !== 'BIENVENUE10') {
        $message = 'Code inconnu.';
    } elseif (in_array('BIENVENUE10', $_SESSION['codes_utilises'], true)) {
        $message = 'Ce code a déjà été appliqué.';          // un seul usage par panier
    } else {
        $_SESSION['codes_utilises'][] = 'BIENVENUE10';
        $_SESSION['remises'][] = 10.0;
        $message = 'Code BIENVENUE10 appliqué : 10 € de remise.';
    }
} elseif ($action === 'vider') {
    $_SESSION['panier'] = [];
    $_SESSION['remises'] = [];
    $_SESSION['codes_utilises'] = [];
} elseif ($action === 'commander') {
    $client = client_connecte();
    if (!$client) {
        header('Location: connexion.php');
        exit;
    }
    if ($_SESSION['panier']) {
        $detail = implode(', ', array_map(fn ($l) => $l['quantite'] . ' × ' . $l['nom'], $_SESSION['panier']));
        $requete = $db->prepare('INSERT INTO commandes (client_id, total, detail, date_commande) VALUES (?, ?, ?, ?)');
        $requete->execute([$client['id'], round(total_panier(), 2), $detail, date('Y-m-d H:i:s')]);
        $numero = (int) $db->lastInsertId();
        $_SESSION['panier'] = [];
        $_SESSION['remises'] = [];
        $_SESSION['codes_utilises'] = [];
        header('Location: commande.php?id=' . $numero);
        exit;
    }
}
require __DIR__ . '/inc/haut.php';
?>
<h1>Panier</h1>
<?php if ($message): ?><p class="info"><?= e($message) ?></p><?php endif; ?>
<?php if (!$_SESSION['panier']): ?>
  <p>Ton panier est vide.</p>
<?php else: ?>
  <table>
    <tr><th>Produit</th><th>Prix</th><th>Quantité</th><th>Sous-total</th></tr>
    <?php foreach ($_SESSION['panier'] as $l): ?>
      <tr><td><?= e($l['nom']) ?></td><td><?= euros($l['prix']) ?></td><td><?= (int) $l['quantite'] ?></td>
          <td><?= euros($l['prix'] * $l['quantite']) ?></td></tr>
    <?php endforeach; ?>
    <?php foreach ($_SESSION['remises'] as $r): ?>
      <tr><td colspan="3">Code BIENVENUE10</td><td>−<?= euros($r) ?></td></tr>
    <?php endforeach; ?>
    <tr class="total"><td colspan="3">Total</td><td><?= euros(total_panier()) ?></td></tr>
  </table>
  <form class="ligne" method="post"><?= champ_csrf() ?><input type="hidden" name="action" value="code">
    <input type="text" name="code" placeholder="Code promo"><button>Appliquer</button></form>
  <form class="ligne" method="post"><?= champ_csrf() ?><input type="hidden" name="action" value="commander">
    <button>Valider la commande</button></form>
  <form class="ligne" method="post"><?= champ_csrf() ?><input type="hidden" name="action" value="vider">
    <button class="second">Vider le panier</button></form>
<?php endif; ?>
<?php require __DIR__ . '/inc/bas.php';
