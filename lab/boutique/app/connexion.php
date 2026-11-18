<?php
require __DIR__ . '/inc/db.php';
$titre = 'Connexion';
$erreur = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = $_POST['email'] ?? '';
    $mdp = $_POST['mot_de_passe'] ?? '';
    // Faille volontaire (injection SQL) : la saisie est collée telle quelle dans la requête.
    $sql = "SELECT id, nom, email FROM clients WHERE email = '$email' AND mot_de_passe = MD5('$mdp')";
    try {
        $client = $db->query($sql)->fetch();
        if ($client) {
            $_SESSION['client'] = $client;
            header('Location: compte.php');
            exit;
        }
        $erreur = 'Adresse e-mail ou mot de passe incorrect.';
    } catch (PDOException $ex) {
        // Faille volontaire : le message d'erreur de la base est affiché au visiteur.
        $erreur = 'Erreur SQL : ' . $ex->getMessage();
    }
}
require __DIR__ . '/inc/haut.php';
?>
<h1>Connexion</h1>
<?php if ($erreur): ?><p class="erreur"><?= e($erreur) ?></p><?php endif; ?>
<form class="carte" method="post" action="connexion.php">
  <label>Adresse e-mail <input type="text" name="email" autocomplete="username"></label>
  <label>Mot de passe <input type="password" name="mot_de_passe" autocomplete="current-password"></label>
  <button>Se connecter</button>
</form>
<p class="petit">Comptes de test du lab : alice@netstock.lab et bob@netstock.lab (mots de passe dans le README).</p>
<?php require __DIR__ . '/inc/bas.php';
