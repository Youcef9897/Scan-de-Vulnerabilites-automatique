<?php
require __DIR__ . '/inc/db.php';
$titre = 'Connexion';
$erreur = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_valide()) {
        $erreur = 'Session expirée, merci de réessayer.';
    } else {
        $email = $_POST['email'] ?? '';
        $mdp = $_POST['mot_de_passe'] ?? '';
        // Requête préparée : la saisie est un paramètre, elle ne peut plus modifier la requête (injection SQL impossible).
        $requete = $db->prepare('SELECT id, nom, email, mot_de_passe FROM clients WHERE email = ?');
        $requete->execute([$email]);
        $client = $requete->fetch();
        // Mot de passe vérifié avec password_verify (hachage bcrypt avec sel).
        if ($client && password_verify($mdp, $client['mot_de_passe'])) {
            unset($client['mot_de_passe']);
            session_regenerate_id(true);           // nouvel identifiant de session à la connexion
            $_SESSION['client'] = $client;
            header('Location: compte.php');
            exit;
        }
        // Message générique : aucune erreur de base de données n'est révélée au visiteur.
        $erreur = 'Adresse e-mail ou mot de passe incorrect.';
    }
}
require __DIR__ . '/inc/haut.php';
?>
<h1>Connexion</h1>
<?php if ($erreur): ?><p class="erreur"><?= e($erreur) ?></p><?php endif; ?>
<form class="carte" method="post" action="connexion.php">
  <?= champ_csrf() ?>
  <label>Adresse e-mail <input type="text" name="email" autocomplete="username"></label>
  <label>Mot de passe <input type="password" name="mot_de_passe" autocomplete="current-password"></label>
  <button>Se connecter</button>
</form>
<p class="petit">Comptes de test du lab : alice@netstock.lab et bob@netstock.lab (mots de passe dans le README).</p>
<?php require __DIR__ . '/inc/bas.php';
