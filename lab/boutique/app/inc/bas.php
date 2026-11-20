</main>
<footer>
  NetStock Lab — matériel réseau fictif, aucune vente réelle.
  <?php
  $credits = [];
  foreach (@file(__DIR__ . '/../img/photos.txt', FILE_IGNORE_NEW_LINES) ?: [] as $ligne) {
      $champs = explode('|', $ligne);
      if ($ligne !== '' && $ligne[0] !== '#' && count($champs) === 4 && is_file(__DIR__ . '/../img/produit-' . (int) $champs[0] . '.jpg')) {
          $credits[] = '<a href="' . e($champs[2]) . '">' . e($champs[3]) . '</a>';
      }
  }
  if ($credits): ?>
    <br>Photos libres de droits : <?= implode(', ', $credits) ?>.
  <?php endif; ?>
</footer>
</body>
</html>
