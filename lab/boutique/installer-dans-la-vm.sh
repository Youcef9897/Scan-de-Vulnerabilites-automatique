#!/bin/sh
# Installe NetStock Lab dans la VM Ubuntu, en écoute sur 127.0.0.1:8082 UNIQUEMENT.
# À lancer en root (su -) depuis ce dossier :  sh installer-dans-la-vm.sh
# Relancer le script remet la boutique et sa base à zéro.
set -eu

DEST=/var/www/netstock-lab
PORT=8082
ICI=$(cd "$(dirname "$0")" && pwd)

[ "$(id -u)" -eq 0 ] || { echo "À lancer en root : su - puis sh $0"; exit 1; }

echo "1/5 Module PHP pour MariaDB"
apt-get install -y php8.1-mysql >/dev/null

echo "2/5 Fichiers du site dans $DEST"
mkdir -p "$DEST"
cp -r "$ICI/app/." "$DEST/"

echo "3/5 Base de données et compte dédié (mot de passe aléatoire, jamais affiché)"
MDP=$(openssl rand -hex 16)
mysql <<SQL
CREATE DATABASE IF NOT EXISTS netstock_lab CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS 'netstock_lab'@'localhost' IDENTIFIED BY '$MDP';
ALTER USER 'netstock_lab'@'localhost' IDENTIFIED BY '$MDP';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP ON netstock_lab.* TO 'netstock_lab'@'localhost';
SQL
cat > "$DEST/config.php" <<PHP
<?php
return ['dsn' => 'mysql:host=localhost;dbname=netstock_lab;charset=utf8mb4',
        'utilisateur' => 'netstock_lab', 'mot_de_passe' => '$MDP'];
PHP
chown root:www-data "$DEST/config.php"
chmod 640 "$DEST/config.php"

echo "4/5 Tables et données fictives"
php "$DEST/inc/installer.php"

echo "5/5 Site Apache sur 127.0.0.1:$PORT"
cat > /etc/apache2/sites-available/netstock-lab.conf <<CONF
# NetStock Lab : boutique volontairement vulnérable, joignable depuis la VM seulement.
Listen 127.0.0.1:$PORT
<VirtualHost 127.0.0.1:$PORT>
    DocumentRoot $DEST
    <Directory $DEST>
        Options -Indexes
        AllowOverride None
        Require local
    </Directory>
    <Directory $DEST/inc>
        Require all denied
    </Directory>
    <Files "config.php">
        Require all denied
    </Files>
    ErrorLog \${APACHE_LOG_DIR}/netstock-lab-error.log
    CustomLog \${APACHE_LOG_DIR}/netstock-lab-access.log combined
</VirtualHost>
CONF
a2ensite netstock-lab >/dev/null
apache2ctl configtest
systemctl reload apache2
echo "NetStock Lab prêt : http://127.0.0.1:$PORT/ (depuis la VM uniquement)"
