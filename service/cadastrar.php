<?php
include "header.php";

$in = "0 ";
$in .= $_POST["login"];
$in .= " ";
$in .= $_POST["senha"];
$in .= " ";
$in .= strval(rand());

$hashhamc=hash_hmac('sha256', $in, "chavedohmac\n");
$in.=" ";
$in.=$hashhamc;

include "footer.php";



?>
