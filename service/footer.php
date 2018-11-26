<?php

function autenticar($message){
  if (strpos($message, 'wrong') !== false) {
    header("Location: senha_errada.php");
    die();
    return 0;
  }
  if (strpos($message, 'saved') !== false) {
    header("Location: cadsucesso.php");
    die();
    return 1;
  }

  if (strpos($message, 'Successfully') !== false) {
    header("Location: sucesso.php");
    die();
    return 2;
  }

  return -1;
}

function n_autenticar(){
  header("Location: hmac_erro.php");

}


socket_write($socket, $in, strlen($in));


$data="";
while ($out = socket_read($socket, 2048)) {
    echo $out;
    $data.=$out;


}
list($message,$nonce,$hash) =explode(":",$data);


$local_obj=$_POST["login"];
$local_obj.=$nonce;
$local_obj.=":";

$my_hash=hash_hmac('sha256', $local_obj, "chavedohmac\n");

/*echo "<br>";
echo "$hash <br> $my_hash<br> $data<br>";*/
if ($hash==$my_hash){
  echo autenticar($message);
}else{
  n_autenticar();
}





?>
