<?php

session_start();
include 'funciones/configuracion/config.php';

$eventos_destacados = obtener_eventos_destacados(6);
$eventos_recientes = obtener_eventos_recientes();

include 'pagina/index.view.php';
?>
