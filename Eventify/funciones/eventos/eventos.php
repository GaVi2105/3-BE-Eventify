<?php
include '../configuracion/config.php';
session_start();

$page = isset($_GET['page']) ? (int) $_GET['page'] : 1;
$items_per_page = 9;
$categoria = isset($_GET['categoria']) ? (int) $_GET['categoria'] : null;

$eventos = obtener_eventos($page, $items_per_page, $categoria);
$eventos_recientes = obtener_eventos_recientes();
$total_eventos = obtener_total_eventos($categoria);
$total_pages = ceil($total_eventos / $items_per_page);

$categorias = obtener_categorias();

include '../../pagina/eventos.view.php';
?>