<?php
// perfil.php

include '../configuracion/config.php';
session_start();
verificar_sesion();

$id_usuario = $_SESSION['ID_usuario'];

// Obtener la información del usuario
$sql = "SELECT * FROM Usuario WHERE ID_usuario = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id_usuario);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

// Incluir la vista del perfil
include '../../pagina/perfil_view.php';
?>
