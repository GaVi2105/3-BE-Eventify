<?php
// perfil.php

include '../configuracion/config.php';
session_start();
verificar_sesion();

$id_usuario = $_SESSION['ID_usuario'];
$tipo_usuario = $_SESSION['tipo_usuario']; // Verificar si es organizador o participante

// Obtener la información del usuario
$sql_usuario = "SELECT * FROM Usuario WHERE ID_usuario = ?";
$stmt_usuario = $conn->prepare($sql_usuario);
$stmt_usuario->bind_param("i", $id_usuario);
$stmt_usuario->execute();
$result_usuario = $stmt_usuario->get_result();
$user = $result_usuario->fetch_assoc();

// Verificar el tipo de usuario
if ($tipo_usuario == 'organizador') {
    // Si el usuario es organizador, obtener los eventos que ha creado
    $sql_eventos = "SELECT e.ID_evento, e.Nombre, e.Fecha, e.Ubicacion 
                    FROM Evento e
                    INNER JOIN Organizador o ON e.ID_organizador = o.ID_organizador
                    WHERE o.ID_usuario = ?";
} else {
    // Si el usuario es participante, obtener los eventos en los que está registrado
    $sql_eventos = "SELECT e.ID_evento, e.Nombre, e.Fecha, e.Ubicacion 
                    FROM Evento e
                    INNER JOIN Participante p ON e.ID_evento = p.ID_evento 
                    WHERE p.ID_usuario = ?";
}

$stmt_eventos = $conn->prepare($sql_eventos);
$stmt_eventos->bind_param("i", $id_usuario);
$stmt_eventos->execute();
$result_eventos = $stmt_eventos->get_result();

$eventos = [];
if ($result_eventos->num_rows > 0) {
    while ($row = $result_eventos->fetch_assoc()) {
        $eventos[] = $row;
    }
} else {
    // Mensaje si no tiene eventos
    $eventos = null;
}

// Incluir la vista del perfil
include '../../pagina/perfil_view.php';
?>
