<?php
include '../configuracion/config.php';
session_start();
verificar_sesion();

$id_usuario = $_SESSION['ID_usuario'];
$tipo_usuario = $_SESSION['tipo_usuario'];

if ($tipo_usuario == 'organizador') {
    $sql = "SELECT e.ID_evento, e.Nombre, e.Descripcion, e.Fecha, e.Ubicacion, e.Costo_entrada, c.Nombre_categoria 
            FROM Evento e 
            INNER JOIN Organizador o ON e.ID_organizador = o.ID_organizador 
            INNER JOIN Categoria c ON e.ID_categoria = c.ID_categoria
            WHERE o.ID_usuario = ?";
} else {
    $sql = "SELECT e.ID_evento, e.Nombre, e.Descripcion, e.Fecha, e.Ubicacion, e.Costo_entrada, c.Nombre_categoria 
            FROM Evento e 
            INNER JOIN Participante p ON e.ID_evento = p.ID_evento 
            INNER JOIN Categoria c ON e.ID_categoria = c.ID_categoria
            WHERE p.ID_usuario = ?";
}

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id_usuario);
$stmt->execute();
$result = $stmt->get_result();

$eventos = [];
if ($result->num_rows > 0) {
    while ($row = $result->fetch_assoc()) {
        $eventos[] = $row;
    }
}
include '../../pagina/mis_eventos_view.php';
?>