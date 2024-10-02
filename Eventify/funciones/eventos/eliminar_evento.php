<?php
include '../configuracion/config.php';
session_start();
verificar_organizador();

if (!isset($_GET['id'])) {
    header("Location: mis_eventos.php");
    exit();
}

$id_evento = $_GET['id'];
$id_usuario = $_SESSION['ID_usuario'];

// Verificar que el evento pertenece al organizador
$sql_check = "SELECT e.* FROM Evento e 
              INNER JOIN Organizador o ON e.ID_organizador = o.ID_organizador 
              WHERE e.ID_evento = ? AND o.ID_usuario = ?";
$stmt_check = $conn->prepare($sql_check);
$stmt_check->bind_param("ii", $id_evento, $id_usuario);
$stmt_check->execute();
$result_check = $stmt_check->get_result();

if ($result_check->num_rows == 0) {
    header("Location: mis_eventos.php");
    exit();
}

// Elimina la relacion con evento
$stmt = $conn->prepare("DELETE FROM participante WHERE ID_evento = ?");
$stmt->bind_param("i", $id_evento);
$stmt->execute();


// Eliminar el evento
$sql_delete = "DELETE FROM Evento WHERE ID_evento = ?";
$stmt_delete = $conn->prepare($sql_delete);
$stmt_delete->bind_param("i", $id_evento);

if ($stmt_delete->execute()) {
    $_SESSION['mensaje'] = "Evento eliminado exitosamente.";
} else {
    $_SESSION['error'] = "Error al eliminar el evento: " . $conn->error;
}

header("Location: mis_eventos.php");
exit();
?>