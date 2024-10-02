<?php
// participar_evento.php
include '../configuracion/config.php';
session_start();

if (!isset($_SESSION['ID_usuario']) || $_SESSION['tipo_usuario'] != 'participante') {
    header("Location: ../usuario/login.php");
    exit;
}

$id_usuario = $_SESSION['ID_usuario'];
$id_evento = isset($_POST['id_evento']) ? $_POST['id_evento'] : (isset($_GET['id']) ? $_GET['id'] : null);
$action = isset($_GET['action']) ? $_GET['action'] : 'participate';

if (!$id_evento) {
    header("Location: eventos.php");
    exit;
}

// Obtener información completa del evento
$sql_evento = "SELECT e.*, c.Nombre_categoria 
               FROM Evento e 
               JOIN Categoria c ON e.ID_categoria = c.ID_categoria 
               WHERE e.ID_evento = ?";
$stmt_evento = $conn->prepare($sql_evento);
$stmt_evento->bind_param("i", $id_evento);
$stmt_evento->execute();
$result_evento = $stmt_evento->get_result();
$evento = $result_evento->fetch_assoc();

if ($action == 'participate') {
    $sql_check = "SELECT * FROM Participante WHERE ID_evento = ? AND ID_usuario = ?";
    $stmt_check = $conn->prepare($sql_check);
    $stmt_check->bind_param("ii", $id_evento, $id_usuario);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();

    if ($result_check->num_rows == 0) {
        $sql_insert = "INSERT INTO Participante (ID_evento, ID_usuario, Fecha_confirmacion) VALUES (?, ?, NOW())";
        $stmt_insert = $conn->prepare($sql_insert);
        $stmt_insert->bind_param("ii", $id_evento, $id_usuario);

        if ($stmt_insert->execute()) {
            $mensaje = "Te has registrado para este evento exitosamente.";
            $tipo_mensaje = "success";
        } else {
            $mensaje = "Error al confirmar participación: " . $conn->error;
            $tipo_mensaje = "danger";
        }
    } else {
        $mensaje = "Ya te has registrado para este evento.";
        $tipo_mensaje = "warning";
    }
} elseif ($action == 'cancel') {
    $sql_delete = "DELETE FROM Participante WHERE ID_evento = ? AND ID_usuario = ?";
    $stmt_delete = $conn->prepare($sql_delete);
    $stmt_delete->bind_param("ii", $id_evento, $id_usuario);

    if ($stmt_delete->execute()) {
        $mensaje = "Has cancelado tu participación en este evento.";
        $tipo_mensaje = "success";
    } else {
        $mensaje = "Error al cancelar la participación: " . $conn->error;
        $tipo_mensaje = "danger";
    }
} else {
    $mensaje = "Acción no válida.";
    $tipo_mensaje = "danger";
}

// Incluir el HTML
include '../../pagina/participar_evento_view.php';
?>