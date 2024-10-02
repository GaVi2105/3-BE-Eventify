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

$evento = $result_check->fetch_assoc();

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $nombre = mysqli_real_escape_string($conn, $_POST['nombre']);
    $descripcion = mysqli_real_escape_string($conn, $_POST['descripcion']);
    $fecha = mysqli_real_escape_string($conn, $_POST['fecha']);
    $ubicacion = mysqli_real_escape_string($conn, $_POST['ubicacion']);
    $costo = mysqli_real_escape_string($conn, $_POST['costo']);
    $id_categoria = mysqli_real_escape_string($conn, $_POST['id_categoria']);

    $sql_update = "UPDATE Evento SET Nombre = ?, Descripcion = ?, Fecha = ?, Ubicacion = ?, Costo_entrada = ?, ID_categoria = ? WHERE ID_evento = ?";
    $stmt_update = $conn->prepare($sql_update);
    $stmt_update->bind_param("ssssdii", $nombre, $descripcion, $fecha, $ubicacion, $costo, $id_categoria, $id_evento);

    if ($stmt_update->execute()) {
        $mensaje = "Evento actualizado exitosamente.";

        if (isset($_FILES['imagen']) && $_FILES['imagen']['error'] == 0) {
            $resultado_imagen = subir_imagen($_FILES['imagen'], $id_evento);
            if (strpos($resultado_imagen, "exitosamente") === false) {
                $error = $resultado_imagen;
            } else {
                $mensaje .= " " . $resultado_imagen;
            }
        }
    } else {
        $error = "Error al actualizar el evento: " . $conn->error;
    }
}

$categorias = obtener_categorias();

include '../../pagina/editar_evento.php';