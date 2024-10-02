<?php
include '../configuracion/config.php';

if (isset($_GET['id'])) {
    $id_evento = intval($_GET['id']);

    $sql = "SELECT Imagen_evento FROM Evento WHERE ID_evento = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $id_evento);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($imagen);
    $stmt->fetch();

    if ($imagen) {
        header("Content-Type: image/jpeg");
        echo $imagen;
    } else {
        // Mostrar una imagen por defecto
        header("Content-Type: image/png");
        readfile("img/evento_default.png");
    }
} else {
    echo "No se especificó ID de evento.";
}