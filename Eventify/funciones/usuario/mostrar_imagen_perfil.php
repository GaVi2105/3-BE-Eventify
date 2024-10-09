<?php
include '../configuracion/config.php';

if (isset($_GET['id'])) {
    $id_usuario = intval($_GET['id']);
    $sql = "SELECT Imagen_perfil FROM Usuario WHERE ID_usuario = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $id_usuario);
    $stmt->execute();
    $stmt->store_result();
    $stmt->bind_result($imagen_perfil);
    $stmt->fetch();

    if ($imagen_perfil) {
        header("Content-Type: image/jpeg");
        echo $imagen_perfil;
    } else {
        header("Content-Type: image/png");
        readfile('../../imagenes/imagen_generica.png');
    }
}
?>
