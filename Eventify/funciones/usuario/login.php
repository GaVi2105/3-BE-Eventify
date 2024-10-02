<?php

include '../configuracion/config.php';
session_start();

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $correo = mysqli_real_escape_string($conn, $_POST['correo']);
    $contrasenia = $_POST['contrasenia'];

    $sql = "SELECT ID_usuario, Nombre, Contrasenia, Tipo_usuario FROM Usuario WHERE Correo_electronico = '$correo'";
    $result = $conn->query($sql);

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if (password_verify($contrasenia, $row['Contrasenia'])) {
            $_SESSION['ID_usuario'] = $row['ID_usuario'];
            $_SESSION['usuario'] = $row['Nombre'];
            $_SESSION['tipo_usuario'] = $row['Tipo_usuario'];

            header("Location: ../../index.php");
            exit();
        } else {
            $error = "Contraseña incorrecta.";
        }
    } else {
        $error = "No se encontró un usuario con ese correo electrónico.";
    }
}
include '../../pagina/login.view.php';
?>