<?php
// Ruta corregida para config.php
include '../configuracion/config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $correo = mysqli_real_escape_string($conn, $_POST['correo']);

    // Verificar si el correo está registrado
    $sql = "SELECT ID_usuario FROM Usuario WHERE Correo_electronico = '$correo'";
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $id_usuario = $row['ID_usuario'];

        // Generar token único
        $token = bin2hex(random_bytes(50));

        // Guardar el token en la base de datos
        $sql_token = "INSERT INTO RecuperacionContrasena (ID_usuario, Token, Fecha_solicitud) VALUES (?, ?, NOW())";
        $stmt_token = $conn->prepare($sql_token);
        $stmt_token->bind_param("is", $id_usuario, $token);
        $stmt_token->execute();

        // Enviar correo con el enlace de recuperación
        $enlace = "https://tu-sitio.com/restablecer_contrasena.php?token=" . $token;
        $mensaje = "Haz clic en el siguiente enlace para restablecer tu contraseña: " . $enlace;
        mail($correo, "Recuperación de contraseña", $mensaje);

        $success_message = "Se ha enviado un enlace de recuperación a tu correo.";
    } else {
        $error_message = "No se encontró una cuenta con ese correo.";
    }
}

// Ruta corregida para la vista
include '../../pagina/recuperar_contrasena.view.php';
?>
