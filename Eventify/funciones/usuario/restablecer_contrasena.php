<?php
// Archivo: restablecer_contrasena.php
include '../configuracion/config.php';


if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_GET['token'])) {
    $token = $_GET['token'];
    $nueva_contrasenia = password_hash($_POST['nueva_contrasenia'], PASSWORD_DEFAULT);

    // Verificar el token y obtener el ID del usuario
    $sql = "SELECT ID_usuario FROM RecuperacionContrasena WHERE Token = ? AND Fecha_solicitud >= NOW() - INTERVAL 1 DAY";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $id_usuario = $row['ID_usuario'];

        // Actualizar la contraseña
        $sql_update = "UPDATE Usuario SET Contrasenia = ? WHERE ID_usuario = ?";
        $stmt_update = $conn->prepare($sql_update);
        $stmt_update->bind_param("si", $nueva_contrasenia, $id_usuario);
        $stmt_update->execute();

        $success_message = "Tu contraseña ha sido restablecida correctamente.";
    } else {
        $error_message = "El token es inválido o ha expirado.";
    }
}

// Incluir la vista HTML
include 'pagina/restablecer_contrasena.view.php';
?>
