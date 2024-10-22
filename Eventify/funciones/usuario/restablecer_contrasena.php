<?php
include 'config.php'; // Conexión a la base de datos

if (isset($_GET['token'])) {
    $token = $_GET['token'];

    // Verificar si el token es válido y no ha expirado
    $sql = "SELECT user_id FROM password_resets WHERE token = ? AND expires_at > NOW()";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        $userId = $user['user_id'];

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $nuevaContrasena = password_hash($_POST['new_password'], PASSWORD_DEFAULT);

            // Actualizar la contraseña del usuario
            $sql_update = "UPDATE Usuario SET Contrasenia = ? WHERE ID_usuario = ?";
            $stmt_update = $conn->prepare($sql_update);
            $stmt_update->bind_param("si", $nuevaContrasena, $userId);
            $stmt_update->execute();

            // Eliminar el token después de su uso
            $sql_delete = "DELETE FROM password_resets WHERE user_id = ?";
            $stmt_delete = $conn->prepare($sql_delete);
            $stmt_delete->bind_param("i", $userId);
            $stmt_delete->execute();

            echo "La contraseña ha sido actualizada correctamente.";
        }
    } else {
        echo "El token es inválido o ha expirado.";
    }
} else {
    echo "No se proporcionó un token.";
}
?>

<form action="" method="POST">
    <label for="new_password">Ingresa una nueva contraseña:</label>
    <input type="password" id="new_password" name="new_password" required>
    <button type="submit">Restablecer Contraseña</button>
</form>
