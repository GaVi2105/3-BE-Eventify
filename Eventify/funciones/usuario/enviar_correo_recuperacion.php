<?php
// Importar PHPMailer
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
require 'vendor/autoload.php';
include 'config.php'; // Archivo de conexión a la base de datos

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $email = mysqli_real_escape_string($conn, $_POST['email']);

    // Verificar si el correo existe en la base de datos
    $sql = "SELECT ID_usuario FROM Usuario WHERE Correo_electronico = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // Generar un token seguro
        $token = bin2hex(random_bytes(32));
        $user = $result->fetch_assoc();
        $userId = $user['ID_usuario'];

        // Guardar el token y la fecha de expiración en la base de datos (tabla `password_resets`)
        $sql_token = "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))";
        $stmt_token = $conn->prepare($sql_token);
        $stmt_token->bind_param("is", $userId, $token);
        $stmt_token->execute();

        // Enviar el correo con PHPMailer
        $mail = new PHPMailer(true);
        try {
            // Configuración del servidor SMTP
            $mail->isSMTP();
            $mail->Host = 'smtp.example.com';  // Servidor SMTP
            $mail->SMTPAuth = true;
            $mail->Username = 'usuario@example.com'; // Tu usuario SMTP
            $mail->Password = 'secret'; // Tu contraseña SMTP
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            $mail->Port = 465;

            // Destinatarios
            $mail->setFrom('no-reply@example.com', 'Eventify');
            $mail->addAddress($email);

            // Contenido
            $mail->isHTML(true);
            $mail->Subject = 'Solicitud de Restablecimiento de Contraseña';
            $resetLink = "http://tuweb.com/restablecer_contrasena.php?token=$token";
            $mail->Body    = "Haz clic <a href='$resetLink'>aquí</a> para restablecer tu contraseña. Este enlace expira en 1 hora.";

            $mail->send();
            echo 'Se ha enviado el enlace de restablecimiento de contraseña a tu correo.';
        } catch (Exception $e) {
            echo "El mensaje no pudo ser enviado. Error de Mailer: {$mail->ErrorInfo}";
        }
    } else {
        echo "No se encontró una cuenta con ese correo electrónico.";
    }
}
?>
