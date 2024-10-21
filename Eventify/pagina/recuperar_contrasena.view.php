<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Recuperar Contraseña</title>
    <link rel="stylesheet" href="../css/styles.css">
</head>
<body>
    <h2>Recuperar Contraseña</h2>

    <?php if (isset($success_message)): ?>
        <div class="alert alert-success"><?= $success_message; ?></div>
    <?php elseif (isset($error_message)): ?>
        <div class="alert alert-danger"><?= $error_message; ?></div>
    <?php endif; ?>

    <form method="POST" action="recuperar_contrasena.php">
        <label for="correo">Correo Electrónico:</label>
        <input type="email" id="correo" name="correo" required>
        <button type="submit">Enviar enlace de recuperación</button>
    </form>
</body>
</html>
