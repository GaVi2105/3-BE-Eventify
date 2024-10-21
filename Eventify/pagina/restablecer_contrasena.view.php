<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Restablecer Contraseña</title>
    <link rel="stylesheet" href="../css/styles.css">
</head>
<body>
    <h2>Restablecer Contraseña</h2>

    <?php if (isset($success_message)): ?>
        <div class="alert alert-success"><?= $success_message; ?></div>
    <?php elseif (isset($error_message)): ?>
        <div class="alert alert-danger"><?= $error_message; ?></div>
    <?php endif; ?>

    <form method="POST" action="">
        <label for="nueva_contrasenia">Nueva Contraseña:</label>
        <input type="password" id="nueva_contrasenia" name="nueva_contrasenia" required>
        <button type="submit">Restablecer Contraseña</button>
    </form>
</body>
</html>
