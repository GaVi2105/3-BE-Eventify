<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Modificar Perfil - Eventify</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../../css/styles.css">
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
        <a href="../../index.php" width="60" height="60">
               <img src="../../icono/Logo.png" alt="Logo" width="60" height="60" class="d-inline-block align-text-top">
            </a>            <a class="navbar-brand" href="../../index.php">Eventify</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-gear-fill" viewBox="0 0 16 16">
                    <path d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z" />
                </svg>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="../../index.php">Inicio</a></li>
                    <li class="nav-item"><a class="nav-link" href="../eventos/eventos.php">Eventos</a></li>
                    <li class="nav-item"><a class="nav-link" href="../eventos/mis_eventos.php">Mis Eventos</a></li>
                    <li class="nav-item"><a class="nav-link" href="perfil.php">Mi Perfil</a></li>
                    <li class="nav-item"><a class="nav-link" href="cerrar_sesion.php">Cerrar Sesión</a></li>
                </ul>
            </div>
        </div>
    </nav>

    <main class="container mt-4">
        <br>
        <h1 class="mb-4">Modificar Perfil</h1>
        <?php if (isset($mensaje)): ?>
            <div class="alert alert-success" role="alert"><?php echo htmlspecialchars($mensaje); ?></div>
        <?php endif; ?>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger" role="alert"><?php echo htmlspecialchars($error); ?></div>
        <?php endif; ?>
        <div class="row">
            <div class="col-md-6">
                <h2>Actualizar Información Personal</h2>
                <form method="POST" action="editar_perfil.php" class="needs-validation" novalidate>
                    <div class="mb-3">
                        <label for="nombre" class="form-label">Nombre:</label>
                        <input type="text" class="form-control" id="nombre" name="nombre" value="<?php echo htmlspecialchars($user['Nombre']); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label for="edad" class="form-label">Edad:</label>
                        <input type="number" class="form-control" id="edad" name="edad" value="<?php echo htmlspecialchars($user['Edad']); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label for="telefono" class="form-label">Teléfono:</label>
                        <input type="tel" class="form-control" id="telefono" name="telefono" value="<?php echo htmlspecialchars($user['Numero_telefono']); ?>">
                    </div>
                    <div class="mb-3">
                        <label for="correo" class="form-label">Correo Electrónico:</label>
                        <input type="email" class="form-control" id="correo" name="correo" value="<?php echo htmlspecialchars($user['Correo_electronico']); ?>" required>
                    </div>
                    <div class="mb-3">
                        <label for="ci" class="form-label">CI:</label>
                        <input type="text" class="form-control" id="ci" name="ci" value="<?php echo htmlspecialchars($user['CI']); ?>">
                    </div>
                    <button type="submit" name="actualizar_perfil" class="btn btn-primary">Guardar Cambios</button>
                </form>
            </div>
            <div class="col-md-6">
                <h2>Cambiar Contraseña</h2>
                <form method="POST" action="editar_perfil.php" class="needs-validation" novalidate>
                    <div class="mb-3">
                        <label for="contrasenia_actual" class="form-label">Contraseña Actual:</label>
                        <input type="password" class="form-control" id="contrasenia_actual" name="contrasenia_actual" required>
                    </div>
                    <div class="mb-3">
                        <label for="nueva_contrasenia" class="form-label">Nueva Contraseña:</label>
                        <input type="password" class="form-control" id="nueva_contrasenia" name="nueva_contrasenia" required>
                    </div>
                    <div class="mb-3">
                        <label for="confirmar_contrasenia" class="form-label">Confirmar Nueva Contraseña:</label>
                        <input type="password" class="form-control" id="confirmar_contrasenia" name="confirmar_contrasenia" required>
                    </div>
                    <button type="submit" name="cambiar_contrasenia" class="btn btn-primary">Cambiar Contraseña</button>
                </form>
            </div>
        </div>
        <div class="row mt-4">
            <div class="col-md-6">
                <h2>Cambiar Tipo de Usuario</h2>
                <form method="POST" action="editar_perfil.php" class="needs-validation" novalidate>
                    <div class="mb-3">
                        <label for="tipo_usuario" class="form-label">Tipo de Usuario:</label>
                        <select class="form-select" id="tipo_usuario" name="tipo_usuario" required>
                            <option value="participante" <?php echo ($user['Tipo_usuario'] == 'participante') ? 'selected' : ''; ?>>Participante</option>
                            <option value="organizador" <?php echo ($user['Tipo_usuario'] == 'organizador') ? 'selected' : ''; ?>>Organizador</option>
                        </select>
                    </div>
                    <button type="submit" name="cambiar_tipo_usuario" class="btn btn-primary">Cambiar Tipo de Usuario</button>
                </form>
            </div>
            <div class="col-md-6">
                <h2>Eliminar Cuenta</h2>
                <p class="text-danger">Advertencia: Esta acción es irreversible y eliminará todos tus datos.</p>
                <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#confirmarEliminarModal">
                    Eliminar mi cuenta
                </button>
            </div>
        </div>
    </main>

    <!-- Modal de confirmación para eliminar cuenta -->
    <div class="modal fade" id="confirmarEliminarModal" tabindex="-1" aria-labelledby="confirmarEliminarModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="confirmarEliminarModalLabel">Confirmar eliminación de cuenta</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                </div>
                <div class="modal-body">
                    <p>¿Estás seguro de querer eliminar tu cuenta? Esta acción no se puede deshacer.</p>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <form method="POST" action="editar_perfil.php">
                        <button type="submit" name="eliminar_cuenta" class="btn btn-danger">Sí, eliminar mi cuenta</button>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <footer class="d-block d-md-none" style="background-color: #007BFF; color: #fff; text-align: center; padding: 0.2rem 0;"> 
    <div class="hstack gap-3"> <!-- Alineación en fila, solo en pantallas pequeñas -->
        <div class="p-1">
            <button class="btn btn-primary" type="button" aria-label="Perfil" onclick="window.location.href='../usuario/perfil.php'">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-person" viewBox="0 0 16 16">
                    <path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6m2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0m4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4m-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10s-3.516.68-4.168 1.332c-.678.678-.83 1.418-.832 1.664z"/>
                </svg>
            </button>
        </div>
        <div class="p-1 ms-auto" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%);">
        <?php if (isset($_SESSION['usuario'])): ?>
            <?php if ($_SESSION['tipo_usuario'] == 'participante'): ?>
            <button class="btn btn-primary" type="button" aria-label="Buscar" onclick="window.location.href='funciones/eventos/buscar.php'">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-search" viewBox="0 0 16 16">
                    <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/>
                </svg>
            </button>
            <?php endif; ?>
            <?php endif; ?>
        </div>
        <div class="p-1" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%);">
                <?php if (isset($_SESSION['usuario'])): ?>
                <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
            <button class="btn btn-primary" type="button" aria-label="Agregar Evento" onclick="window.location.href='../../funciones/eventos/crear_evento.php'">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-plus-lg" viewBox="0 0 16 16">
                    <path fill-rule="evenodd" d="M8 2a.5.5 0 0 1 .5.5v5h5a.5.5 0 0 1 0 1h-5v5a.5.5 0 0 1-1 0v-5h-5a.5.5 0 0 1 0-1h5v-5A.5.5 0 0 1 8 2"/>
                </svg>
            </button>
                <?php endif; ?>
                <?php endif; ?>
        </div>
    </div>
</footer>


    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>
    <script src="menu.js"></script>
</body>
</html>
