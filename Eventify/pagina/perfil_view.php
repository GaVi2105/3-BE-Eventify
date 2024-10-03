<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mi Perfil - Eventify</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../../css/styles.css">
</head>
<body class="login">
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
        <a href="../../index.php" width="60" height="60">
               <img src="../../icono/Logo.png" alt="Logo" width="60" height="60" class="d-inline-block align-text-top">
            </a>
            <a class="navbar-brand" href="../../index.php">Eventify</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-gear-fill" viewBox="0 0 16 16">
                    <path d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z" />
                </svg>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="../../index.php">Inicio</a></li>
                    <li class="nav-item"><a class="nav-link" href="../eventos/eventos.php">Eventos</a></li>
                    <?php if (isset($_SESSION['usuario'])): ?>
                        <li class="nav-item"><a class="nav-link" href="../eventos/mis_eventos.php">Mis Eventos</a></li>
                        <li class="nav-item"><a class="nav-link" href="perfil.php">Mi Perfil</a></li>
                        <li class="nav-item"><a class="nav-link" href="cerrar_sesion.php">Cerrar Sesión</a></li>
                    <?php else: ?>
                        <li class="nav-item"><a class="nav-link" href="login.php">Iniciar Sesión</a></li>
                        <li class="nav-item"><a class="nav-link" href="register.php">Registrarse</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <main class="container mt-4">
    <br>
    <h1 class="mb-4">Mi Perfil</h1>
    <div class="row fondo-container">
        <div class="col-md-6">
            <h2>Información Personal</h2>
            <p><strong>Nombre:</strong> <?php echo htmlspecialchars($user['Nombre']); ?></p>
            <p><strong>Edad:</strong> <?php echo htmlspecialchars($user['Edad']); ?></p>
            <p><strong>Teléfono:</strong> <?php echo htmlspecialchars($user['Numero_telefono']); ?></p>
            <p><strong>Correo Electrónico:</strong> <?php echo htmlspecialchars($user['Correo_electronico']); ?></p>
            <p><strong>CI:</strong> <?php echo htmlspecialchars($user['CI']); ?></p>
        </div>
        <div class="col-md-6">
            <h2>Información de la Cuenta</h2>
            <p><strong>Tipo de Usuario:</strong> <?php echo htmlspecialchars($user['Tipo_usuario']); ?></p>
            <p><strong>Foto de Perfil:</strong></p>
            <!-- Mostrar imagen de perfil -->
            <?php if (!empty($user['Foto_perfil'])): ?>
                <img src="<?php echo htmlspecialchars($user['Foto_perfil']); ?>" alt="Foto de Perfil" class="img-fluid" style="max-width: 200px; max-height: 200px;">
            <?php else: ?>
                <p>No se ha cargado ninguna foto de perfil.</p>
            <?php endif; ?>
            <a href="editar_perfil.php" class="btn btn-primary">Modificar Perfil</a>
        </div>
    </div>
</main>


<footer style="background-color: #007BFF; color: #fff; text-align: center; padding: 0.2rem 0;"> 
    <div class="d-flex justify-content-around d-block d-md-none"> <!-- Alineación en fila, solo en pantallas pequeñas -->
        <div>
            <button class="btn btn-primary" type="button" aria-label="Perfil" onclick="window.location.href='funciones/usuario/perfil.php'">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-person" viewBox="0 0 16 16">
                    <path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6m2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0m4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4m-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10s-3.516.68-4.168 1.332c-.678.678-.83 1.418-.832 1.664z"/>
                </svg>
            </button>
        </div>
        <div>
            <button class="btn btn-primary" type="button" aria-label="Buscar" onclick="window.location.href='funciones/eventos/buscar.php'">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-search" viewBox="0 0 16 16">
                    <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/>
                </svg>
            </button>
        </div>
        <div>
            <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
            <button class="btn btn-primary" type="button" aria-label="Agregar Evento" onclick="window.location.href='funciones/eventos/agregar.php'">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-plus-circle" viewBox="0 0 16 16">
                    <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                    <path d="M8 4a.5.5 0 0 1 .5.5v3h3a.5.5 0 0 1 0 1h-3v3a.5.5 0 0 1-1 0v-3h-3a.5.5 0 0 1 0-1h3v-3A.5.5 0 0 1 8 4"/>
                </svg>
            </button>
            <?php endif; ?>
        </div>
    </div>
</footer>


    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>
    <script src="menu.js"></script>
</body>
</html>