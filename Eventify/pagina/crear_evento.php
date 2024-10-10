<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Crear Evento - Eventify</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../../css/styles.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
</head>

<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
            <a href="../../index.php" width="50" height="50">
                <img src="../../icono/Logo.png" alt="Logo" width="50" height="50" class="d-inline-block align-text-top">
            </a>
            <a class="navbar-brand" href="../../index.php">Crear Evento</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor" class="bi bi-gear-fill" viewBox="0 0 16 16">
                    <path d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z" />
                </svg>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="../../index.php">Inicio</a></li>
                    <li class="nav-item"><a class="nav-link" href="eventos.php">Eventos</a></li>
                    <?php if (isset($_SESSION['usuario'])): ?>
                        <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
                            <li class="nav-item"><a class="nav-link" href="crear_evento.php">Crear Evento</a></li>
                        <?php endif; ?>
                        <li class="nav-item"><a class="nav-link" href="mis_eventos.php">Mis Eventos</a></li>
                        <li class="nav-item"><a class="nav-link" href="../usuario/perfil.php">Mi Perfil</a></li>
                        <li class="nav-item"><a class="nav-link" href="../usuario/cerrar_sesion.php">Cerrar Sesión</a></li>
                    <?php else: ?>
                        <li class="nav-item"><a class="nav-link" href="../usuario/login.php">Iniciar Sesión</a></li>
                        <li class="nav-item"><a class="nav-link" href="../usuario/register.php">Registrarse</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

    <main style="padding-top: 5%;" class="container mt-4">
        <?php if (isset($mensaje)): ?>
            <div class="alert alert-success"><?= $mensaje; ?></div>
        <?php endif; ?>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger"><?= $error; ?></div>
        <?php endif; ?>

        <form method="post" enctype="multipart/form-data" class="needs-validation" novalidate>
            <div class="mb-3">
                <label for="nombre" class="form-label">Nombre:</label>
                <input type="text" class="form-control" id="nombre" name="nombre" required>
            </div>

            <div class="mb-3">
                <label for="descripcion" class="form-label">Descripción:</label>
                <textarea class="form-control" id="descripcion" name="descripcion" required></textarea>
            </div>

            <div class="mb-3">
                <label for="fecha" class="form-label">Fecha:</label>
                <input type="datetime-local" class="form-control" id="fecha" name="fecha" required>
            </div>

            <div id="map" style="height: 400px; width: 100%;"></div>
            <div class="mb-3">
                <label for="ubicacion" class="form-label">Ubicación:</label>
                <input type="text" class="form-control" id="ubicacion" name="ubicacion" required readonly>
            </div>

            <div class="mb-3">
                <label for="costo" class="form-label">Costo:</label>
                <input type="number" class="form-control" id="costo" name="costo" step="0.01" required>
            </div>

            <div class="mb-3">
                <label for="id_categoria" class="form-label">Categoría:</label>
                <select class="form-select" id="id_categoria" name="id_categoria" required>
                    <?php while ($cat = $categorias->fetch_assoc()): ?>
                        <option value="<?= $cat['ID_categoria']; ?>"><?= htmlspecialchars($cat['Nombre_categoria']); ?></option>
                    <?php endwhile; ?>
                </select>
            </div>

            <div class="mb-3">
                <label for="imagen" class="form-label">Imagen del evento:</label>
                <input type="file" class="form-control" id="imagen" name="imagen" accept="image/*">
            </div>

            <button type="submit" class="btn btn-primary">Crear Evento</button>
        </form>
        <br>
        <br>
        <br>
    </main>

    <footer class="d-block d-md-none" style="background-color: #007BFF; color: #fff; text-align: center; padding: 0.2rem 0;">
        <div class="hstack gap-3">
            <div class="p-1">
                <button class="btn btn-primary" type="button" aria-label="Perfil" onclick="window.location.href='../usuario/perfil.php'">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-person-circle" viewBox="0 0 16 16">
                        <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0" />
                        <path fill-rule="evenodd" d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1" />
                    </svg>
                </button>
            </div>
            <div class="p-1 ms-auto" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%);">
                <?php if (isset($_SESSION['usuario'])): ?>
                    <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
                        <button class="btn btn-primary" type="button" aria-label="Eventos" onclick="window.location.href='eventos.php'">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor" class="bi bi-calendar-event" viewBox="0 0 16 16">
                                <path d="M3.5 0a.5.5 0 0 1 .5.5V1h9V.5a.5.5 0 0 1 1 0V1h1a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H1a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2h1V.5a.5.5 0 0 1 .5-.5zM1 3v11h14V3H1zm8 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2z" />
                            </svg>
                        </button>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.10.2/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>
    <script src="../../menu.js"></script>
</body>

</html>