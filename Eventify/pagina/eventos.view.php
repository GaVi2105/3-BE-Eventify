<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Eventos - Eventify</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../../css/styles.css">
</head>

<header>

    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
            <a href="../../index.php" width="50" height="50">
                <img src="../../icono/Logo.png" alt="Logo" width="50" height="50" class="d-inline-block align-text-top">
            </a>
            <a class="navbar-brand" href="../../index.php">Eventos</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor"
                    class="bi bi-gear-fill" viewBox="0 0 16 16">
                    <path
                        d="M9.405 1.05c-.413-1.4-2.397-1.4-2.81 0l-.1.34a1.464 1.464 0 0 1-2.105.872l-.31-.17c-1.283-.698-2.686.705-1.987 1.987l.169.311c.446.82.023 1.841-.872 2.105l-.34.1c-1.4.413-1.4 2.397 0 2.81l.34.1a1.464 1.464 0 0 1 .872 2.105l-.17.31c-.698 1.283.705 2.686 1.987 1.987l.311-.169a1.464 1.464 0 0 1 2.105.872l.1.34c.413 1.4 2.397 1.4 2.81 0l.1-.34a1.464 1.464 0 0 1 2.105-.872l.31.17c1.283.698 2.686-.705 1.987-1.987l-.169-.311a1.464 1.464 0 0 1 .872-2.105l.34-.1c1.4-.413 1.4-2.397 0-2.81l-.34-.1a1.464 1.464 0 0 1-.872-2.105l.17-.31c.698-1.283-.705-2.686-1.987-1.987l-.311.169a1.464 1.464 0 0 1-2.105-.872zM8 10.93a2.929 2.929 0 1 1 0-5.86 2.929 2.929 0 0 1 0 5.858z" />
                </svg>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item"><a class="nav-link" href="../../index.php">Inicio</a></li>
                    <li class="nav-item"><a class="nav-link" href="../../funciones/eventos/eventos.php">Eventos</a></li>
                    <?php if (isset($_SESSION['usuario'])): ?>
                        <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
                            <li class="nav-item"><a class="nav-link" href="../../funciones/eventos/crear_evento.php">Crear
                                    Evento</a></li>
                        <?php endif; ?>
                        <li class="nav-item"><a class="nav-link" href="../../funciones/eventos/mis_eventos.php">Mis
                                Eventos</a></li>
                        <li class="nav-item"><a class="nav-link" href="../../funciones/usuario/perfil.php">Mi Perfil</a>
                        </li>
                        <li class="nav-item"><a class="nav-link" href="../../funciones/usuario/cerrar_sesion.php">Cerrar
                                Sesión</a></li>
                    <?php else: ?>
                        <li class="nav-item"><a class="nav-link" href="../../funciones/usuario/login.php">Iniciar Sesión</a>
                        </li>
                        <li class="nav-item"><a class="nav-link" href="../usuario/register.php">Registrarse</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>

</header>

<body>

    
    <main>
        <div id="mensajeFinalizado" class="alert alert-warning" style="display:none;">
            Este evento ha finalizado.
        </div>
        <form action="eventos.php" method="get" style="padding-left: 70%;" class="mb-4">
            <div class="row g-3 align-items-center">
                <div class="col-auto">
                    <select name="categoria" id="categoria" class="form-select">
                        <option value="">Todas las categorías</option>
                        <?php while ($cat = $categorias->fetch_assoc()): ?>
                            <option value="<?php echo $cat['ID_categoria']; ?>" <?php echo ($categoria == $cat['ID_categoria']) ? 'selected' : ''; ?>>
                                <?php echo htmlspecialchars($cat['Nombre_categoria']); ?>
                            </option>
                        <?php endwhile; ?>
                    </select>
                </div>
                <div class="col-auto">
                    <button type="submit" class="btn btn-primary">Filtrar</button>
                </div>
            </div>
        </form>
        </main>
    <main style="margin-top: 100px;" class="container mt-4">
        <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
            <?php while ($evento = $eventos->fetch_assoc()): ?>
                <div class="col">
                    <div class="card h-100">
                        <img src="mostrar_imagen.php?id=<?php echo $evento['ID_evento']; ?>" class="card-img-top"
                            alt="Imagen del evento" style="height: 200px; object-fit: cover;">
                        <div class="card-body">
                            <h5 class="card-title"><?php echo htmlspecialchars($evento['Nombre']); ?></h5>
                            <h6 class="card-subtitle mb-2 text-muted">
                                <?php echo htmlspecialchars($evento['Nombre_categoria']); ?>
                            </h6>
                            <p class="card-text">
                                <strong>Fecha:</strong> <?php echo htmlspecialchars($evento['Fecha']); ?><br>
                                <strong>Ubicación:</strong> <?php echo htmlspecialchars($evento['Ubicacion']); ?><br>
                                <strong>Costo de entrada:</strong>
                                $<?php echo htmlspecialchars($evento['Costo_entrada']); ?>
                            </p>

                            <?php
                            // Verificar si el evento ha finalizado
                            $fechaEvento = new DateTime($evento['Fecha']);
                            $fechaActual = new DateTime();

                            if ($fechaActual >= $fechaEvento): ?>
                                <div style="background-color: rgb(255, 101, 101); color: whitesmoke; font-weight: bold;"
                                    class="alert alert-warning">
                                    Este evento ha finalizado.
                                </div>
                            <?php endif; ?>

                            <?php if (isset($_SESSION['usuario']) && $_SESSION['tipo_usuario'] == 'participante'): ?>
                                <form action="participar_evento.php" method="POST">
                                    <input type="hidden" name="id_evento" value="<?php echo $evento['ID_evento']; ?>">
                                    <button type="submit" class="btn btn-primary">Participar</button>
                                </form>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            <?php endwhile; ?>
        </div>

        <nav aria-label="Page navigation" class="mt-4">
            <ul class="pagination justify-content-center">
                <?php for ($i = 1; $i <= $total_pages; $i++): ?>
                    <li class="page-item <?php echo ($page == $i) ? 'active' : ''; ?>">
                        <a class="page-link"
                            href="?page=<?php echo $i; ?>&categoria=<?php echo $categoria; ?>"><?php echo $i; ?></a>
                    </li>
                <?php endfor; ?>
            </ul>
        </nav>
        <br>
    </main>

    <footer class="d-block d-md-none"
        style="background-color: #007BFF; color: #fff; text-align: center; padding: 0.2rem 0;">
        <div class="hstack gap-3"> <!-- Alineación en fila, solo en pantallas pequeñas -->
            <div class="p-1">
                <?php if (isset($_SESSION['usuario'])): ?>
                    <?php if ($_SESSION['tipo_usuario'] == 'participante' || $_SESSION['tipo_usuario'] == 'organizador'): ?>
                        <button class="btn btn-primary" type="button" aria-label="Perfil"
                            onclick="window.location.href='../usuario/perfil.php'">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                                class="bi bi-person-circle" viewBox="0 0 16 16">
                                <path d="M11 6a3 3 0 1 1-6 0 3 3 0 0 1 6 0" />
                                <path fill-rule="evenodd"
                                    d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m8-7a7 7 0 0 0-5.468 11.37C3.242 11.226 4.805 10 8 10s4.757 1.225 5.468 2.37A7 7 0 0 0 8 1" />
                            </svg>
                        </button>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <div class="p-1 ms-auto" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%);">
                <?php if (isset($_SESSION['usuario'])): ?>
                    <?php if ($_SESSION['tipo_usuario'] == 'participante'): ?>
                        <button class="btn btn-primary" type="button" aria-label="Buscar"
                            onclick="window.location.href='eventos.php'">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                                class="bi bi-calendar-event" viewBox="0 0 16 16">
                                <path
                                    d="M3.5 0a.5.5 0 0 1 .5.5V1h9V.5a.5.5 0 0 1 1 0V1h1a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H1a2 2 0 0 1-2-2V3a2 2 0 0 1 2-2h1V.5a.5.5 0 0 1 .5-.5zM1 3v11h14V3H1zm8 5a1 1 0 1 0 0 2 1 1 0 0 0 0-2z" />
                            </svg>
                        </button>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
            <div class="p-1" style="position: absolute; right: 0; top: 50%; transform: translateY(-50%);">
                <?php if (isset($_SESSION['usuario'])): ?>
                    <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
                        <button class="btn btn-primary" type="button" aria-label="Agregar Evento"
                            onclick="window.location.href='crear_evento.php'">
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" fill="currentColor"
                                class="bi bi-plus-lg" viewBox="0 0 16 16">
                                <path fill-rule="evenodd"
                                    d="M8 2a.5.5 0 0 1 .5.5v5h5a.5.5 0 0 1 0 1h-5v5a.5.5 0 0 1-1 0v-5h-5a.5.5 0 0 1 0-1h5v-5A.5.5 0 0 1 8 2" />
                            </svg>
                        </button>
                    <?php endif; ?>
                <?php endif; ?>
            </div>
        </div>
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>
    <script src="../menu.js"></script>
</body>

</html>