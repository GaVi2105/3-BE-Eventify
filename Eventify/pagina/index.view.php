<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=main-width, initial-scale=1.0">
    <title>Eventify</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="css/styles.css">
</head>

<header>

    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
            <a href="index.php" width="50" height="50">
                <img src="icono/Logo.png" alt="Logo" width="50" height="50" class="d-inline-block align-text-top">
            </a>
            <a class="navbar-brand" href="index.php">Eventify</a>
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
                    <li class="nav-item"><a class="nav-link" href="index.php">Inicio</a></li>
                    <li class="nav-item"><a class="nav-link" href="funciones/eventos/eventos.php">Eventos</a></li>
                    <?php if (isset($_SESSION['usuario'])): ?>
                        <?php if ($_SESSION['tipo_usuario'] == 'organizador'): ?>
                            <li class="nav-item"><a class="nav-link" href="funciones/eventos/crear_evento.php">Crear Evento</a>
                            </li>
                        <?php endif; ?>
                        <li class="nav-item"><a class="nav-link" href="funciones/eventos/mis_eventos.php">Mis Eventos</a>
                        </li>
                        <li class="nav-item"><a class="nav-link" href="funciones/usuario/perfil.php">Mi Perfil</a></li>
                        <li class="nav-item"><a class="nav-link" href="funciones/usuario/cerrar_sesion.php">Cerrar
                                Sesión</a></li>
                    <?php else: ?>
                        <li class="nav-item"><a class="nav-link" href="funciones/usuario/login.php">Iniciar Sesión</a></li>
                        <li class="nav-item"><a class="nav-link" href="funciones/usuario/register.php">Registrarse</a></li>
                    <?php endif; ?>
                </ul>
            </div>
        </div>
    </nav>
</header>

<body>
<main>
    <div id="carouselExampleCaptions" class="carousel slide" data-bs-ride="carousel">
        <div class="carousel-indicators">
            <button type="button" data-bs-target="#carouselExampleCaptions" data-bs-slide-to="0" class="active" aria-current="true" aria-label="Slide 1"></button>
            <button type="button" data-bs-target="#carouselExampleCaptions" data-bs-slide-to="1" aria-label="Slide 2"></button>
            <button type="button" data-bs-target="#carouselExampleCaptions" data-bs-slide-to="2" aria-label="Slide 3"></button>
        </div>
        <div class="carousel-inner">
            <div class="carousel-item active">
                <img src="imagenes/baner azul.jpg" class="d-block w-100" alt="..." style="object-fit: cover; height: 500px;">
                <div class="carousel-caption d-none d-md-block">
                    <img class="banner-img" src="imagenes/SemanaCerveza.jpg" alt="">
                </div>
            </div>
            <div class="carousel-item">
                <img src="imagenes/baner azul.jpg" class="d-block w-100" alt="..." style="object-fit: cover; height: 500px;">
                <div class="carousel-caption d-none d-md-block">
                    <img class="banner-img" src="imagenes/DiaLibro.jpg" alt="">
                </div>
            </div>
            <div class="carousel-item">
                <img src="imagenes/baner azul.jpg" class="d-block w-100" alt="..." style="object-fit: cover; height: 500px;">
                <div class="carousel-caption d-none d-md-block">
                    <img class="banner-img" src="imagenes/GolfNavidad.jpeg" alt="">
                </div>
            </div>
        </div>
        <button class="carousel-control-prev" type="button" data-bs-target="#carouselExampleCaptions" data-bs-slide="prev">
            <span class="carousel-control-prev-icon" aria-hidden="true" style="filter: invert(1);"></span>
            <span class="visually-hidden">Previous</span>
        </button>
        <button class="carousel-control-next" type="button" data-bs-target="#carouselExampleCaptions" data-bs-slide="next">
            <span class="carousel-control-next-icon" aria-hidden="true" style="filter: invert(1);"></span>
            <span class="visually-hidden">Next</span>
        </button>
    </div>
</main>

    <main class="mt-5">
        <div class="container">
            <h2 class="mb-4 mt-4">Eventos Recientes</h2>
            <div class="event-carousel">
                <?php if (!empty($eventos_recientes) && $eventos_recientes->num_rows > 0): ?>
                    <?php foreach ($eventos_recientes as $evento): ?>
                        <div class="event-item">
                            <img src="funciones/eventos/mostrar_imagen.php?id=<?php echo $evento['ID_evento']; ?>"
                                class="card-img-top" alt="Imagen del evento"
                                style="height: 100px; width: 100px; object-fit: cover;">
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p>No hay eventos recientes disponibles.</p>
                <?php endif; ?>
            </div>
            <h2 class="mt-4 mb-4">Eventos Destacados</h2>
            <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-4">
                <?php while ($evento = $eventos_destacados->fetch_assoc()): ?>
                    <div class="col">
                        <div class="card h-100">
                            <img src="funciones/eventos/mostrar_imagen.php?id=<?php echo $evento['ID_evento']; ?>"
                                class="card-img-top" alt="Imagen del evento" style="height: 200px; object-fit: cover;">
                            <div class="card-body">
                                <h5 class="card-title"><?php echo htmlspecialchars($evento['Nombre']); ?></h5>
                                <h6 class="card-subtitle mb-2 text-muted">
                                    <?php echo htmlspecialchars($evento['Nombre_categoria']); ?>
                                </h6>
                                <p class="card-text">
                                    <strong>Fecha:</strong> <?php echo htmlspecialchars($evento['Fecha']); ?><br>
                                    <strong>Ubicación:</strong> <?php echo htmlspecialchars($evento['Ubicacion']); ?><br>
                                    <strong>Descripción:</strong> <?php echo htmlspecialchars($evento['Descripcion']); ?>
                                </p>
                                <a href="funciones/eventos/eventos.php?id=<?php echo $evento['ID_evento']; ?>"
                                    class="btn btn-primary">Ver más</a>
                            </div>
                        </div>
                    </div>
                <?php endwhile; ?>
            </div>

            <h2 class="mt-4 mb-4">Próximos Eventos</h2>
            <p>A continuación, te presentamos una selección de próximos eventos que no te puedes perder:</p>
            <ul class="list-group mb-4">
                <li class="list-group-item">Concierto de Jazz - <strong>Fecha:</strong> 15 de octubre de 2024 -
                    <strong>Ubicación:</strong> Centro Cultural
                </li>
                <li class="list-group-item">Taller de Fotografía - <strong>Fecha:</strong> 22 de octubre de 2024 -
                    <strong>Ubicación:</strong> Estudio Creativo
                </li>
                <li class="list-group-item">Feria de Tecnología - <strong>Fecha:</strong> 5 de noviembre de 2024 -
                    <strong>Ubicación:</strong> Parque de la Innovación
                </li>
            </ul>
    </main>
    <main>
    <div id="carouselExampleDark" class="carousel carousel-dark slide" data-bs-ride="carousel">
        <div class="carousel-indicators">
            <button type="button" data-bs-target="#carouselExampleDark" data-bs-slide-to="0" class="active" aria-current="true" aria-label="Slide 1"></button>
            <button type="button" data-bs-target="#carouselExampleDark" data-bs-slide-to="1" aria-label="Slide 2"></button>
            <button type="button" data-bs-target="#carouselExampleDark" data-bs-slide-to="2" aria-label="Slide 3"></button>
        </div>
        <div class="carousel-inner">
            <div class="carousel-item active" data-bs-interval="10000">
                <img src="imagenes/ElCangue.jpeg" class="d-block w-100" alt="..." style="object-fit: cover; height: 400px;">
                <div class="carousel-caption d-none d-md-block" style="background: rgba(0, 0, 0, 0.5); border-radius: 10px;">
                    <h5 style="color: #fff;">First slide label</h5>
                    <p style="color: #ddd;">Some representative placeholder content for the first slide.</p>
                </div>
            </div>
            <div class="carousel-item" data-bs-interval="2000">
                <img src="imagenes/meseta.jpg" class="d-block w-100" alt="..." style="object-fit: cover; height: 400px;">
                <div class="carousel-caption d-none d-md-block" style="background: rgba(0, 0, 0, 0.5); border-radius: 10px;">
                    <h5 style="color: #fff;">Second slide label</h5>
                    <p style="color: #ddd;">Some representative placeholder content for the second slide.</p>
                </div>
            </div>
            <div class="carousel-item">
                <img src="imagenes/Concierto.webp" class="d-block w-100" alt="..." style="object-fit: cover; height: 400px;">
                <div class="carousel-caption d-none d-md-block" style="background: rgba(0, 0, 0, 0.5); border-radius: 10px;">
                    <h5 style="color: #fff;">Third slide label</h5>
                    <p style="color: #ddd;">Some representative placeholder content for the third slide.</p>
                </div>
            </div>
        </div>
        <button class="carousel-control-prev" type="button" data-bs-target="#carouselExampleDark" data-bs-slide="prev">
            <span class="carousel-control-prev-icon" aria-hidden="true" style="filter: invert(1);"></span>
            <span class="visually-hidden">Previous</span>
        </button>
        <button class="carousel-control-next" type="button" data-bs-target="#carouselExampleDark" data-bs-slide="next">
            <span class="carousel-control-next-icon" aria-hidden="true" style="filter: invert(1);"></span>
            <span class="visually-hidden">Next</span>
        </button>
    </div>
</main>


    <footer class="d-block d-md-none"
        style="background-color: #007BFF; color: #fff; text-align: center; padding: 0.2rem 0;">
        <div class="hstack gap-3">
            <div class="p-1">
                <?php if (isset($_SESSION['usuario'])): ?>
                    <?php if ($_SESSION['tipo_usuario'] == 'participante' || $_SESSION['tipo_usuario'] == 'organizador'): ?>
                        <button class="btn btn-primary" type="button" aria-label="Perfil"
                            onclick="window.location.href='funciones/usuario/perfil.php'">
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
                            onclick="window.location.href='funciones/eventos/eventos.php'">
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
                            onclick="window.location.href='funciones/eventos/crear_evento.php'">
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

    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>
    <script src="menu.js"></script>
</body>

</html>