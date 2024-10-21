<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Participar en Evento - Eventify</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../../css/styles.css">
    <link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
</head>
<header>
    <nav class="navbar navbar-expand-lg navbar-dark bg-primary fixed-top">
        <div class="container-fluid">
            <a href="../../index.php" width="50" height="50">
                <img src="../../icono/Logo.png" alt="Logo" width="50" height="50" class="d-inline-block align-text-top">
            </a>
            <a class="navbar-brand" href="../../index.php">Participación</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" fill="currentColor"
                    class="bi bi-gear-fill" viewBox="0 0 16 16">
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
</header>
<body>
    <main class="container mt-5 pt-5">
        <div style="margin-top: 75px;" class="row justify-content-center">
            <div class="col-md-6">
                <div class="card mb-4">
                    <img src="mostrar_imagen.php?id=<?php echo $evento['ID_evento']; ?>" class="card-img-top"
                        alt="Imagen del evento" style="height: 400px; object-fit: cover;">
                    <div class="card-body">
                        <h3 class="card-title"><?php echo htmlspecialchars($evento['Nombre'] ?? 'Nombre no disponible'); ?></h3>
                        <h5 class="card-subtitle mb-3 text-muted"><?php echo htmlspecialchars($evento['Nombre_categoria'] ?? 'Categoría no disponible'); ?></h5>
                        <p class="card-text">
                            <strong>Descripción:</strong>
                            <?php echo htmlspecialchars($evento['Descripcion'] ?? 'Descripción no disponible'); ?><br>
                            <strong>Fecha:</strong>
                            <?php echo htmlspecialchars($evento['Fecha'] ?? 'Fecha no disponible'); ?><br>
                            <strong>Ubicación:</strong>
                            <?php echo htmlspecialchars($evento['Ubicacion'] ?? 'Ubicación no disponible'); ?><br>
                            <strong>Costo de entrada:</strong>
                            $<?php echo htmlspecialchars($evento['Costo_entrada'] ?? 'Costo no disponible'); ?>
                        </p>
                        <form action="participar_evento.php" method="POST">
                            <input type="hidden" name="id_evento" value="<?php echo $evento['ID_evento']; ?>">
                            <button type="submit" class="btn btn-success btn-lg w-100">Confirmar Participación</button>
                        </form>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div id="map" style="height: 400px; border-radius: 15px;"></div>
            </div>
        </div>
    </main>
    
    <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.11.6/dist/umd/popper.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.min.js"></script>
    <script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

    <script>  
    // Inicializa el mapa  
    var map = L.map('map').setView([-32.3171, -58.08072], 13); // Ajusta el centro del mapa  

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {  
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'  
    }).addTo(map);  

    // Supongamos que tienes un array de eventos en PHP llamado $eventos  
    <?php if (!empty($eventos)) : ?>  
        <?php foreach ($eventos as $evento) : ?>  
            <?php  
                // Supongamos que la ubicación está en formato "lat,lng"  
                list($lat, $lng) = explode(',', $evento['Ubicacion']);  
            ?>  
            // Crear un marcador en la ubicación del evento  
            var marker = L.marker([<?php echo $lat; ?>, <?php echo $lng; ?>]).addTo(map);  
            // Asociar un popup al marcador con la información del evento  
            marker.bindPopup('<b><?php echo $evento['Nombre']; ?></b><br><?php echo $evento['Descripcion']; ?><br><?php echo $evento['Fecha']; ?>');  
        <?php endforeach; ?>  
    <?php else : ?>  
        console.log("No hay eventos disponibles para mostrar.");  
    <?php endif; ?>  
</script>
</body>

</html>
