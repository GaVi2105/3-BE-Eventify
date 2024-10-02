<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "eventify";

// Crear la conexión a la base de datos
$conn = new mysqli($servername, $username, $password, $dbname);

// Verificar si hay errores en la conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Función para verificar si el usuario ha iniciado sesión
function verificar_sesion()
{
    if (!isset($_SESSION['usuario'])) {
        header("Location: funciones/usuario/login.php");
        exit();
    }
}

// Función para verificar si el usuario es organizador
function verificar_organizador()
{
    if (!isset($_SESSION['usuario']) || $_SESSION['tipo_usuario'] != 'organizador') {
        header("Location: ../../index.php");
        exit();
    }
}

// Obtener eventos destacados
function obtener_eventos_destacados($limit = 3)
{
    global $conn;
    $sql = "SELECT e.*, c.Nombre_categoria FROM Evento e 
            JOIN Categoria c ON e.ID_categoria = c.ID_categoria 
            ORDER BY e.Fecha DESC LIMIT ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $limit);
    $stmt->execute();
    return $stmt->get_result();
}

// Obtener eventos con paginación
function obtener_eventos($page = 1, $items_per_page = 10, $categoria = null)
{
    global $conn;
    $offset = ($page - 1) * $items_per_page;

    $sql = "SELECT e.*, c.Nombre_categoria FROM Evento e 
            JOIN Categoria c ON e.ID_categoria = c.ID_categoria";

    if ($categoria) {
        $sql .= " WHERE c.ID_categoria = ?";
    }

    $sql .= " ORDER BY e.Fecha DESC LIMIT ? OFFSET ?";

    $stmt = $conn->prepare($sql);

    if ($categoria) {
        $stmt->bind_param("iii", $categoria, $items_per_page, $offset);
    } else {
        $stmt->bind_param("ii", $items_per_page, $offset);
    }

    $stmt->execute();
    return $stmt->get_result();
}

// Obtener el número total de eventos
function obtener_total_eventos($categoria = null)
{
    global $conn;
    $sql = "SELECT COUNT(*) as total FROM Evento";

    if ($categoria) {
        $sql .= " WHERE ID_categoria = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("i", $categoria);
    } else {
        $stmt = $conn->prepare($sql);
    }

    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    return $row['total'];
}

// Obtener todas las categorías de eventos
function obtener_categorias()
{
    global $conn;
    $sql = "SELECT * FROM Categoria";
    $result = $conn->query($sql);
    return $result;
}

// Función para subir una imagen a la base de datos
function subir_imagen($file, $id_evento)
{
    global $conn;

    // Verificar si se subió el archivo
    if (!isset($file['tmp_name']) || empty($file['tmp_name'])) {
        return "No se subió ningún archivo.";
    }

    // Tipos de archivos permitidos (agregado BMP, TIFF, WebP)
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/tiff', 'image/webp'];
    if (!in_array($file['type'], $allowed_types)) {
        return "Tipo de archivo no permitido. Solo se permiten JPG, PNG, GIF, BMP, TIFF y WebP.";
    }

    // Validar el tamaño del archivo (100MB)
    if ($file['size'] > 100 * 1024 * 1024) {
        return "El archivo es demasiado grande. El tamaño máximo permitido es 100MB.";
    }

    // Obtener información de la imagen
    $image_info = getimagesize($file['tmp_name']);
    if ($image_info === false) {
        return "No se pudo obtener la información de la imagen.";
    }

    // Validar las dimensiones de la imagen (máximo 3840x2160)
    $max_width = 3840;
    $max_height = 2160;
    if ($image_info[0] > $max_width || $image_info[1] > $max_height) {
        return "La resolución de la imagen es demasiado alta. El máximo permitido es 4K (3840x2160 píxeles).";
    }

    // Leer el contenido del archivo de imagen
    $imagen_contenido = file_get_contents($file['tmp_name']);
    if ($imagen_contenido === false) {
        return "Error al leer el archivo.";
    }

    // Preparar la consulta para actualizar la imagen en la base de datos
    $sql = "UPDATE Evento SET Imagen_evento = ? WHERE ID_evento = ?";
    $stmt = $conn->prepare($sql);

    // Asegurarse de que el primer parámetro (imagen) sea NULL para luego agregar los datos grandes
    $null = NULL;
    $stmt->bind_param("bi", $null, $id_evento);

    // Enviar los datos largos de la imagen
    $stmt->send_long_data(0, $imagen_contenido);

    // Ejecutar la consulta y verificar si fue exitosa
    if ($stmt->execute()) {
        return "Imagen subida y guardada en la base de datos exitosamente.";
    } else {
        return "Error al guardar la imagen en la base de datos: " . $stmt->error;
    }
}

// Obtener los eventos más recientes
function obtener_eventos_recientes($limit = 10) {
    global $conn;
    $sql = "SELECT e.ID_evento, e.Nombre, e.Fecha, e.Imagen_evento FROM Evento e
            ORDER BY e.Fecha DESC LIMIT ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $limit);
    $stmt->execute();
    return $stmt->get_result();
}
?>
