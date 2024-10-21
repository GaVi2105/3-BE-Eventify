<?php  
include '../configuracion/config.php';  
session_start();  
verificar_organizador();  

if (!isset($_SESSION['ID_usuario'])) {  
    $error = "Error: Sesión no válida. No se ha encontrado el ID de usuario.";  
} else {  
    $id_usuario = $_SESSION['ID_usuario'];  

    // Manejo de la creación de eventos  
    if ($_SERVER["REQUEST_METHOD"] == "POST") {  
        $nombre = mysqli_real_escape_string($conn, $_POST['nombre']);  
        $descripcion = mysqli_real_escape_string($conn, $_POST['descripcion']);  
        $fecha = mysqli_real_escape_string($conn, $_POST['fecha']);  
        $ubicacion = mysqli_real_escape_string($conn, $_POST['ubicacion']);  
        $costo = mysqli_real_escape_string($conn, $_POST['costo']);  
        $id_categoria = mysqli_real_escape_string($conn, $_POST['id_categoria']);  

        $sql_organizador = "SELECT ID_organizador FROM Organizador WHERE ID_usuario = ?";  
        $stmt_organizador = $conn->prepare($sql_organizador);  
        $stmt_organizador->bind_param("i", $id_usuario);  
        $stmt_organizador->execute();  
        $result_organizador = $stmt_organizador->get_result();  

        if ($result_organizador->num_rows > 0) {  
            $row_organizador = $result_organizador->fetch_assoc();  
            $id_organizador = $row_organizador['ID_organizador'];  

            $sql = "INSERT INTO Evento (Nombre, Descripcion, Fecha, Ubicacion, Costo_entrada, ID_categoria, ID_organizador)   
                    VALUES (?, ?, ?, ?, ?, ?, ?)";  
            $stmt = $conn->prepare($sql);  
            $stmt->bind_param("ssssdii", $nombre, $descripcion, $fecha, $ubicacion, $costo, $id_categoria, $id_organizador);  

            if ($stmt->execute()) {  
                $id_evento = $conn->insert_id;  
                $mensaje = "Evento creado exitosamente.";  

                if (isset($_FILES['imagen']) && $_FILES['imagen']['error'] == 0) {  
                    $resultado_imagen = subir_imagen($_FILES['imagen'], $id_evento);  
                    if (strpos($resultado_imagen, "exitosamente") === false) {  
                        $error = $resultado_imagen;  
                    } else {  
                        $mensaje .= " " . $resultado_imagen;  
                    }  
                }  
            } else {  
                $error = "Error al crear el evento: " . $stmt->error;  
            }  
        } else {  
            $error = "Error: No se encontró el ID del organizador para el usuario actual.";  
        }  
    }  

    // Recuperar eventos para participar  
    $sql_eventos = "SELECT ID_evento, Nombre, Descripcion, Fecha, Ubicacion FROM Evento";  
    $result_eventos = $conn->query($sql_eventos);  
    $eventos = [];  
    while ($row = $result_eventos->fetch_assoc()) {  
        $eventos[] = $row; // Guardar cada evento en un array  
    }  

    $categorias = obtener_categorias();  
    include '../../pagina/crear_evento.php'; // Página para crear evento  
}  
?> 