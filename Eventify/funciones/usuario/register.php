<?php 
include '../configuracion/config.php';  // Incluye la conexión a la base de datos

$error = '';

// Verifica si el formulario fue enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Obtiene los datos del formulario
    $nombre = mysqli_real_escape_string($conn, $_POST['nombre']);
    $correo = mysqli_real_escape_string($conn, $_POST['correo']);
    $contrasenia = $_POST['contrasenia'];
    $confirmar_contrasenia = $_POST['confirmar_contrasenia'];
    $edad = mysqli_real_escape_string($conn, $_POST['edad']);
    $telefono = mysqli_real_escape_string($conn, $_POST['telefono']);
    $ci = mysqli_real_escape_string($conn, $_POST['ci']);
    $tipo_usuario = mysqli_real_escape_string($conn, $_POST['tipo_usuario']);

    // Verifica si las contraseñas coinciden
    if ($contrasenia !== $confirmar_contrasenia) {
        $error = "Las contraseñas no coinciden";
    } 
    // Verifica que la contraseña cumpla con los requisitos
    elseif (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^*()\-+=\[\]{}<>|:;.\'",\/\\\\~`¡¿°¬¨_€£¥₱¢₹])[A-Za-z\d@$!%*?&#^*()\-+=\[\]{}<>|:;.\'",\/\\\\~`¡¿°¬¨_€£¥₱¢₹]{8,20}$/', $contrasenia)) {
        $error = "La contraseña debe tener entre 8 y 20 caracteres, incluyendo al menos una letra mayúscula, una letra minúscula, un número y un carácter especial (@, $, !, %, *, ?, &, #, ^, (), -, +, =, [], {}, <>, |, :, ;, ., \", ', /, \\, ~, `, ¡, ¿, °, ¬, ¨, _, €, £, ¥, ₱, ¢, ₹).";
    }
    // Verifica que la edad esté en el rango permitido
    elseif ($edad < 18 || $edad > 90) {
        $error = "La edad debe estar entre 18 y 90 años.";
    } else {
        // Verifica si el correo ya está registrado
        $sql_check_email = "SELECT * FROM Usuario WHERE Correo_electronico = ?";
        $stmt_check_email = $conn->prepare($sql_check_email);
        $stmt_check_email->bind_param("s", $correo);
        $stmt_check_email->execute();
        $result_email = $stmt_check_email->get_result();

        if ($result_email->num_rows > 0) {
            $error = "Este correo ya está registrado.";
        } else {
            // Verifica si el número de teléfono ya está registrado
            $sql_check_phone = "SELECT * FROM Usuario WHERE Numero_telefono = ?";
            $stmt_check_phone = $conn->prepare($sql_check_phone);
            $stmt_check_phone->bind_param("s", $telefono);
            $stmt_check_phone->execute();
            $result_phone = $stmt_check_phone->get_result();

            if ($result_phone->num_rows > 0) {
                $error = "Este número de teléfono ya está registrado.";
            } else {
                // Verifica si la cédula ya está registrada
                $sql_check_ci = "SELECT * FROM Usuario WHERE CI = ?";
                $stmt_check_ci = $conn->prepare($sql_check_ci);
                $stmt_check_ci->bind_param("s", $ci);
                $stmt_check_ci->execute();
                $result_ci = $stmt_check_ci->get_result();

                if ($result_ci->num_rows > 0) {
                    $error = "Esta cédula ya está registrada.";
                } else {
                    // Si todo está bien, realiza el hash de la contraseña
                    $contrasenia_hash = password_hash($contrasenia, PASSWORD_DEFAULT);

                    // Inserta el nuevo usuario en la base de datos
                    $sql = "INSERT INTO Usuario (Nombre, Correo_electronico, Contrasenia, Edad, Numero_telefono, CI, Tipo_usuario) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("sssssss", $nombre, $correo, $contrasenia_hash, $edad, $telefono, $ci, $tipo_usuario);

                    if ($stmt->execute()) {
                        $id_usuario = $conn->insert_id;

                        // Si es organizador, inserta en la tabla Organizador
                        if ($tipo_usuario == 'organizador') {
                            $sql_organizador = "INSERT INTO Organizador (ID_usuario) VALUES (?)";
                            $stmt_organizador = $conn->prepare($sql_organizador);
                            $stmt_organizador->bind_param("i", $id_usuario);
                            if ($stmt_organizador->execute()) {
                                header("Location: login.php?registro_exitoso=1");
                                exit();
                            } else {
                                $error = "Error al registrar el organizador: " . $stmt_organizador->error;
                            }
                        } else {
                            header("Location: login.php?registro_exitoso=1");
                            exit();
                        }
                    } else {
                        $error = "Error al registrar el usuario: " . $stmt->error;
                    }
                }
            }
        }
    }
}

/* if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $nombre = $_POST['nombre'];
    $email = $_POST['email'];

    $directorio_destino = "uploads/perfiles/";
    $archivo_imagen = $directorio_destino . basename($_FILES["imagen_perfil"]["name"]);
    $tipo_imagen = strtolower(pathinfo($archivo_imagen, PATHINFO_EXTENSION));
    $uploadOk = 1;

    $check = getimagesize($_FILES["imagen_perfil"]["tmp_name"]);
    if ($check !== false) {
        $uploadOk = 1;
    } else {
        echo "El archivo no es una imagen.";
        $uploadOk = 0;
    }

    if ($_FILES["imagen_perfil"]["size"] > 500000) {
        echo "El archivo es demasiado grande.";
        $uploadOk = 0;
    }

    if ($tipo_imagen != "jpg" && $tipo_imagen != "png" && $tipo_imagen != "jpeg" && $tipo_imagen != "gif") {
        echo "Solo se permiten archivos JPG, JPEG, PNG y GIF.";
        $uploadOk = 0;
    }

    if ($uploadOk == 1) {
        if (move_uploaded_file($_FILES["imagen_perfil"]["tmp_name"], $archivo_imagen)) {
            echo "La imagen ". htmlspecialchars(basename($_FILES["imagen_perfil"]["name"])) . " ha sido subida.";
            $sql = "INSERT INTO usuarios (nombre, email, imagen_perfil) VALUES ('$nombre', '$email', '$archivo_imagen')";
            if (mysqli_query($conn, $sql)) {
                echo "Registro exitoso.";
            } else {
                echo "Error al registrar el usuario: " . mysqli_error($conn);
            }
        } else {
            echo "Hubo un error al subir la imagen.";
        }
    }
} */
include '../../pagina/register.view.php';
?>
