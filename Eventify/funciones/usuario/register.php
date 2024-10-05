<?php 
include '../configuracion/config.php';  // Incluye la conexión a la base de datos

$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Obtiene los datos del formulario
    $nombre = mysqli_real_escape_string($conn, $_POST['nombre']);
    $correo = mysqli_real_escape_string($conn, $_POST['correo']);
    $genero = mysqli_real_escape_string($conn, $_POST['genero']);
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
                    // Manejar la carga de la imagen de perfil
                    if (isset($_FILES['imagen_perfil']) && $_FILES['imagen_perfil']['error'] == 0) {
                        $imagen_perfil = file_get_contents($_FILES['imagen_perfil']['tmp_name']);
                    } else {
                        // Imagen genérica si no se sube ninguna
                        $imagen_perfil = file_get_contents('../imagenes/imagen_generica.png');
                    }

                    // Si todo está bien, realiza el hash de la contraseña
                    $contrasenia_hash = password_hash($contrasenia, PASSWORD_DEFAULT);

                    // Inserta el nuevo usuario en la base de datos, incluyendo género y foto de perfil
                    $sql = "INSERT INTO Usuario (Nombre, Correo_electronico, Contrasenia, Edad, Numero_telefono, CI, Tipo_usuario, Genero, Imagen_perfil) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("sssssssss", $nombre, $correo, $contrasenia_hash, $edad, $telefono, $ci, $tipo_usuario, $genero, $imagen_perfil);

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
include '../../pagina/register.view.php';
?>
