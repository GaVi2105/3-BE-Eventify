<?php
// editar_perfil.php

include '../configuracion/config.php';
session_start();
verificar_sesion();

$id_usuario = $_SESSION['ID_usuario'];
$mensaje = $error = null;

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if (isset($_POST['actualizar_perfil'])) {
        $nombre = mysqli_real_escape_string($conn, $_POST['nombre']);
        $edad = mysqli_real_escape_string($conn, $_POST['edad']);
        $telefono = mysqli_real_escape_string($conn, $_POST['telefono']);
        $correo = mysqli_real_escape_string($conn, $_POST['correo']);
        $ci = mysqli_real_escape_string($conn, $_POST['ci']);

        $sql_update = "UPDATE Usuario SET Nombre = ?, Edad = ?, Numero_telefono = ?, Correo_electronico = ?, CI = ? WHERE ID_usuario = ?";
        $stmt_update = $conn->prepare($sql_update);
        $stmt_update->bind_param("sisssi", $nombre, $edad, $telefono, $correo, $ci, $id_usuario);

        if ($stmt_update->execute()) {
            $mensaje = "Perfil actualizado exitosamente.";
            $_SESSION['usuario'] = $nombre;
        } else {
            $error = "Error al actualizar el perfil: " . $conn->error;
        }
    }
    elseif (isset($_POST['cambiar_contrasenia'])) {
        $contrasenia_actual = $_POST['contrasenia_actual'];
        $nueva_contrasenia = $_POST['nueva_contrasenia'];
        $confirmar_contrasenia = $_POST['confirmar_contrasenia'];

        // Verificar la contraseña actual
        $sql_check = "SELECT Contrasenia FROM Usuario WHERE ID_usuario = ?";
        $stmt_check = $conn->prepare($sql_check);
        $stmt_check->bind_param("i", $id_usuario);
        $stmt_check->execute();
        $result = $stmt_check->get_result();
        $user = $result->fetch_assoc();

        if (password_verify($contrasenia_actual, $user['Contrasenia'])) {
            if ($nueva_contrasenia === $confirmar_contrasenia) {
                $hashed_password = password_hash($nueva_contrasenia, PASSWORD_DEFAULT);
                $sql_update = "UPDATE Usuario SET Contrasenia = ? WHERE ID_usuario = ?";
                $stmt_update = $conn->prepare($sql_update);
                $stmt_update->bind_param("si", $hashed_password, $id_usuario);

                if ($stmt_update->execute()) {
                    $mensaje = "Contraseña actualizada exitosamente.";
                } else {
                    $error = "Error al actualizar la contraseña: " . $conn->error;
                }
            } else {
                $error = "Las nuevas contraseñas no coinciden.";
            }
        } else {
            $error = "La contraseña actual es incorrecta.";
        }
    }
    elseif (isset($_POST['cambiar_tipo_usuario'])) {
        $nuevo_tipo = mysqli_real_escape_string($conn, $_POST['tipo_usuario']);
        $sql_update = "UPDATE Usuario SET Tipo_usuario = ? WHERE ID_usuario = ?";
        $stmt_update = $conn->prepare($sql_update);
        $stmt_update->bind_param("si", $nuevo_tipo, $id_usuario);

        if ($stmt_update->execute()) {
            $mensaje = "Tipo de usuario actualizado exitosamente.";
            $_SESSION['tipo_usuario'] = $nuevo_tipo;
        } else {
            $error = "Error al actualizar el tipo de usuario: " . $conn->error;
        }
    }
    elseif (isset($_POST['eliminar_cuenta'])) {
        // Eliminar registros relacionados en la tabla organizador
        $sql_delete_organizador = "DELETE FROM organizador WHERE ID_usuario = ?";
        $stmt_delete_organizador = $conn->prepare($sql_delete_organizador);
        $stmt_delete_organizador->bind_param("i", $id_usuario);

        if ($stmt_delete_organizador->execute()) {
            // Eliminar el registro del usuario después de eliminar las dependencias
            $sql_delete_usuario = "DELETE FROM Usuario WHERE ID_usuario = ?";
            $stmt_delete_usuario = $conn->prepare($sql_delete_usuario);
            $stmt_delete_usuario->bind_param("i", $id_usuario);

            if ($stmt_delete_usuario->execute()) {
                // Destruir la sesión y redirigir a la página de inicio
                session_destroy();
                header("Location: ../../index.php");
                exit();
            } else {
                $error = "Error al eliminar el usuario: " . $conn->error;
            }
        } else {
            $error = "Error al eliminar registros relacionados: " . $conn->error;
        }
    }
}

// Obtener la información del usuario para mostrar en la vista
$sql = "SELECT * FROM Usuario WHERE ID_usuario = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $id_usuario);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();

// Incluir la vista del perfil con el formulario de edición
include '../../pagina/editar_perfil.view.php';
?>
