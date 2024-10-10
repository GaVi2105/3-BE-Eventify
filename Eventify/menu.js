document.addEventListener('DOMContentLoaded', function () {
    var navbarToggler = document.querySelector('.navbar-toggler');
    var navbarCollapse = document.querySelector('.navbar-collapse');

    // Alterna el estado de 'show' cuando se hace clic en el botón del menú (hamburguesa)
    navbarToggler.addEventListener('click', function (event) {
        event.preventDefault(); // Prevenir el comportamiento por defecto
        navbarCollapse.classList.toggle('show'); // Alterna el menú
    });

    // Cierra el menú cuando se hace clic en un enlace de navegación
    var navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    navLinks.forEach(function (navLink) {
        navLink.addEventListener('click', function () {
            navbarCollapse.classList.remove('show'); // Cierra el menú
        });
    });

    // Cierra el menú cuando se hace clic fuera del menú
    document.addEventListener('click', function (event) {
        var isClickInsideNavbar = navbarCollapse.contains(event.target) || navbarToggler.contains(event.target);
        if (!isClickInsideNavbar && navbarCollapse.classList.contains('show')) {
            navbarCollapse.classList.remove('show'); // Cierra el menú si el clic es fuera del menú
        }
    });

    // Función para verificar si el evento ha finalizado
    function verificarEventoFinalizado(fechaEvento) {
        const fechaActual = new Date();
        const fechaEventoDate = new Date(fechaEvento);

        if (fechaActual >= fechaEventoDate) {
            // Mostrar mensaje de evento finalizado
            document.getElementById('mensajeFinalizado').style.display = 'block';
        }
    }

    // Iniciar la verificación cada minuto
    setInterval(function () {
        // Reemplazar con la fecha del evento obtenida desde PHP
        var fechaEvento = "<?php echo $fecha_evento; ?>"; // Asegúrate de tener esta variable disponible en tu script
        verificarEventoFinalizado(fechaEvento);
    }, 60000); // Verifica cada minuto

    // Comprobar al cargar la página
    var fechaEvento = "<?php echo $fecha_evento; ?>"; // Asegúrate de tener esta variable disponible en tu script
    verificarEventoFinalizado(fechaEvento);
});

// Validación del formulario
(function () {
    'use strict'
    var forms = document.querySelectorAll('.needs-validation')
    Array.prototype.slice.call(forms)
        .forEach(function (form) {
            form.addEventListener('submit', function (event) {
                if (!form.checkValidity()) {
                    event.preventDefault()
                    event.stopPropagation()
                }
                form.classList.add('was-validated')
            }, false)
        })
})();


    // Inicializar el mapa
    var map = L.map('map').setView([-34.9011, -56.1645], 13); // Coordenadas iniciales

    // Capa de OpenStreetMap
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '© OpenStreetMap'
    }).addTo(map);

    var marker;

    // Evento de clic en el mapa
    map.on('click', function(e) {
        // Si hay un marcador existente, lo elimina
        if (marker) {
            map.removeLayer(marker);
        }
        
        // Crea un nuevo marcador en la ubicación seleccionada
        marker = L.marker(e.latlng).addTo(map);
        
        // Guarda las coordenadas en el campo oculto
        document.getElementById('ubicacion').value = e.latlng.lat + ',' + e.latlng.lng;

        // Llama a la función para obtener la dirección
        obtenerDireccion(e.latlng);
    });

    // Función para obtener la dirección a partir de las coordenadas
    function obtenerDireccion(latlng) {
        const lat = latlng.lat;
        const lng = latlng.lng;

        fetch(`https://nominatim.openstreetmap.org/reverse?lat=${lat}&lon=${lng}&format=json`)
            .then(response => response.json())
            .then(data => {
                // Actualiza el campo de ubicación con la dirección obtenida
                if (data && data.display_name) {
                    document.getElementById('ubicacion').value = data.display_name; // Guarda la dirección en el campo
                }
            })
            .catch(error => console.error('Error al obtener la dirección:', error));
    }


