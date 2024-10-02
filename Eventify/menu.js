document.addEventListener('DOMContentLoaded', function() {
    var navbarToggler = document.querySelector('.navbar-toggler');
    var navbarCollapse = document.querySelector('.navbar-collapse');

    // Alterna el estado de 'show' cuando se hace clic en el botón del menú (hamburguesa)
    navbarToggler.addEventListener('click', function(event) {
        event.preventDefault(); // Prevenir el comportamiento por defecto
        navbarCollapse.classList.toggle('show'); // Alterna el menú
    });

    // Cierra el menú cuando se hace clic en un enlace de navegación
    var navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    navLinks.forEach(function(navLink) {
        navLink.addEventListener('click', function() {
            navbarCollapse.classList.remove('show'); // Cierra el menú
        });
    });

    // Cierra el menú cuando se hace clic fuera del menú
    document.addEventListener('click', function(event) {
        var isClickInsideNavbar = navbarCollapse.contains(event.target) || navbarToggler.contains(event.target);
        if (!isClickInsideNavbar && navbarCollapse.classList.contains('show')) {
            navbarCollapse.classList.remove('show'); // Cierra el menú si el clic es fuera del menú
        }
    });
});

// Funcion para mostrar el footer al hacer scroll hacia arriba en cualquier parte de la página

