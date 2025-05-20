// Add any JavaScript functionality here

document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for navigation links
    const navLinks = document.querySelectorAll('header nav ul li a');

    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            let targetElement;

            if (targetId === '#top') {
                targetElement = document.body; // Or document.documentElement for some browsers
            } else {
                targetElement = document.querySelector(targetId);
            }

            if (targetElement) {
                let offsetTop = targetElement.offsetTop;
                if (targetId !== '#top') {
                    offsetTop -= 70; // Adjust for fixed header, not for #top target
                }
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Back to Top Button Functionality
    const backToTopButton = document.getElementById('back-to-top-btn');

    if (backToTopButton) {
        window.onscroll = function() {
            if (document.body.scrollTop > 100 || document.documentElement.scrollTop > 100) {
                backToTopButton.style.display = "block";
                setTimeout(() => backToTopButton.style.opacity = "1", 10); // Fade in
            } else {
                backToTopButton.style.opacity = "0";
                setTimeout(() => backToTopButton.style.display = "none", 300); // Fade out
            }
        };

        backToTopButton.addEventListener('click', function(e) {
            e.preventDefault(); // Prevent default anchor behavior
            // The smooth scroll for #top is already handled by the navLinks logic if we reuse it.
            // Alternatively, a direct scroll to top:
            window.scrollTo({
                top: 0,
                behavior: 'smooth'
            });
        });
    }
}); 