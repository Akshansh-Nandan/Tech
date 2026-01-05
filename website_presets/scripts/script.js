/**
 * Smooth Scroll Handler for Anchor Links
 * Attaches a click listener to all anchor tags whose 'href' starts with '#'.
 * Prevents default click behavior and scrolls the target element into view smoothly.
 */
document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Get the ID of the target element (e.g., #contact)
            const target = document.querySelector(this.getAttribute('href'));
            
            if (target) {
                // Scroll to the element smoothly
                target.scrollIntoView({ 
                    behavior: 'smooth', 
                    // Adjust to 'start' to align the top of the element with the top of the viewport
                    block: 'start' 
                });
            }
        });
    });
});


