document.addEventListener('DOMContentLoaded', function() {
    console.log('Redesign project loaded');
    
    initAnimations();
    
    initInteractiveElements();
});

function initAnimations() {
    gsap.from("h1", {
        duration: 1,
        y: 50,
        opacity: 0,
        ease: "power3.out"
    });
    
    gsap.from("p", {
        duration: 1,
        y: 30,
        opacity: 0,
        delay: 0.3,
        ease: "power3.out"
    });
    
    gsap.from("svg, .ph", {
        duration: 1,
        scale: 0,
        rotation: 360,
        delay: 0.6,
        ease: "back.out(1.7)"
    });
}

function initInteractiveElements() {
    const buttons = document.querySelectorAll('.btn-primary');
    
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            gsap.to(button, {
                duration: 0.3,
                scale: 1.05,
                ease: "power2.out"
            });
        });
        
        button.addEventListener('mouseleave', () => {
            gsap.to(button, {
                duration: 0.3,
                scale: 1,
                ease: "power2.out"
            });
        });
    });
}

function fadeIn(element, delay = 0) {
    gsap.from(element, {
        duration: 0.8,
        y: 30,
        opacity: 0,
        delay: delay,
        ease: "power3.out"
    });
}

function slideIn(element, direction = 'left', delay = 0) {
    const x = direction === 'left' ? -100 : 100;
    
    gsap.from(element, {
        duration: 1,
        x: x,
        opacity: 0,
        delay: delay,
        ease: "power3.out"
    });
}

window.DesignUtils = {
    fadeIn,
    slideIn
}; 