var index = 0;

window.onresize = function() {
  carousel();
};


function carousel() {
  if(window.innerWidth <= 1400) {
    var i;
    var x = document.getElementsByClassName("brand-icon");
    for (i = 0; i < x.length; i++) {
      x[i].style.display = "none";  
    }
    index++;
    if (index > x.length) {index = 1}    
    x[index-1].style.display = "block";  
    setTimeout(carousel, 2000); // Change image every 2 seconds
  }
  
}

document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
      e.preventDefault();

      document.querySelector(this.getAttribute('href')).scrollIntoView({
          behavior: 'smooth'
      });
  });
});

function isElementInViewport(el) {
  const rect = el.getBoundingClientRect();
  return (
      rect.top >= 0 &&
      rect.left >= 0 &&
      rect.bottom <= (window.innerHeight || document.documentElement.clientHeight) &&
      rect.right <= (window.innerWidth || document.documentElement.clientWidth)
  );
}

function handleScroll() {
  const scrollSections = document.getElementsByClassName("scroll-section");
  for (const section of scrollSections) {
      if (isElementInViewport(section)) {
          section.classList.add("visible");
      }
  }
}

window.addEventListener("scroll", handleScroll);

// Function to get URL parameter by name
function getURLParameter(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
}

// Get the "variable" parameter from the URL
const companyName = getURLParameter('co');

// Update the content of the <p> element with the variable value
const lowerVariable = document.getElementById('lowerCompanyName');
lowerVariable.textContent = `Which brings us to this point today: Dear folks at ${companyName}, I would love a chance at an
interview with you, not just to convice you of my abilities as a programmer, but myself as a person.`;

const upperVariable = document.getElementById('upperCompanyName');
upperVariable.textContent = `And this is part of my Application at ${companyName}`;