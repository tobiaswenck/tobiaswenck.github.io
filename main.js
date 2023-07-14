var index = 0;
carousel();

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