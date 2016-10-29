$(document).ready(function () {

    var header = $('header');
    var backgrounds = [
      'url(img/logos/shirt1.jpg)',
      'url(img/header-bg.jpg)'];

    var current = 0;
    
    function nextBackground() {
        header.css('background', backgrounds[current = ++current % backgrounds.length] + 'no-repeat');
        header.css('background-size', 'cover');
        header.css('background-attachment', 'scroll');
        header.css('text-align', 'center');
        header.css('-webkit-animation', 'fadeIn 2s');
        header.css('animation', 'fadeIn 2s');
        
        setTimeout(nextBackground, 5000);
    }
    setTimeout(nextBackground, 5000);
    header.css('background', backgrounds[0]);
});