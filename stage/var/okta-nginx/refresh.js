/// refresh.js
/// this code is minifed by refresh-minify.sh
/// all comments should start with 3 forward slashes
/// all statements should end in semicolons
/// the app origin should be referred to as http://localhost:8080
(function(){
    /// iframe variable
    var i;

    /// handle window.postMessage event
    function wl(e){
        console.log('wl');
        if (e.origin !== 'http://localhost:8080'){
            return;
        }
        if (e.data === 'ssoRefreshDone'){
            i.parentNode.removeChild(i);
            i=undefined;
        }
    }
    window.addEventListener('message', wl);

    /// check that window.postMessage has been called
    /// refresh window if it has not
    function wc(){
        console.log('wc');
        if (i !== undefined){
            window.location.reload();
        } else {
            console.log('ok');
            setTimeout(xr, 50000);
        }
    }

    /// create iframe to refresh session
    function wr(u){
        console.log('wr');
        i = document.createElement('iframe');
        i.style.display = 'none';
        i.src = u;
        document.body.appendChild(i);
        setTimeout(wc, 10000);
    }
    
    /// handle xhr response
    function xl(){
        console.log('xl');
        if (this.responseText == "ok"){
            setTimeout(xr, 60000);
            return;
        }
        wr(this.responseText);
    }

    /// handle xhr error
    function xe(){
        console.log('xe');
        setTimeout(xr, 50000);
    }

    /// perform xhr
    function xr(){
        console.log('xe');
        var x=new XMLHttpRequest();
        x.addEventListener("load", xl);
        x.addEventListener("abort", xe);
        x.addEventListener("error", xe);
        x.addEventListener("timeout", xe);
        x.open("GET", "http://localhost:8080/sso/refresh/check");
        x.timeout=10000;
        x.send();
    }
    xr();

})();
