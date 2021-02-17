/// refresh.js
/// this code is minifed by refresh-minify.sh
/// all comments should start with 3 forward slashes
/// all statements should end in semicolons
/// the sso path should be referred to as /sso/
(function () {
    /// iframe variable
    var i;

    /// handle window.postMessage event
    function wl(e) {
        console.log('wl');
        if (e.origin !== window.location.protocol + "//" + window.location.host) {
            return;
        }
        if (e.data === 'ssoRefreshDone') {
            i.parentNode.removeChild(i);
            i = undefined;
        }
    }

    window.addEventListener('message', wl);

    /// check that window.postMessage has been called
    /// refresh window if it has not
    function wc() {
        console.log('wc');
        if (i !== undefined) {
            window.location.reload();
        } else {
            console.log('ok');
            xr();
        }
    }

    /// create iframe to refresh session
    function wr(wct) {
        console.log('wr');
        i = document.createElement('iframe');
        i.style.display = 'none';
        i.src = "/sso/refresh/initiate";
        document.body.appendChild(i);
        setTimeout(wc, wct);
    }

    /// handle xhr response
    function xl() {
        console.log('xl');
        var data = JSON.parse(this.responseText);
        var wct = Math.max(Math.min(300, data.expSeconds - 300), 10) * 1000;
        setTimeout(function () { wr(wct) }, Math.max((data.expSeconds - 300) * 1000, 1));
    }

    /// handle xhr error
    function xe() {
        console.log('xe');
        setTimeout(xr, 50000);
    }

    /// perform xhr
    function xr() {
        console.log('xr');
        var x = new XMLHttpRequest();
        x.addEventListener("load", xl);
        x.addEventListener("abort", xe);
        x.addEventListener("error", xe);
        x.addEventListener("timeout", xe);
        x.overrideMimeType("application/json");
        x.open("GET", "/sso/refresh/check");
        x.timeout = 10000;
        x.withCredentials = true;
        x.send();
    }

    xr();

})();
