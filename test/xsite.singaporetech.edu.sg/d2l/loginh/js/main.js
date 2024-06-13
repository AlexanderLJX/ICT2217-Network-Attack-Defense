function doLogin() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  handleLogin(username, password);
}

function getUrlParam(n) {
  const half = location.search.split(n + '=')[1];
  return half !== undefined ? decodeURIComponent(half.split('&')[0]) : null;
}

function updateCopyrightYear() {
  var copyrightYear = document.getElementById('copyrightYear');
  copyrightYear.innerHTML = new Date().getFullYear();
}

function passQueries() {
  passParametersForSaml('samlLinkId');
  passParameters('guestLoginLinkId');
  passParameters('link1');
  passParameters('link2');
}

document.addEventListener("DOMContentLoaded", function () {
  passQueries();
  updateCopyrightYear();

  if ( getUrlParam('failed') === '1' ) {
    document.querySelector('.failed').classList.remove('hidden');
  }
});
