// Theme toggle with localStorage persistence. The inline <head> snippet in
// base.html applies the stored theme pre-paint; this wires the button.
(function () {
  var btn = document.getElementById("theme-toggle");
  if (!btn) return;
  function label() {
    var dark = document.documentElement.dataset.theme !== "light";
    btn.textContent = dark ? "Light" : "Dark";
  }
  btn.addEventListener("click", function () {
    var next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("traefikctl-theme", next); } catch (e) {}
    label();
  });
  label();
})();
