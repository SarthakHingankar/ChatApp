document.querySelector(".back-button").addEventListener("click", (e) => {
  e.preventDefault();
  window.history.back();
});

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("loginForm").addEventListener("submit", (e) => {
    e.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value.trim();

    if (username && password) {
      fetch("/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      }).then((response) => {
        if (response.redirected) {
          window.location.href = response.url;
        }
      });
    } else {
      alert("Please fill in both fields.");
    }
  });
});

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("signupForm").addEventListener("submit", (e) => {
    e.preventDefault(); // Prevent the form from submitting traditionally

    const username = document.getElementById("username").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value.trim();
    const confirmPassword = document
      .getElementById("confirmPassword")
      .value.trim();

    // Basic validation
    if (!username || !email || !password || !confirmPassword) {
      alert("Please fill in all fields.");
      return;
    }

    if (password !== confirmPassword) {
      alert("Passwords do not match.");
      return;
    }

    fetch("/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, email, password }),
    }).then((response) => {
      if (response.redirected) {
        window.location.href = response.url;
      }
    });
  });
});
