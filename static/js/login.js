(function () {
    const button = document.getElementById("toggle-password");
    const passwordInput = document.getElementById("password");
    if (!button || !passwordInput) return;

    button.addEventListener("click", function () {
        const isHidden = passwordInput.type === "password";
        passwordInput.type = isHidden ? "text" : "password";
        button.textContent = isHidden ? "Hide Password" : "Show Password";
    });
})();
