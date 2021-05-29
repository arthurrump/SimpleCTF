function toggleSolutionVisibility(challengeId) {
    const input = document.getElementById(challengeId + "-solution-input");
    const eye = document.getElementById(challengeId + "-solution-button-eye");
    const eyeSlash = document.getElementById(challengeId + "-solution-button-eye-slash");

    if (input.getAttribute("type") == "password") {
        input.setAttribute("type", "text");
        eye.style.display = "none";
        eyeSlash.style.display = "inline";
    } else {
        input.setAttribute("type", "password");
        eye.style.display = "inline";
        eyeSlash.style.display = "none";
    }
}
