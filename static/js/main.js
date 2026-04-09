document.querySelector("form").addEventListener("submit", function () {
    // Hide the button
    document.querySelector("button").style.display = "none";

    // Create and show spinner
    const spinner = document.createElement("div");
    spinner.innerHTML = `
        <div class="spinner"></div>
        <p class="scanning-text">Scanning... this may take a few seconds</p>
    `;
    spinner.id = "loading";
    document.querySelector("form").appendChild(spinner);
});