chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const currentUrl = tabs[0].url;
    const statusDiv = document.getElementById("status");
    const detailsDiv = document.getElementById("details");

    statusDiv.innerText = "Analyzing...";

    fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: currentUrl, check_visual: false })
    })
        .then(resp => resp.json())
        .then(data => {
            const report = data.report;
            if (report.is_malicious) {
                statusDiv.innerText = "🚩 SUSPICIOUS";
                statusDiv.className = "danger";
                detailsDiv.innerText = report.reasons.join(", ");
            } else {
                statusDiv.innerText = "✅ SAFE";
                statusDiv.className = "safe";
                detailsDiv.innerText = "No threats detected.";
            }
        })
        .catch(err => {
            statusDiv.innerText = "Error: Backend unreachable";
            detailsDiv.innerText = "Make sure the FastAPI server is running.";
        });
});
