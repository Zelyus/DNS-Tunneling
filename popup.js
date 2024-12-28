// Kullanıcının ziyaret ettiği web sayfasını analiz edin
function analyzePage() {
    const dnsInfo = "örnek_dns_bilgisi"; // Web sayfasından elde edilen DNS bilgisi
    const dnsType = "A"; // Örnek DNS türü

    // Python API'ye veri gönderin
    fetch("http://localhost:5000/predict", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            dns_info: dnsInfo,
            dns_type: dnsType
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.result === "Tunnel") {
            alert("Bu sayfa bir tünelleme saldırısı içeriyor olabilir!");
        } else {
            alert("Sayfa güvenli görünüyor.");
        }
    })
    .catch(error => {
        console.error("Hata oluştu:", error);
    });
}

// Popup'taki düğmeye tıklanınca çalıştırın
document.getElementById("analyzeButton").addEventListener("click", analyzePage);
