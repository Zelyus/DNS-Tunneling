chrome.webRequest.onBeforeRequest.addListener(
  function (details) {
    // DNS sorgusunu yakala
    const dnsQuery = details.url;

    // Entropi hesaplama fonksiyonu
    function calculateEntropy(text) {
      if (!text) return 0;
      let entropy = 0;
      const len = text.length;
      const frequencies = {};
      for (const char of text) {
        frequencies[char] = (frequencies[char] || 0) + 1;
      }
      for (const char in frequencies) {
        const p = frequencies[char] / len;
        entropy -= p * Math.log2(p);
      }
      return entropy;
    }

    // Entropiyi hesapla
    const entropy = calculateEntropy(dnsQuery);

    // Entropiye dayalı tünelleme analizi (örnek eşik: 4.5)
    const isTunnel = entropy > 4.5;

    // Sonucu konsola yazdır
    console.log(`DNS Sorgusu: ${dnsQuery}`);
    console.log(`Entropi: ${entropy}`);
    console.log(`Tünelleme mi? ${isTunnel ? "Evet" : "Hayır"}`);

    // İsterseniz tünelleme şüpheli sorguları başka bir yere gönderin
    if (isTunnel) {
      chrome.storage.local.set({ suspiciousQuery: dnsQuery });
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);
