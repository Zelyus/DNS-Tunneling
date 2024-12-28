import re
import math

def hesapla_entropi(dns_adresi):
    """Bir stringin entropisini hesaplar."""
    if not dns_adresi:
        return 0
    frekanslar = {char: dns_adresi.count(char) for char in set(dns_adresi)}
    toplam = len(dns_adresi)
    entropi = -sum((frekans / toplam) * math.log2(frekans / toplam) for frekans in frekanslar.values())
    return entropi

def predict_dns_tuneli(dns_paketi):
    """Verilen DNS paketi için tünel tespiti yapar."""
    # DNS adresini paket içinden çıkar
    dns_adresi = re.search(r"\?\s([a-zA-Z0-9\.\-]+)\.\s", dns_paketi)
    dns_adresi = dns_adresi.group(1) if dns_adresi else ""

    # Özellikleri hesapla
    alt_alan_adi_uzunlugu = len(dns_adresi.split('.')[0]) if '.' in dns_adresi else len(dns_adresi)
    benzersiz_karakter_orani = len(set(dns_adresi)) / len(dns_adresi) if dns_adresi else 0
    rakam_orani = sum(char.isdigit() for char in dns_adresi) / len(dns_adresi) if dns_adresi else 0
    entropi = hesapla_entropi(dns_adresi)
    base64_orani = len(re.findall(r"[A-Za-z0-9+/=]", dns_adresi)) / len(dns_adresi) if dns_adresi else 0
    hex_orani = len(re.findall(r"[0-9a-fA-F]", dns_adresi)) / len(dns_adresi) if dns_adresi else 0

    # Karar kriterleri
    nedenler = []
    if alt_alan_adi_uzunlugu > 30:
        nedenler.append("Alt alan adı uzunluğu 30'dan büyük.")
    if benzersiz_karakter_orani > 0.8:
        nedenler.append("Benzersiz karakter oranı %80'den büyük.")
    if entropi > 3.5:
        nedenler.append("Entropi 3.5'ten büyük.")
    if base64_orani > 0.6:
        nedenler.append("Base64 oranı %60'tan büyük.")
    if hex_orani > 0.6:
        nedenler.append("Hex oranı %60'tan büyük.")

    tahmin = "DNS Tüneli Algılandı" if nedenler else "DNS Tüneli Algılanmadı"

    return {
        "tahmin": tahmin,
        "guven": f"{len(nedenler) / 5 * 100:.2f}%",  # Basit bir güven yüzdesi
        "ozellikler": {
            "alt_alan_adi_uzunlugu": alt_alan_adi_uzunlugu,
            "benzersiz_karakter_orani": round(benzersiz_karakter_orani, 3),
            "rakam_orani": round(rakam_orani, 3),
            "entropi": round(entropi, 3),
            "base64_orani": round(base64_orani, 3),
            "hex_orani": round(hex_orani, 3),
        },
        "nedenler": nedenler
    }

if __name__ == "__main__":
    print("DNS Tüneli Tespiti Aracı")
    print("-" * 50)
    while True:
        kullanici_girdisi = input("Lütfen bir DNS paketi girin (çıkmak için 'exit' yazın):\n")
        if kullanici_girdisi.lower() == "exit":
            print("Çıkış yapılıyor...")
            break

        try:
            sonuc = predict_dns_tuneli(kullanici_girdisi)
            print(f"\nGirdi Paket: {kullanici_girdisi}")
            print(f"Tahmin: {sonuc['tahmin']}")
            print(f"Güven: {sonuc['guven']}")
            print("\nÖzellik Analizi:")
            for ozellik, deger in sonuc['ozellikler'].items():
                print(f"- {ozellik}: {deger}")
            print("\nTespit Nedenleri:")
            for neden in sonuc['nedenler']:
                print(f"- {neden}")
            print("-" * 50)
        except Exception as e:
            print(f"Paket analizi sırasında hata oluştu: {str(e)}")
