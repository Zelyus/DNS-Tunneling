import joblib
import pandas as pd
import socket
from urllib.parse import urlparse


# URL'den domain ve IP adresini çıkaran fonksiyon
def get_dns_from_url(url):
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc or parsed_url.path
        if not domain:
            domain = url
        ip_address = socket.gethostbyname(domain)
        return domain, ip_address
    except Exception as e:
        print(f"DNS çözümlemesi sırasında hata oluştu: {e}")
        return None, None


# DNS sorgusunu modele uygun özelliklere dönüştüren fonksiyon
def preprocess_dns_input(dns_input):
    # Modelin eğitimi sırasında kullanılan özelliklere uygun hale getiriliyor
    features = {
        'DNS_CevapUzunlugu': len(dns_input),
        'DNS_Turu_0/0/0': 1 if '0/0/0' in dns_input else 0,
        'DNS_Turu_0/1/0': 1 if '0/1/0' in dns_input else 0,
        'DNS_Turu_192.168.3.102,': 1 if '192.168.3.102,' in dns_input else 0,
        'DNS_Turu_192.168.3.103,': 1 if '192.168.3.103,' in dns_input else 0,
        # Modelin eğitiminde kullanılan diğer özellikleri buraya ekleyin
    }
    return pd.DataFrame([features])


# DNS tünelleme olup olmadığını tahmin eden fonksiyon
def predict_dns_tunneling(domain, model_path):
    try:
        # Modeli yükleme
        model = joblib.load(model_path)

        # Domaini işleme
        processed_input = preprocess_dns_input(domain)

        # Tahmin yapma
        prediction = model.predict(processed_input)

        if prediction[0] == 1:
            return "Bu DNS sorgusu tünelleme içeriyor."
        else:
            return "Bu DNS sorgusu tünelleme içermiyor."
    except Exception as e:
        return f"Model tahmini sırasında hata oluştu: {e}"


# Ana fonksiyon
if __name__ == "__main__":
    model_path = "RandomForest.pkl"  # .pkl dosyasının yolu
    while True:
        url = input("Bir URL girin: ")
        domain, ip_address = get_dns_from_url(url)
        if domain and ip_address:
            print(f"Çıkarılan domain: {domain}")
            print(f"Çözümlenen IP adresi: {ip_address}")

            # Tahmin yapma
            result = predict_dns_tunneling(domain, model_path)
            print(result)
        else:
            print("Geçersiz URL veya DNS çözümlemesi yapılamadı.")

        # Yeni URL girme isteği
        continue_input = input("Başka bir URL girmek ister misiniz? (e/h): ").strip().lower()
        if continue_input != 'e':
            break
