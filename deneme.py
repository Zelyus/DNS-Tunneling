import socket
import pandas as pd
from datetime import datetime
from typing import List, Optional
import struct
import joblib

# Yüklediğiniz modeli yükleyin
model = joblib.load('logistic_regression_model.pkl')



def get_dns_record_type(record_type: str) -> int:
    """DNS kayıt tiplerinin sayısal karşılıklarını döndürür"""
    dns_types = {
        'A': 1,
        'NS': 2,
        'CNAME': 5,
        'MX': 15,
        'TXT': 16,
        'AAAA': 28
    }
    return dns_types.get(record_type, 1)


def create_dns_query(domain: str, record_type: str) -> bytes:
    """DNS sorgu paketi oluşturur"""
    # Rastgele ID oluştur
    transaction_id = struct.pack('H', 1234)

    # Flags
    flags = struct.pack('H', 256)  # Standart sorgu

    # Soru sayısı
    qdcount = struct.pack('H', 1)

    # Diğer sayaçlar
    ancount = struct.pack('H', 0)
    nscount = struct.pack('H', 0)
    arcount = struct.pack('H', 0)

    # Domain adını DNS formatına dönüştür
    labels = domain.split('.')
    dns_name = b''
    for label in labels:
        length = len(label)
        dns_name += struct.pack('B', length)
        dns_name += label.encode()
    dns_name += b'\x00'

    # Sorgu tipi ve sınıfı
    qtype = struct.pack('H', get_dns_record_type(record_type))
    qclass = struct.pack('H', 1)  # IN class

    # Paketi birleştir
    return transaction_id + flags + qdcount + ancount + nscount + arcount + dns_name + qtype + qclass


def analyze_dns_for_url(url: str, record_types: Optional[List[str]] = None) -> pd.DataFrame:
    """
    Belirtilen URL için DNS sorgularını yapar ve sonuçları analiz eder
    """
    if record_types is None:
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']

    dns_records = []
    dns_server = ('8.8.8.8', 53)  # Google DNS

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)

    for record_type in record_types:
        try:
            # DNS sorgusu oluştur ve gönder
            query = create_dns_query(url, record_type)
            sock.sendto(query, dns_server)

            # Yanıtı al
            response, _ = sock.recvfrom(4096)

            # Basit kayıt oluştur (gerçek uygulamada yanıt parse edilmeli)
            record = {
                'ZamanDamgasi': datetime.now().strftime('%H:%M:%S.%f'),
                'Protokol': 'UDP',
                'Kaynak_IP': dns_server[0],
                'Hedef_IP': socket.gethostbyname(url) if record_type == 'A' else None,
                'KimlikNo': len(response),  # Yanıt uzunluğunu ID olarak kullan
                'DNS_Turu': record_type,
                'DNS_Bilgisi': socket.gethostbyname(url) if record_type == 'A' else 'Received',
                'DNS_CevapUzunlugu': len(response)
            }
            dns_records.append(record)

        except socket.gaierror:
            print(f"No {record_type} record found for {url}")
        except socket.timeout:
            print(f"Timeout querying {record_type} record for {url}")
        except Exception as e:
            print(f"Error querying {record_type} record for {url}: {e}")

    sock.close()

    # Sonuçları DataFrame'e dönüştür
    df = pd.DataFrame(dns_records)

    # Modeli kullanarak tahmin yap
    # Veriyi modelin gereksinim duyduğu formatta hazırlayın (Örneğin: ZamanDamgasi_Fark gibi ek özellikler eklemek gerekebilir)
    X = df.drop(['ZamanDamgasi', 'Kaynak_IP', 'Hedef_IP', 'DNS_Bilgisi'], axis=1)  # Modelin kullanacağı özellikler
    predictions = model.predict(X)

    # Tahminleri DataFrame'e ekleyin
    df['Tahmin'] = predictions
    return df


def save_to_csv(df: pd.DataFrame, filename: str = 'dns_analysis_with_predictions.csv') -> None:
    """Sonuçları CSV dosyasına kaydeder"""
    df.to_csv(filename, index=False)
    print(f"Veriler {filename} dosyasına kaydedildi.")


def main():
    # URL'yi burada belirtin
    url = "7.wan.com"  # Analiz etmek istediğiniz domain

    print(f"DNS analizi başlatılıyor: {url}")

    # DNS analizini yap
    results = analyze_dns_for_url(url)

    # Sonuçları kaydet
    save_to_csv(results)

    # Özet istatistikler
    print("\nÖzet İstatistikler:")
    print(f"Toplam kayıt sayısı: {len(results)}")
    print("\nDNS kayıt türleri dağılımı:")
    print(results['DNS_Turu'].value_counts())

    # Detaylı sonuçları göster
    print("\nDetaylı DNS kayıtları:")
    print(results)


if __name__ == "__main__":
    main()
