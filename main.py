import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression  # Lojistik Regresyon'ı içe aktar
from sklearn.metrics import accuracy_score, classification_report
import math
import joblib
# Veri setlerini yükle
tunnel_data = pd.read_csv("Tunnelling_data.txt", delim_whitespace=True, on_bad_lines='skip', header=None)
legitimate_data = pd.read_csv("Legitimate_data.txt", delim_whitespace=True, on_bad_lines='skip', header=None)

# Gereksiz sütunları kaldır
tunnel_data = tunnel_data.drop(columns=[3])
legitimate_data = legitimate_data.drop(columns=[3])

# Sütun adlarını belirle
column_names = ["ZamanDamgasi", "Protokol", "Kaynak_IP", "Hedef_IP", "KimlikNo", "DNS_Turu", "DNS_Bilgisi", "DNS_CevapUzunlugu"]
tunnel_data.columns = column_names
legitimate_data.columns = column_names

# "Etiket" sütununu ekle ve verileri etiketle
tunnel_data["Etiket"] = "Tunnel"
legitimate_data["Etiket"] = "Normal"

# Veri kümelerini birleştir
data = pd.concat([tunnel_data, legitimate_data])

# "DNS_CevapUzunlugu" sütununu temizle ve sayısal hale getir
data["DNS_CevapUzunlugu"] = data["DNS_CevapUzunlugu"].astype(str).str.extract(r'\((\d+)\)')
data["DNS_CevapUzunlugu"] = pd.to_numeric(data["DNS_CevapUzunlugu"], errors='coerce').fillna(0).astype(int)

# Gereksiz DNS kayıt türlerini filtrele
dns_kayit_turleri_filtre = ["NXDomain", "ServFail"]
data = data[~data["DNS_Turu"].isin(dns_kayit_turleri_filtre)]

# DNS_Bilgisi sütunundaki tüm değerleri metne dönüştür
data["DNS_Bilgisi"] = data["DNS_Bilgisi"].astype(str)

# Entropi hesaplama fonksiyonu
def calculate_entropy(text):
    if not text:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

# DNS sorgularının entropisini hesapla
data["Entropi"] = data["DNS_Bilgisi"].apply(calculate_entropy)

# Gereksiz sütunları kaldır
data = data.drop(columns=["ZamanDamgasi", "Protokol", "Kaynak_IP", "Hedef_IP", "KimlikNo"])

# Yinelenen satırları kaldır
data.drop_duplicates(inplace=True)

# Öznitelik seçimi
X = data[["DNS_Turu", "DNS_CevapUzunlugu", "Entropi"]]
y = data["Etiket"]

# DNS_Turu sütununu sayısal hale getir
X = pd.get_dummies(X, columns=["DNS_Turu"])

# Veri setini eğitim ve test kümelerine ayır
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Lojistik Regresyon modelini oluşturun ve eğitin
model = LogisticRegression()  # Lojistik Regresyon modelini oluştur
model.fit(X_train, y_train)  # Modeli eğit

# Modelin performansını değerlendir
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy}")
print(classification_report(y_test, y_pred))
# Modeli kaydet
joblib.dump(model, "logistic_regression_model.pkl")
print("Model başarıyla kaydedildi.")