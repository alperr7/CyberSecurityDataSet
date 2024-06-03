import pandas as pd 
#Veri işleme ve analiz için kullanılan bir kütüphane 
import numpy as np
#Sayısal hesaplamalar ve dizilerle çalışmak için kullanılan bir kütüphane
import matplotlib.pyplot as plt
#Grafik ve görselleştirme için kullanılan bir kütüphane
import seaborn as sns
#daha estetik grafikler oluşturmak için kullanılan bir kütüphane
import plotly.express as px 
#İnteraktif grafikler oluşturmak için kullanılan bir kütüphane

import warnings 
#Pyhtonda uyarıları yönetmek için kullanılan bir modül
warnings.filterwarnings("ignore")
#Programın çalışması sırasında oluşabilicek uyarı mesajlarını göz ardı etmek için kullanılır

df = pd.read_csv("cybersecurity_attacks.csv")
#CSV dosyasını okuyarak pandas DataFrame nesnesine yükler

df.head().T 
#DataFrame'in ilk 5 satırını döndürür
#.T:satırları sütun,sütunları satır yapar.

df.columns
#DataFrame'in tüm sütun isimlerini döndürür

print(f"There are {df.shape[0]}, row and {df.shape[1]} columns in the dataset")
#DataFrame'deki satır ve sütun sayısını ekrana yazdırır

df.info()
#DataFrame hakkında genel bilgi verir

df.isnull().sum().sort_values(ascending=False)
#Eksik değerleri kontrol etmek için null sayısını hesaplayan df.isnull().sum() ve eksik değer sayısını azalan sırayla sıralaması için de .sort_values kullanılır

df.isnull().sum() / len(df)* 100 
#her sütundaki eksik değerlerin sayısı ile DataFrame'deki toplam satır sayısını bölerek veri içindeki yüzdeyi hesaplar


#SÜTUNDAKİ DEĞERLER KONTROL EDİLİYOR
df['Alerts/Warnings'] = df['Alerts/Warnings'].apply(lambda x: 'yes' if x == 'Alert Triggered' else 'no')

df['Malware Indicators'] = df['Malware Indicators'].apply(lambda x: 'No Detection' if pd.isna(x) else x)

df['Proxy Information'] = df['Proxy Information'].apply(lambda x: 'No proxy' if pd.isna(x) else x)

df['Firewall Logs'] = df['Firewall Logs'].apply(lambda x: 'No Data' if pd.isna(x) else x)

df['IDS/IPS Alerts'] = df['IDS/IPS Alerts'].apply(lambda x: 'No Data' if pd.isna(x) else x)

df.isnull().sum().sort_values(ascending=False)

df['Device Information'].value_counts()
#Device Information sütunundaki her bir değerin kaç kez geçtiğini sayar ve bu sayımları azalan sırayla döndürür

df['Browser'] = df['Device Information'].str.split('/').str[0]
#Browses sütununa '/' karakterine göre bölünmüş Device Informationdaki bilgiler eklenir
df['Browser']

import re
#Düzenli ifadelerle çalışmak için kullanılan bir kütüphane

#İşletim sistemini ve cihaz türlerini aramak için kullanılacak kalıplar
patterns = [
    r'Windows',
    r'Linux',
    r'Android',
    r'iPad',
    r'iPod',
    r'iPhone',
    r'Macintosh',
]


#Kullanıcı dizesinden işletim sistemi veya cihaz türünü ayıklayan fonksiyon
def extract_device_or_os(user_agent):
    for pattern in patterns:
        match = re.search(pattern, user_agent, re.I)  # re.I aramayı büyük/küçük harf duyarsız yapar
        if match:
            return match.group()
    return 'Unknown'  # Hiçbiri eşleşmese 'Unknown' döndürür

# İşletim sistemi veya chaz türünü ayıklar
df['Device/OS'] = df['Device Information'].apply(extract_device_or_os)

#'Browser'sütundaki her bir değerin kaç kez geçtiğini sayar
df['Browser'].value_counts()

#'Device/Os' sütunundaki her bir değerin kaç kez geçtiğini sayar 
df['Device/OS'].value_counts()

#'Device Information'sütununu DataFrame'den kaldırır
df = df.drop('Device Information', axis = 1)

def extract_time_features(df, Timestamp):
    #'Timestamp'sütunundaki verileri datetime nesnesine dönüştürür
    df[Timestamp] = pd.to_datetime(df[Timestamp])
    
    # Zaman damgasından yılı ayıklar ve yeni bir 'Year'sütunu oluşturur
    df['Year'] = df[Timestamp].dt.year
    df['Month'] = df[Timestamp].dt.month
    df['Day'] = df[Timestamp].dt.day
    df['Hour'] = df[Timestamp].dt.hour
    df['Minute'] = df[Timestamp].dt.minute
    df['Second'] = df[Timestamp].dt.second
    df['DayOfWeek'] = df[Timestamp].dt.dayofweek
    
    return df

#'extract_time_features'fonksiyonunu çağırır ve sonuçları saklar
new_df = extract_time_features(df, 'Timestamp')

#Yeni oluşturulan sütunları görmek için ilk 5 satırı yazdırır
print(new_df.head())

#ilk 5 satırı döndürür ve satırları sütun,sütunları satır yapar
df.head().T

#Sayısal olmayan sütunların özet istatistiklerini döndürür ve transpozunu alır
df.describe(include = 'object').T
#DataFrame'in tüm sütun isimlerini döndürür
df.columns

#Yukarıda import ettiğimiz plotly.express as px ile daha basit ve hızlı bir şekilde interaktif grafikler oluşturabiliriz
#burda da 'Day' sütununa göre histogram oluşturulur
plt = px.histogram(df, x = 'Day', color = 'Malware Indicators', title = 'Number of Malware Attacks by Day')
plt.show() #Grafiği gösteriyo

# 'Month' sütununa göre histogram oluşturulur
plt = px.histogram(df, x = 'Month', title = 'Month')
plt.show()

# 'Month' sütununa göre histogram oluşturulur
plt = px.histogram(df, x = 'Month', color = 'Malware Indicators', title = 'Number of Malware Attacks by Month')
plt.show()

#'Year' sütununa göre histogram oluşturulur
plt = px.histogram(df, x='Year', title = 'Year')
plt.show()

# Checking the Day Column ploting with plotly
plt = px.histogram(df, x = 'Year', color = 'Malware Indicators', title = 'Number of Malware Attacks by Year')
plt.show()

# Checking the Protocol distribution with Bar Chart Using Plotly
plt = px.histogram(df, x = 'Protocol', color = 'Malware Indicators', title = 'Number of Malware Attacks by Protocol')
plt.show()

# 'px.pie' fonksiyonu ile 'Traffic Type' sütununa göre pasta grafik oluşturulur
plt = px.pie(df, names = 'Traffic Type', title = 'Traffic Distribution')
plt.show()

#'Traffic Type' sütununa göre bir histogram oluşturur 
plt = px.histogram(df, x = 'Traffic Type', color = 'Malware Indicators', title = 'Number of Malware Attacks by Traffic Type')
plt.show()

# 'Attack Type' türüne sütununa göre bir pasta grafiği oluşturur
plt = px.pie(df, names = 'Attack Type', title = 'Attack Type Distribution')
plt.show()

# 'Attack Type' sütununa göre bir histogram oluşturur
plt = px.histogram(df, x='Attack Type', color='Traffic Type', title='Number of Malware Attacks by Attack Type')
plt.show()

# 'Browser' sütununa göre bir pasta grafiği oluşturur
plt = px.pie(df, names = 'Browser', title = 'Browser Distribution')
plt.show()

# 'Device/OS'sütununa göre bir pasta grafiği oluşturur
plt = px.pie(df, names = 'Device/OS', title = 'Platform Distribution')
plt.show()

# 'Device/Os' sütununa göre bir histogram oluşturur

plt = px.histogram(df, x ='Device/OS', color= 'Browser', title = 'Platform Distribution')
plt.show()

#'Attack Type' Çubukları 'Attack Type'sütunundaki değerlere göre renklendirir
plt = px.histogram(df, x= 'Device/OS', color = 'Attack Type', title = 'Number of Malware Attacks by Browser and Devices')
plt.show()

# 'Browser'sütununa göre bir histogram oluşturur
plt = px.histogram(df, x= 'Browser', color='Attack Type', title= 'Number of Attacks by Browser')
plt.show()

# 'Log Source'sütununa göre bir histogram oluşturur
plt = px.histogram(df, x='Log Source', title='Log Source')
plt.show()

# 'Action Taken'sütununa göre bir histogram oluşturur 
plt = px.histogram(df, x='Action Taken', title='Action Taken')
plt.show()

# 'Action Taken' sütununa göre bir histogram oluşturur
plt = px.histogram(df, x='Action Taken', color='Attack Type', title='Log Source')
plt.show()

# 'Log Source' sütununa göre bir histogram oluşturur
plt = px.histogram(df, x='Log Source', color='Attack Type', title='Log Source')
plt.show()

import plotly.graph_objs as go
#grafik objelerini içe aktarır

# Her Saldırı Türü İçin Verilerin Filtrelenmesi
malware_data = df[df['Attack Type'] == 'Malware']['Packet Length']
intrusion_data = df[df['Attack Type'] == 'Intrusion']['Packet Length']
ddos_data = df[df['Attack Type'] == 'DDoS']['Packet Length']

#Her Saldırı Türü için Histogramların Oluşturulması
malware_histogram = go.Histogram(x=malware_data, name='Malware', opacity=0.7)
intrusion_histogram = go.Histogram(x=intrusion_data, name='Intrusion', opacity=0.7)
ddos_histogram = go.Histogram(x=ddos_data, name='DDoS', opacity=0.7)

# Grafik Düzeninin Oluşturulması
layout = go.Layout(title='Packet Length Distribution for Different Attack Types',
                   xaxis=dict(title='Packet Length'),
                   yaxis=dict(title='Frequency'))
#xaxis:X ekseni ayarları 
#yaxis:Y ekseni ayarları

# Grafik Nesnesinin Oluşturulması
fig = go.Figure(data=[malware_histogram, intrusion_histogram, ddos_histogram], layout=layout)

# Grafiğin Görüntülenmesi
fig.show()