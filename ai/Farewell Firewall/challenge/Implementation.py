import numpy as np
import pandas as pd
from sklearn.datasets import make_blobs
from sklearn.cluster import DBSCAN
import matplotlib.pyplot as plt

n_samples = 15000
n_features = 15
n_clusters = 3

feature_names = [
    'timestamp', 'user_id', 'session_duration', 'num_login_attempts', 
    'data_downloaded', 'data_uploaded', 'num_alerts', 'num_firewall_hits', 
    'avg_response_time', 'encryption_type', 'latitude_coord', 'longitude_coord', 
    'os_version', 'user_role', 'alert_level'
]

X, _ = make_blobs(n_samples=n_samples, centers=n_clusters, n_features=n_features - 2, random_state=42)
data1 = pd.DataFrame(X, columns=feature_names[:-2])

data1['timestamp'] = pd.to_datetime(np.random.randint(1609459200, 1631001600, size=n_samples), unit='s')  # Random timestamps
data1['user_id'] = np.random.randint(1000, 9999, size=n_samples)
data1['session_duration'] = np.random.exponential(scale=30, size=n_samples)  # in minutes
data1['num_login_attempts'] = np.random.randint(1, 10, size=n_samples)
data1['data_downloaded'] = np.random.uniform(0, 500, size=n_samples)  # in MB
data1['data_uploaded'] = np.random.uniform(0, 100, size=n_samples)  # in MB
data1['num_alerts'] = np.random.randint(0, 5, size=n_samples)
data1['num_firewall_hits'] = np.random.randint(1, 20, size=n_samples)
data1['avg_response_time'] = np.random.uniform(0.1, 5.0, size=n_samples)  # in seconds
data1['encryption_type'] = np.random.choice(['AES', 'RSA', 'None'], size=n_samples)
data1['os_version'] = np.random.choice(['Windows', 'Linux', 'macOS'], size=n_samples)
data1['user_role'] = np.random.choice(['admin', 'user', 'guest'], size=n_samples)
data1['alert_level'] = np.random.choice(['low', 'medium', 'high'], size=n_samples)

secret_string = "nite{f0und_my_d3st1ny_by_sp@t14l_clust3r1ng_0f_d3ns1ty}"
anomaly_samples = len(secret_string)
anomaly_data = np.random.randn(anomaly_samples, n_features - 2) * 0.5 

for i in range(anomaly_samples):
    anomaly_data[i, 9] += np.random.uniform(200, 400) 
    anomaly_data[i, 10] -= np.random.uniform(200, 400)  


data2 = pd.DataFrame(anomaly_data, columns=feature_names[:-2])

data2['timestamp'] = pd.to_datetime(np.random.randint(1609459200, 1631001600, size=anomaly_samples), unit='s')
data2['user_id'] = np.random.randint(1000, 9999, size=anomaly_samples)
data2['session_duration'] = np.random.exponential(scale=30, size=anomaly_samples)
data2['num_login_attempts'] = np.random.randint(1, 10, size=anomaly_samples)
data2['data_downloaded'] = np.random.uniform(0, 500, size=anomaly_samples)
data2['data_uploaded'] = np.random.uniform(0, 100, size=anomaly_samples)
data2['num_alerts'] = np.random.randint(0, 5, size=anomaly_samples)
data2['num_firewall_hits'] = np.random.randint(1, 20, size=anomaly_samples)
data2['avg_response_time'] = np.random.uniform(0.1, 5.0, size=anomaly_samples)
data2['encryption_type'] = np.random.choice(['AES', 'RSA', 'None'], size=anomaly_samples)
data2['os_version'] = np.random.choice(['Windows', 'Linux', 'macOS'], size=anomaly_samples)
data2['user_role'] = np.random.choice(['admin', 'user', 'guest'], size=anomaly_samples)
data2['alert_level'] = np.random.choice(['low', 'medium', 'high'], size=anomaly_samples)


data2_sorted = data2.sort_values(by='user_id', ascending=True)

# da flag
secret_string = "nite{f0und_my_d3st1ny_by_sp@t14l_clust3r1ng_0f_d3ns1ty}"
ascii_values = [ord(char) for char in secret_string]

# hide da flag
for i, (index, row) in enumerate(data2_sorted.iterrows()):
    target_ascii = ascii_values[i]  
    upload_value = np.random.randint(1, 255)  
    download_value = target_ascii ^ upload_value  
    
    
    data2_sorted.at[index, 'data_downloaded'] = download_value
    data2_sorted.at[index, 'data_uploaded'] = upload_value

merged_data = pd.concat([data1, data2_sorted], ignore_index=True)
merged_data = merged_data.sample(frac=1).reset_index(drop=True)  

dbscan = DBSCAN(eps=3, min_samples=5)
labels = dbscan.fit_predict(merged_data[['latitude_coord', 'longitude_coord']])


merged_data['cluster'] = labels

anomalies = merged_data[merged_data['cluster'] == -1]

plt.figure(figsize=(10, 6))
plt.scatter(merged_data['latitude_coord'], merged_data['longitude_coord'], c=merged_data['cluster'], cmap='viridis', marker='o', s=10)
plt.scatter(anomalies['latitude_coord'], anomalies['longitude_coord'], color='red', marker='x', s=50, label='Anomalies')
plt.xlabel('Latitude Coordinate')
plt.ylabel('Longitude Coordinate')
plt.title('DBSCAN Anomaly Detection in Cybersecurity Data')
plt.legend()
plt.show()

print("Modified Anomalies with XOR Values:")
print(anomalies[['user_id', 'data_downloaded', 'data_uploaded']])


merged_data.to_csv('Network_Log.csv', index=False)
