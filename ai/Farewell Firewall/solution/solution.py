import pandas as pd
from sklearn.cluster import DBSCAN

merged_data = pd.read_csv('Network_Log.csv')

dbscan = DBSCAN(eps=3, min_samples=5)
merged_data['cluster'] = dbscan.fit_predict(merged_data[['latitude_coord', 'longitude_coord']])

anomalies = merged_data[merged_data['cluster'] == -1]

anomalies_sorted = anomalies.sort_values(by='user_id', ascending=True)

flag_characters = []
for _, row in anomalies_sorted.iterrows():
    data_downloaded_int = int(row['data_downloaded'])
    data_uploaded_int = int(row['data_uploaded'])
    
    multiplied_value = data_downloaded_int ^ data_uploaded_int
    
    ascii_character = chr(multiplied_value % 256)  
    
    flag_characters.append(ascii_character)

flag = ''.join(flag_characters)

print(f"The flag is: {flag}")