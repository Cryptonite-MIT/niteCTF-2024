# Farewell Firewall Solution

1. **Load the Data**:  
   The `Network_Log.csv` file is loaded into a Pandas DataFrame using `pd.read_csv()`.

2. **Apply DBSCAN for Anomaly Detection**:  
   The DBSCAN algorithm is applied using the `latitude_coord` and `longitude_coord` features. Anomalies are labeled as `-1` by DBSCAN.

3. **Filter Anomalies**:  
   The anomalies (points labeled as `-1`) are extracted from the dataset by filtering rows where the `cluster` column equals `-1`.

4. **Sort Anomalies by User ID**:  
   The anomalies are sorted by the `user_id` column in ascending order to maintain consistency.

5. **Extract the Flag from Anomalies**:  
   For each anomaly:

    - The `data_downloaded` and `data_uploaded` values are converted into integers.
    - These values are XORed together to produce a new value.
    - The XOR result is converted to an ASCII character using the modulo operation (`% 256`).

6. **Reconstruct the Flag**:  
   The characters derived from each anomaly are appended to a list. This list is then joined together to form the complete flag string.

7. **Print the Flag**:  
   The reconstructed flag is printed to the console.

[Solve script](solution.py)
