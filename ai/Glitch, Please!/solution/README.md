# Glitch, Please! Solution

The challenge, titled `"All Alone in the Forest"`, hints at the `"Isolation Forest Anomaly Detection Algorithm"`. Key details include:  
- A dataset of `15,000 entries`.  
- Reference to `20 cheats`, implying a contamination level.  
- Columns of interest are `"ItemsCollected"` and `"ConnectionPing"`, based on the description of inventory overflow and reduced feedback delay.  
- The challenge instructs to "uncover faces," suggesting the `ProfilePic` column contains the flag.

---

The dataset has `15,000 entries`, with `20 cheats` mentioned.  
We calculate the contamination level for the Isolation Forest algorithm as:  

`20/15000`

---

Using the Isolation Forest algorithm with the specified contamination level:  
- `Fit the model` using the `"ItemsCollected"` and `"ConnectionPing"` columns.  


The algorithm successfully identifies `20 anomalies` as expected, corresponding to the cheats.

---

The challenge asks us to "uncover faces." Examining the `ProfilePic` column:  
- The column contains arrays labeled as `256x256`.  
- These arrays represent pixel data for images.  

To visualize the profile pictures:  
1. Reshape each array to a `256x256 matrix`.  
2. Use a library such as `matplotlib` or `Pillow` to plot the images.

---

Upon plotting the images, we observe:  
- Each profile picture is a representation of `letters or symbols`.  
- Sorting the profile pictures by their `PlayerScore` reveals :
![Sorted Profile Pictures](<flagimg.png>)
