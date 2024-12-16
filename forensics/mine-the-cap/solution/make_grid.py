import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Read the CSV file (assuming no header)
df = pd.read_csv('trust.csv', header=None, names=['block_id', 'x', 'y', 'z'])

# Create the plot for the scatter view
plt.figure(figsize=(10, 8))

# Create scatter plot for block_id 160
plt.scatter(df['x'], df['z'], alpha=0.6)

# Customize the plot
plt.title('Block 160 - X-Z Plane View')
plt.xlabel('X Coordinate')
plt.ylabel('Z Coordinate')

# Add grid
plt.grid(True, linestyle='--', alpha=0.7)

# Ensure equal aspect ratio so squares appear square
plt.axis('equal')

# Save the plot
plt.savefig('block_160_plot.png', dpi=300, bbox_inches='tight')
plt.close()

# Alternative: Create a pixel-based visualization for block_id 160
def create_pixel_visualization():
    # Find the range of coordinates
    x_min, x_max = df['x'].min(), df['x'].max()
    z_min, z_max = df['z'].min(), df['z'].max()

    # Create a grid
    grid_width = int(x_max - x_min + 1)
    grid_height = int(z_max - z_min + 1)
    grid = np.zeros((grid_height, grid_width))

    # Fill the grid
    for _, row in df.iterrows():
        x_idx = int(row['x'] - x_min)
        z_idx = int(row['z'] - z_min)
        grid[z_idx, x_idx] = 1

    # Create the plot
    plt.figure(figsize=(10, 8))
    plt.imshow(grid, cmap='Blues', interpolation='nearest')
    plt.title('Block 160 - X-Z Plane (Pixel View)')
    plt.xlabel('X Coordinate')
    plt.ylabel('Z Coordinate')

    # Add colorbar
    plt.colorbar(label='Presence of Block')

    # Save the plot
    plt.savefig('block_160_pixel_plot.png', dpi=300, bbox_inches='tight')
    plt.close()

# Create both visualizations
create_pixel_visualization()
