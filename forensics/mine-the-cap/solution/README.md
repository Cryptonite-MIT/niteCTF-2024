# Mine the Cap - Solution

**Given:** A pcap file `traffic.pcap`, which contains Minecraft server data.

The TCP packets follow protocol 753, corresponding the Minecraft version 1.16.3. Referencing [https://wiki.vg](http://web.archive.org/web/20201202115228/https://wiki.vg/Protocol), we create our own script to parse the packets, in `parse_packets.py` and fed into a file `trust.csv`.

Concepts to remember here are:

**Encoded Data:**

- `VarInt` and `VarLong`: Variable-length integer formats used in Minecraft protocol.
- Data is tightly packed, so decoding requires special handling.

**3D Coordinates:** Positions of blocks in the game world are stored as compact integers.

Our target packets are ones with Packet ID `0x0b` and `0x3b`, corresponding to single block and multi-block changes respectively.

The functions to note are:

- **`block_change(byte_string)`:**
    - Extracts x, y and z-values of the block using bitshifting, as the coordinates are stored as an 8-byte value.
    - Decodes the block ID using the `decode_varint` function.
    - If the block ID is 9, 10, or 1398, it prints the block's ID and coordinates (debugging).

- **`multi_block_change(byte_string)`:**
    - Decodes a chunk section (a 16x16x256 area of the Minecraft game world), and extracts its section coordinates.
    - For each block given in the chunk,  it extracts its local position within a chunk, adjusts it to an absolute value, and stores it in a list.
    - Prints details for blocks with IDs 9, 10, or 1398.

- **`parse_minecraft_packets(pcap_file)`:**
    - Uses the `pyshark` library to read network packets.
    - Only looks at TCP packets (used for Minecraft communication), and checks if it has a 'Minecraft' layer.
    - Reads the raw byte payload, and calls `block_change` or `multi_block_change` based on packet ID.

The block IDs 9, 10 and 1398 were chosen after much filtering and testing, as they were giving the clearest image of the text.

The parsed coordinates are transferred to a file `trust.csv`.

```sh
python3 parse_packets.py > trust.csv
```

Next, on the `trust.csv` file, we run the script `make_grid.py`.

This just plots a block grid of the coordinates in `trust.csv` using Python's Numpy library, which eventually spells out a pastebin link — `pastebin/BnF81jrU` — so we get the link as `https://pastebin.com/BnF81jrU`.

That link contains the flag: **`nite{bl0ck_8y_bl0ck+chu7k_8y_chu7k}`**

# References:

- http://web.archive.org/web/20201202115228/https://wiki.vg/Protocol

