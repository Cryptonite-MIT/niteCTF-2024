import pyshark

def multi_block_change(byte_string):
    # Set initial offset and parse chunk section position (8 bytes as a Long)
    offset = 0
    chunk_section_position = int.from_bytes(byte_string[offset:offset+8], 'big')
    offset += 8

    # Decode chunk section position
    section_x = chunk_section_position >> 42 & 0x3FFFFF
    section_y = chunk_section_position & 0xFFFFF
    section_z = chunk_section_position >> 20 & 0x3FFFFF

    trust_edges = bool(byte_string[offset])
    offset += 1

    # Parse blocks array size as VarInt
    blocks_array_size, varint_size = decode_varint(byte_string, offset)
    offset += varint_size

    blocks = []
    for _ in range(blocks_array_size):
        # Parse each block as VarLong (between 1 and 10 bytes, depending on the value)
        block_raw_id, varlong_size = decode_varlong(byte_string, offset)
        offset += varlong_size

        # Extract block ID and relative block position
        block_id = block_raw_id >> 12
        x = (section_x << 4) | ((block_raw_id >> 8) & 0xF)
        y = (section_y << 4) | ((block_raw_id >> 4) & 0xF)
        z = (section_z << 4) | (block_raw_id & 0xF)

        if x >= 1 << 25 : x -= 1 << 26
        if y >= 1 << 11 : y -= 1 << 12
        if z >= 1 << 25 : z -= 1 << 26

        blocks.append({
            "block_id": block_id,
            "local_x": x,
            "local_y": y,
            "local_z": z
        })

    # Display parsed blocks
    for _, block in enumerate(blocks):
        if block['block_id'] in [9, 10, 1398]:
            print(f"ID: {block['block_id']}, X: {block['local_x']}, Y: {block['local_y']}, Z: {block['local_z']}")

def block_change(byte_string):
    # Set initial offset
    offset = 0

    # Parse Location (Position) as 8-byte long integer
    position_data = int.from_bytes(byte_string[offset:offset+8], 'big')
    offset += 8

    # Decode Position
    x = (position_data >> 38) & 0x3FFFFFF
    z = (position_data >> 12) & 0x3FFFFFF
    y = position_data & 0xFFF

    if x >= 1 << 25 : x -= 1 << 26
    if y >= 1 << 11 : y -= 1 << 12
    if z >= 1 << 25 : z -= 1 << 26


    # Parse Block ID as VarInt
    block_id, varint_size = decode_varint(byte_string, offset)
    offset += varint_size
    if block_id in [9, 10, 1398]:
        print(f"ID: {block_id}, X: {x}, Y: {y}, Z: {z}")

def decode_varint(byte_string, offset):
    """Decodes a VarInt starting at offset and returns the integer value and byte length."""
    value = 0
    for i in range(5):
        byte = byte_string[offset + i]
        value |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return value, i + 1
    raise ValueError("VarInt is too large")

def decode_varlong(byte_string, offset):
    """Decodes a VarLong starting at offset and returns the integer value and byte length."""
    value = 0
    for i in range(10):
        byte = byte_string[offset + i]
        value |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            return value, i + 1
    raise ValueError("VarLong is too large")

# PyShark integration for packet parsing
def parse_minecraft_packets(pcap_file):
    capture = pyshark.FileCapture(pcap_file, display_filter="tcp")

    for packet in capture:
        try:
            # Check for Minecraft protocol and packet ID
            minecraft_layer = packet.get_multiple_layers("MINECRAFT")
            if minecraft_layer:
                for layer in minecraft_layer:
                    packet_id_field = layer.get_field("packet_id")
                    if packet_id_field:
                        packet_id = int(packet_id_field.show, 16)

                        # Retrieve the raw byte data for analysis
                        raw_data = bytes.fromhex(''.join(packet.tcp.payload.split(':')[3:]))
                        # Call appropriate function based on Packet ID

                        if packet_id == 0x0b:
                            block_change(raw_data)
                        elif packet_id == 0x3b:
                            multi_block_change(raw_data)
        except AttributeError:
            pass  # Handle packets without the Minecraft protocol layer

    capture.close()

# Run the parser on a pcap file
parse_minecraft_packets("../challenge/public/traffic.pcap")

