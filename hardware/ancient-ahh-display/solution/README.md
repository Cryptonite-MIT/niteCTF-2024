# Ancient Ahh Display Solution

Since it's an anode display so 0 means the segment is on

And with convention the segments are in `gfedcba` format

so when you decode it

```
ancient_ahh_display

flag: nite{tr0UbLe_bUbbLe_L0L}

Description: bro is still stuck on Basys 3 Artix-7's display, LOL!

file: display_code.txt, fpga_inputs.xlsx



module seven_segment (i_binary, o_hexdisplay, anode);
input [4:0] i_binary; // Extend input to 5 bits for alphabets
output reg [6:0] o_hexdisplay;
output [3:0] anode;
assign anode = 4'b0001;

always @(i_binary)
case (i_binary)
    // Digits (0-9)
    5'b00000 : o_hexdisplay = 7'b1000000; // 0
    5'b00001 : o_hexdisplay = 7'b1111001; // 1
    5'b00010 : o_hexdisplay = 7'b0100100; // 2
    5'b00011 : o_hexdisplay = 7'b0110000; // 3
    5'b00100 : o_hexdisplay = 7'b0011001; // 4
    5'b00101 : o_hexdisplay = 7'b0010010; // 5
    5'b00110 : o_hexdisplay = 7'b0000010; // 6
    5'b00111 : o_hexdisplay = 7'b1111000; // 7
    5'b01000 : o_hexdisplay = 7'b0000000; // 8
    5'b01001 : o_hexdisplay = 7'b0010000; // 9
    5'b01010 : o_hexdisplay = 7'b0001000; // A
    5'b01011 : o_hexdisplay = 7'b0000011; // b
    5'b01100 : o_hexdisplay = 7'b1000110; // C
    5'b01101 : o_hexdisplay = 7'b0100001; // D
    5'b01110 : o_hexdisplay = 7'b0000100; // e
    5'b01111 : o_hexdisplay = 7'b0001110; // F
    5'b10000 : o_hexdisplay = 7'b0001001; // H
    5'b10001 : o_hexdisplay = 7'b1101111; // i
    5'b10010 : o_hexdisplay = 7'b1100001; // J
    5'b10011 : o_hexdisplay = 7'b1000111; // L
    5'b10100 : o_hexdisplay = 7'b0101011; // n
    5'b10101 : o_hexdisplay = 7'b0001100; // P
    5'b10110 : o_hexdisplay = 7'b0011000; // Q
    5'b10111 : o_hexdisplay = 7'b0101111; // r
    5'b11000 : o_hexdisplay = 7'b0000111; // t
    5'b11001 : o_hexdisplay = 7'b1000001; // U
    5'b11010 : o_hexdisplay = 7'b0010001; // Y
    5'b11011 : o_hexdisplay = 7'b1000110; // [
    5'b11100 : o_hexdisplay = 7'b1110000; // ]
    5'b11010 : o_hexdisplay = 7'b0111111; // -

    default: o_hexdisplay = 7'b1110111; // Default: _
endcase

endmodule



//i_binary[0] -> V17
//i_binary[1] -> W16
//i_binary[2] -> W13
//i_binary[3] -> A3
//i_binary[4] -> W2


//i_binary[0] -> V17
//i_binary[1] -> W16
//i_binary[2] -> W13
//i_binary[3] -> A3
//i_binary[4] -> W2
```

There are the pins that are relevant so ignore all other pins.

after mapping those 5 bit inputs to 7 bit of the display you get the flag.
