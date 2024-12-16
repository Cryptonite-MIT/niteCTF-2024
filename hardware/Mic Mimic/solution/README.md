## Mic Mimic Solution

-   get Shure ULXD8 X52 FCC ID: DD4ULXD8X52
-   get ADC ID from internal photos and datasheet: PCM1803A, https://www.ti.com/lit/ds/symlink/pcm1803a.pdf?ts=1730617276007&ref_url=https%253A%252F%252Fwww.ti.com%252Fproduct%252FPCM1803A
-   point 1 proves device atcs in master mode, 32Khz respresents fs of 512. This fits 2nd condition of table 3 which gives us the mode pins
-   Carefully comparing the timing diagrams in 7.4.1.2 with the output characterists will provide the format mode hence the format pins
-   8.2 point A talks about the HPF in the input wrt schematic and 8.2.2.3 give the fomula to calculate the resistor value
