# Renderman Solution

Multiple possible expected solves:

1. can extract the models put in a renderer and manually bruteforce state (labour ig, prolly what most people would do)
2. patch using apktools or smali, to stop the jumpscare, increase camera's far plane and take down the walls, manually sign an generate apks for each state (even more labour)
3. **`INTENDED`** hook onto the triggerJumpscare method, set camera's near plane to 0 (this allows rendering stuff to infinity in libgdx, because depth calculations divide by the cam's near plane value) \
   since triggerJumpscare is called in render method once the jumpscare timer is over, u have access to the update method directly. \
   write frida hook to increment state on keypress and keep bruting it until state `241` where the flag assembles.

### `NITE{N0W_U_C_M3}`
