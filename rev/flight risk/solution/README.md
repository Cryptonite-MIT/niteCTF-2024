# Flight Risk Solution

Decompile the game using Il2cppdumper. You can see `TerrainGenerator.cs` and `Missile.cs` and the method names defined within.

Open the GameAssembly.dll then on IDA or any debugger and patch `TerrainGenerator` class to set heights to 0

Then modify the `Missile` class to `nop` calls to `SpawnMissile` function.
