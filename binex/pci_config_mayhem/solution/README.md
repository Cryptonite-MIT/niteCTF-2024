# Solution

Just copy everything in `solve.sh` into the buildroot shell. The rationale is explained in the script line-by-line. Yes,
it's a bit cringe I authored the exploit solution entirely in bash.

# The Gist

* Signed underflow in `nitedev->addr` allows us to read and write the rest of the PCINiteDeviceState struct i.e behind `nitedev->mem`.
* Executable base address can easily be leaked from `config_read` and `config_write` fields in PCIDevice struct, which is parent of PCINiteDeviceState in the QOM inheritance hierarchy. 
* Heap address can be leaked from a child QOM object, `nitedev->obj1` which stores a backlink to the PCINiteDeviceState in the `obj1->parent_obj->parent` field. This is useful for eventually preparing the fake wmask and w1cmask so that we can write our shellcode properly. Here, parent and child refers to objects containing another, not their inheritance. Confusingly, QEMU uses the same terminologies for both cases.
* There is a `config` pointer field in the PCIDevice struct, This can be clobbered to point elsewhere allowing fully arbitrary read/write when the guest attempts to read/write pci configs.
* Many pointers in the executable store addresses residing in the rwx region, used by TCG. `tcg_qemu_tb_exec` is one such pointer. Some other solutions read out of one of the fields of `region` instead.

# Note

* The solution can be optimized even further to remove the need of faking w1cmask and wmask. The wmask is set as 0xff from configuration register 0x40 onwards making it fully writable from that point. This is something I discovered from a few writeups after the CTF and digging through the source code. This also removes the necessity of doing a heap leak.
* It may be possible to clobber the device state structs of other devices and do leaks from elsewhere in the heap to solve   the challenge. However this is very flaky, as some people had trouble when they proceeded with this approach.
