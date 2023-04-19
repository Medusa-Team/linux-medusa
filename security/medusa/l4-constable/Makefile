# For the Linux kernel part of Medusa DS9 Security System,
# L4/constable

# for GCOV coverage profiling
ifdef CONFIG_SECURITY_MEDUSA_GCOV_PROFILE
GCOV_PROFILE := y
endif

export-objs :=  teleport_cycle teleport_reset

l4-constable-y:= teleport.o chardev.o
obj-y := l4-constable.o

