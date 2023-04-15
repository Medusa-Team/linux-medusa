#
# Makefile for building the BASC module as part of the kernel tree.
#

#KBUILD_CFLAGS += -g -Wall
KBUILD_CFLAGS += -Werror=deprecated-declarations
LINUXINCLUDE    += -I$(srctree)/security/medusa/include

subdir-$(CONFIG_SECURITY_MEDUSA)	+= l1
subdir-$(CONFIG_SECURITY_MEDUSA)        += l2
subdir-$(CONFIG_SECURITY_MEDUSA)        += l3
subdir-$(CONFIG_SECURITY_MEDUSA)        += testing

obj-$(CONFIG_SECURITY_MEDUSA) += l1/
obj-$(CONFIG_SECURITY_MEDUSA) += l2/
obj-$(CONFIG_SECURITY_MEDUSA) += l3/
obj-$(CONFIG_SECURITY_MEDUSA) += l4-constable/
obj-$(CONFIG_SECURITY_MEDUSA_TESTING) += testing/
