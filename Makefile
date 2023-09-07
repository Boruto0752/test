ifeq ($(KSRC),)
        KSRC := /lib/modules/$(shell uname -r)/build
endif

obj-m += misc.o

CFLAGS_misc.o := -Wno-declaration-after-statement
EXTRA_CFLAGS += -g

all:
	$(MAKE) -C$(KSRC) M=$(PWD)

install:
	install -o root -g root -m 0755 misc.ko $(DESTDIR)/lib/modules/$(shell uname -r)/kernel/drivers/block/
	depmod -a

uninstall:
	rm -f $(DESTDIR)/lib/modules/$(shell uname -r)/kernel/drivers/block/misc.ko
	depmod -a

clean:
	rm -rf *.o *.ko *.symvers *.mod.c .*.cmd Module.markers modules.order .tmp_versions .misc.o.d
