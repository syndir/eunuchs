obj-m += eunuchs.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	rm -rf *.o *.ko *.symvers *.mod *.order
