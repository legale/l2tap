# Makefile for building kernel module

# Имя модуля ядра
obj-m += l2tap.o

# Указание пути к заголовочным файлам ядра
KDIR := /lib/modules/$(shell uname -r)/build

# Каталог текущего проекта
PWD := $(shell pwd)

# Цель для сборки модуля
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Чистка скомпилированных файлов
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Загрузка модуля в ядро
insmod: all
	sudo insmod l2tap.ko

# Удаление модуля из ядра
rmmod:
	sudo rmmod l2tap
