# l2tap
simpliest l2 tunnel over udp linux kernel module


# l2tap Kernel Module

The `l2tap` kernel module creates a Layer 2 TAP network interface with support for UDP tunneling. This allows for encapsulation of L2 frames over a UDP connection between a local and a remote IP address. The module provides the capability to configure local and remote IP addresses and ports via sysfs.

## Features

- Creation of a Layer 2 TAP device.
- Encapsulation of Ethernet frames over a UDP tunnel.
- Dynamically configurable local and remote IP/Port via sysfs.
- Support for basic Layer 2 protocols like IPv4, ARP, and IPv6.

## Requirements

- A Linux kernel with networking support.
- Kernel headers for your Linux version.
- `make` and `gcc` installed on your system.

## Compilation

1. Clone or download the `l2tap` source code.
2. Ensure you have the kernel headers installed for your running kernel. Module was tested on linux 6.1.0-22.


```sh
sudo apt-get install linux-headers-$(uname -r)

#compile
make
#load module
sudo make insmod
#unload module
sudo make rmmod
```


# Usage

## host 1 192.168.1.1

```sh
echo "192.168.1.1" > /sys/kernel/l2tap/local_ip
echo "192.168.1.2" > /sys/kernel/l2tap/remote_ip
echo "5555" > /sys/kernel/l2tap/local_port
echo "5556" > /sys/kernel/l2tap/remote_port
ip link add l2 type l2tap
ip link set dev l2 arp on
ip l set l2 up
```

## host 2 192.168.1.2
```sh
echo "192.168.1.2" > /sys/kernel/l2tap/local_ip
echo "192.168.1.1" > /sys/kernel/l2tap/remote_ip
echo "5556" > /sys/kernel/l2tap/local_port
echo "5555" > /sys/kernel/l2tap/remote_port

ip link add l2 type l2tap
ip link set dev l2 arp on
ip l set l2 up
```