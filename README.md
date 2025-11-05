# OStealth

Currently the kernel module simply registers a netfliter hook that updates the TTL of packets with a
custom value and exposes a device to fetch and modify said value.

## Usage

Before starting development install pre-commit to the repo:
```
pre-commit install
```

Before attempting to compile the kernel module install the appropriate linux headers for the machine. For instance, an Intel Kali
would required the following command:
```
sudo apt install linux-headers-amd64
```

To compile the kernel module and load it:
```
make
sudo insmod ostealth.ko
```

To print and update the current TTL value:
```
sudo python ostealth.py get
sudo python ostealth.py set 128
```
