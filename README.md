# OStealth

Currently the kernel module simply registers a netfliter hook that updates the TTL of packets with a
custom value and exposes a device to fetch and modify said value.

## Usage

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

## Issues

At the moment, setting the TTL to a value other than 64 makes TCP packets stop working.
