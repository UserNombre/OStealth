import sys
import fcntl
import struct
import click

# https://github.com/vpelletier/python-ioctl-opt/blob/master/ioctl_opt/__init__.py
IOC_NONE = 0
IOC_WRITE = 1
IOC_READ = 2

def _IOC(dir, type, nr, size):
    return (dir << 30) | (size << 16) | (type << 8) |  nr

IOCTL_MAGIC = 0x05
DEVICE_PATH = "/dev/ostealth"

ioctl_data = {
    "ttl": {
        "set": _IOC(IOC_WRITE, IOCTL_MAGIC, 1, 1),
        "get": _IOC(IOC_READ, IOCTL_MAGIC, 1, 1),
        "size": 1
    },
    "window_size": {
        "set": _IOC(IOC_WRITE, IOCTL_MAGIC, 2, 2),
        "get": _IOC(IOC_READ, IOCTL_MAGIC, 2, 2),
        "size": 2
    }
}

@click.command()
@click.argument("field", type=click.Choice(ioctl_data.keys()))
@click.argument("value", type=int)
def set_field(field, value):
    data = ioctl_data[field]
    with open(DEVICE_PATH, "wb") as fd:
        packed = value.to_bytes(data["size"], byteorder=sys.byteorder)
        fcntl.ioctl(fd, data["set"], packed)
        click.echo(f"Successfully set {field} to {value}")

@click.command()
@click.argument("field", type=click.Choice(ioctl_data.keys()))
def get_field(field):
    data = ioctl_data[field]
    with open(DEVICE_PATH, "rb") as fd:
        packed = fcntl.ioctl(fd, data["get"], b"\0" * data["size"])
        value = int.from_bytes(packed, byteorder=sys.byteorder)
        click.echo(f"Current {field} value is {value}")

@click.group()
def cli():
    pass

cli.add_command(set_field, "set")
cli.add_command(get_field, "get")

if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)
