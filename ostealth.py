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
IOCTL_SET_TTL = _IOC(IOC_WRITE, IOCTL_MAGIC, 1, 1)
IOCTL_GET_TTL = _IOC(IOC_READ, IOCTL_MAGIC, 2, 1)
DEVICE_PATH = "/dev/ostealth"

@click.command()
@click.argument("ttl_value", type=int)
def ttl_set(ttl_value):
    with open(DEVICE_PATH, "wb") as fd:
        fcntl.ioctl(fd, IOCTL_SET_TTL, struct.pack("B", ttl_value))
        click.echo(f"Successfully set TTL to {ttl_value}")

@click.command()
def ttl_get():
    with open(DEVICE_PATH, "rb") as fd:
        ttl_value = struct.unpack("B", fcntl.ioctl(fd, IOCTL_GET_TTL, b'\0'))[0]
        click.echo(f"Current TTL value is {ttl_value}")

@click.group()
def cli():
    pass

cli.add_command(ttl_set, "set")
cli.add_command(ttl_get, "get")

if __name__ == "__main__":
    try:
        cli()
    except Exception as e:
        click.echo(f"Error: {e}")
        raise SystemExit(1)
