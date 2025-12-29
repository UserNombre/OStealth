all: unload compile load

DEV = lo

compile:
	clang -O2 -g -target bpf -c ostealth.c -o ostealth.o

load:
	sudo tc qdisc add dev $(DEV) clsact
	sudo tc filter add dev $(DEV) egress bpf direct-action \
    	obj ostealth.o sec tc_egress verbose

unload:
	sudo tc filter del dev $(DEV) egress || true
	sudo tc qdisc del dev $(DEV) clsact || true

clean:
	rm -f ostealth.o
