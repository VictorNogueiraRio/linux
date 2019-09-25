============
Environment
============

- Linux Distribution: Debian GNU/Linux 9.8 (stretch)
- Kernel Version: 5.2.0-rc2+
- CPU model name: Intel(R) Core(TM) i5-5257U CPU @ 2.70GHz
- Cores: 1
- RAM: 2GB

==================================
Loading and compiling eBPF Scripts
==================================

To load an eBPF program created in this repository follow these steps::

 1) Go to the samples/bpf directory
 2) Run Make
 3) Run ip link set dev [interfacename] xdp obj [progname.o] sec [progsec]

To remove the loaded eBPF program run::

 ip link set dev [interfacename] xdp off

source::

 https://cilium.readthedocs.io/en/latest/bpf/
