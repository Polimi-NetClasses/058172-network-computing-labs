# eBPF Labs

In these set of labs, we will lean how to write **eBPF** programs and how to use the eBPF language.

We provide several exercises that will help you to learn the basics of the eBPF language.

_Note_: Part of the material that we used for this lab come from the [_XDP Tutorial_](https://github.com/xdp-project/xdp-tutorial). We would like to thank the authors for their work.

## Getting started

You have two options to run the lab:

1. You can run the lab on your local machine. We suggest you to use a Linux machine, preferably with Ubuntu 20.04 or Ubuntu 22.04. If you are using a different Linux distribution, you might need to install some additional packages. The instructions to install the packages are available [here](#install-prerequisites)

2. You can run the lab on a VM. We provide a VM that you can download and import into VirtualBox. The instructions are avaialble [here](#download-the-vm)

## Run on your local machine

### Install prerequisites

On Debian and Ubuntu installations, install the dependencies like this:

```bash
 sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential linux-headers-$(uname -r) linux-tools-common linux-tools-generic tcpdump
```

Then, you might need to install Python to run the Python scripts that we provide. You can install Python by running the following command:

```bash
sudo apt install python3
```

Finally, install the required Python packages by running the following command:

```bash
pip3 install -r lab_1/requirements.txt
```

## Download the VM

To get started with the labs, you first need to install VirtualBox, a virtualization software that will allow you to run a virtual machine (VM) on your machine. You can download VirtualBox from [here](https://www.virtualbox.org/wiki/Downloads).

In the PDF file that we provided, you will find a link to download the VM. Once you download the VM, you can import it into VirtualBox by clicking on `File -> Import Appliance...` and selecting the VM file that you downloaded.

### Start the VM

When you start the VM, you will be prompted to enter a username and a password. The username is `ebpf` and the password is `ebpf`.

## Clone this repository into your local machine

Once you are logged into the VM, you can clone this repository into your local machine by running the following command:

```bash
git clone https://github.com/Polimi-NetClasses/058172-network-computing-labs.git --recurse-submodules
```

After you clone the repository, you can start working on the labs.
Please, refer to the PDF file that we provide for each lab to get more information about the lab and the instructions to complete it.
