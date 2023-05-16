#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# include helper.bash file: used to provide some common function across testing scripts
source "${DIR}/../libs/helpers.bash"

# Read the YAML file into a variable
yaml=$(cat ${DIR}/config.yaml)

# Check if shyaml is installed, if not install it
if ! [ -x "$(command -v shyaml)" ]; then
  echo 'Error: shyaml is not installed.' >&2
  echo 'Installing shyaml...'
  sudo pip install shyaml
fi

# Check if ethtool is installed, if not install it
if ! [ -x "$(command -v ethtool)" ]; then
  echo 'Error: ethtool is not installed.' >&2
  echo 'Installing ethtool...'
  sudo apt-get install ethtool -y
fi

# Check if nmap is installed, if not install it
if ! [ -x "$(command -v nmap)" ]; then
  echo 'Error: nmap is not installed.' >&2
  echo 'Installing nmap...'
  sudo apt-get install nmap -y
fi

# Get the number of elements in the ips list
num_ips=$(echo "$yaml" | shyaml get-length ips)

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth $1
}
trap 'cleanup "$num_ips"' ERR

# Enable verbose output
set -x

cleanup ${num_ips}
# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

# Create two network namespaces and veth pairs
create_veth ${num_ips}

set +x
# Loop through the ips in the YAML file
for (( i=0; i<$num_ips; i++ )); do
    elem=$(echo "$yaml" | shyaml get-value ips.$i)

    ip=$(echo "$elem" | shyaml get-value "ip")
    port=$(echo "$elem" | shyaml get-value "port")
    mac=$(echo "$elem" | shyaml get-value "mac")
    gw=$(echo "$elem" | shyaml get-value "gw")

    echo "IP: $ip, Port: $port, MAC: $mac"

    sudo ip netns exec ns${port} ifconfig veth${port}_ hw ether ${mac}
    sudo ip netns exec ns${port} ifconfig veth${port}_ ${ip}/24
    sudo ifconfig veth${port} ${gw}/24

    sudo ip netns exec ns${port} ./xdp_loader -i veth${port}_

    sudo ethtool --offload veth${port} rx off tx off
    sudo ip netns exec ns${port} ethtool --offload veth${port}_ rx off tx off

    for (( j=0; j<$num_ips; j++ )); do
        nested_elem=$(echo "$yaml" | shyaml get-value ips.$j)

        nested_ip=$(echo "$nested_elem" | shyaml get-value "ip")
        nested_port=$(echo "$nested_elem" | shyaml get-value "port")

        # check if the port is the same as the current port
        if [ "$nested_port" == "$port" ]; then
            continue
        fi

        sudo ip netns exec ns${port} ip route add ${nested_ip}/32 via ${gw}
    done
done
