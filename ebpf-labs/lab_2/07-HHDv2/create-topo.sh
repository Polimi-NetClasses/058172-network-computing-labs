#!/bin/bash

COLOR_RED='\033[0;31m'
COLOR_GREEN='\033[0;32m'
COLOR_YELLOW='\033[0;33m'
COLOR_OFF='\033[0m' # No Color

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# include helper.bash file: used to provide some common function across testing scripts
source "${DIR}/../libs/helpers.bash"

# Read the YAML file into a variable
yaml=$(cat ${DIR}/config.yaml)

# Check if shyaml is installed, if not install it
if ! [ -x "$(command -v shyaml)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: shyaml is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing shyaml... ${COLOR_OFF}"
  sudo pip install shyaml
fi

# Check if ethtool is installed, if not install it
if ! [ -x "$(command -v ethtool)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: ethtool is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing ethtool... ${COLOR_OFF}"
  sudo apt-get install ethtool -y
fi

# Check if nmap is installed, if not install it
if ! [ -x "$(command -v nmap)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: nmap is not installed ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Installing nmap... ${COLOR_OFF}"
  sudo apt-get install nmap -y
fi

# Get the number of elements in the ips list
num_ips=$(echo "$yaml" | shyaml get-length ips)

# function cleanup: is invoked each time script exit (with or without errors)
function cleanup {
  set +e
  delete_veth $1
  # Check is second parameter is not empty
  if [ ! -z "$2" ]; then
    echo -e "${COLOR_GREEN} Topology deleted successfully ${COLOR_OFF}"
  else
    echo -e "${COLOR_RED} Error while running the script ${COLOR_OFF}"
    echo -e "${COLOR_YELLOW} Topology deleted successfully ${COLOR_OFF}"
  fi
}
trap 'cleanup "$num_ips"' ERR

# Enable verbose output
set +x

cleanup ${num_ips} 1

# Check if xdp_loader is compiled, if not compile it
if ! [ -x "$(command -v ${DIR}/xdp_loader)" ]; then
  echo -e "${COLOR_YELLOW} WARNING: xdp_loader is not compiled ${COLOR_OFF}" >&2
  echo -e "${COLOR_YELLOW} Compiling xdp_loader... ${COLOR_OFF}"
  make -C ${DIR} xdp_loader
fi

if ! [ -x "$(command -v ${DIR}/xdp_loader)" ]; then
  echo -e "${COLOR_RED} ERROR: xdp_loader is not compiled ${COLOR_OFF}" >&2
  exit 1
fi

# Makes the script exit, at first error
# Errors are thrown by commands returning not 0 value
set -e

set +x
# Create two network namespaces and veth pairs
create_veth ${num_ips}

# Loop through the ips in the YAML file
for (( i=0; i<$num_ips; i++ )); do
    elem=$(echo "$yaml" | shyaml get-value ips.$i)

    ip=$(echo "$elem" | shyaml get-value "ip")
    port=$(echo "$elem" | shyaml get-value "port")
    mac=$(echo "$elem" | shyaml get-value "mac")
    gw=$(echo "$elem" | shyaml get-value "gw")

    echo -e "${COLOR_GREEN} IP: $ip, Port: $port, MAC: $mac ${COLOR_OFF}"

    sudo ip netns exec ns${port} ifconfig veth${port}_ hw ether ${mac}
    sudo ip netns exec ns${port} ifconfig veth${port}_ ${ip}/24
    sudo ifconfig veth${port} ${gw}/24

    sudo ip netns exec ns${port} ${DIR}/xdp_loader -i veth${port}_

    sudo ethtool --offload veth${port} rx off tx off > /dev/null 2>&1
    sudo ip netns exec ns${port} ethtool --offload veth${port}_ rx off tx off > /dev/null 2>&1

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

echo -e "${COLOR_GREEN} Topology created successfully ${COLOR_OFF}"
