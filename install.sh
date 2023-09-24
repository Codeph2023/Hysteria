#!/bin/bash
# Custom Installer Script for Unlinet UDP-Hysteria Server
# (c) 2023 voltssh
# mod by Unlinet
export DEBIAN_FRONTEND=noninteractive

# Colors for better output
T_BOLD=$(tput bold)
T_GREEN=$(tput setaf 2)
T_YELLOW=$(tput setaf 3)
T_RED=$(tput setaf 1)
T_RESET=$(tput sgr0)

# Display a header with the script name and purpose
clear
echo "${T_GREEN} Please wait...${T_RESET}"
echo ""
# Check if running with sudo
if [[ "$EUID" -ne 0 ]]; then
    echo "${T_RED}Error: This script requires root privileges.${T_RESET}"
    echo "Please run with ${T_YELLOW}sudo${T_RESET} or as root user."
    exit 1
fi

# Check if systemd is available
if ! command -v systemctl &>/dev/null; then
    echo "${T_RED}Error: This script requires a systemd-based system.${T_RESET}"
    exit 1
fi

# Check for curl and other dependencies
check_dependencies() {
            clear
            echo "${T_YELLOW}Installing dependencies, please wait...${T_RESET}"
            apt-get clean >/dev/null 2>&1
			apt-get update >/dev/null 2>&1
package_name="sudo"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="curl"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="figlet"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="bc"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="lolcat"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="figlet"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="lsb-release"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="iptables"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
package_name="screen"
if dpkg -l | grep -q "^ii  $package_name "; then
    echo "$package_name is already installed."
else
    # If the package is not installed, install it without interaction
    echo "Installing $package_name..."
    apt-get install -y $package_name >/dev/null 2>&1
    echo "$package_name has been installed."
fi
clear
}

# Function to display error messages
error() {
    echo "${T_RED}Error: $1${T_RESET}" >&2
    exit 1
}

# Function to display success messages
success() {
    echo "${T_GREEN}Success: $1${T_RESET}"
}

# Function to display information messages
info() {
    echo "${T_YELLOW}Info: $1${T_RESET}"
}

# verification function
verification() {
    fetch_valid_keys() {
        keys=$(curl --insecure --silent "https://codeph.online/Hysteria/hysteria.json") 
        echo "$keys"
    }

    valid_keys=$(fetch_valid_keys)

    verify_key() {
        local key_to_verify="$1"
        local valid_keys="$2"

        if [[ $valid_keys == *"$key_to_verify"* ]]; then
            return 0 # Key is valid
        else
            return 1 # Key is not valid
        fi
    }

    clear
    figlet -k Unlinet | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k UDP-Hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
    echo -e "$BLUE•──────────────────────────────────────────────•$NC"
    echo -e "\033[1;33m You must have purchased access code.\033[0m  "
    echo -e "\033[1;33m If you didn't, contact [JRC]\033[0m          "
    echo -e "\033[1;33m https://unlinet.com\033[0m                   "
    echo -e "$BLUE•──────────────────────────────────────────────•$NC"
    echo ""
    read -p " Please enter access code: " user_key

    # Remove whitespaces from the user input
    user_key=$(echo "$user_key" | tr -d '[:space:]')

    # Verify the key length
    if [[ ${#user_key} -ne 10 ]]; then
        clear
        echo -e "${T_RED} ⇢ Verification failed.${T_RESET}"
        echo -e "${T_RED} ⇢ Aborting installation...${T_RESET}"
        sleep 1
		clear
        exit 1
    fi

    # Verify the key
    if verify_key "$user_key" "$valid_keys"; then
        clear
        echo "${T_GREEN} ⇢ Verification successful.${T_RESET}"
        echo "${T_GREEN} ⇢ Proceeding with the installation...${T_RESET}"
        sleep 1
		clear

        # Prompt user for input with default values
        prompt_input_with_default() {

            # Default values
            DEFAULT_DOMAIN="xxx"
            DEFAULT_PROTOCOL="udp"
            DEFAULT_UDP_PORT="5666"
            DEFAULT_OBFS="unlinet"
            DEFAULT_PASSWORD="unlinet"
            local var_name="$1"
            local prompt_text="$2"
            local default_value="$3"

            # Check if the variable is already set, and if not, use the default value
            if [ -z "${!var_name}" ]; then
                eval "$var_name=\"$default_value\""
            fi

            # Display the defined variable along with the default value in the prompt
            if [ -n "${!var_name}" ]; then
                read -p "$prompt_text (default: ${!var_name}): " user_input
            else
                read -p "$prompt_text (default: $default_value): " user_input
            fi

            # Use the user's input if provided, otherwise use the default
            if [ -n "$user_input" ]; then
                eval "$var_name=\"$user_input\""
            fi

            # Save user input to a file
            case "$var_name" in
            "DOMAIN") echo "${!var_name}" >/etc/unlinet-udph/DOMAIN ;;
            "PROTOCOL") echo "${!var_name}" >/etc/unlinet-udph/PROTOCOL ;;
            #"UDP_PORT") echo "${!var_name}" >/etc/unlinet-udph/UDP_PORT ;;
            "OBFS") echo "${!var_name}" >/etc/unlinet-udph/OBFS ;;
            "PASSWORD") echo "${!var_name}" >/etc/unlinet-udph/PASSWORD ;;
            esac
        }

        # Create the /etc/unlinet directory if it doesn't exist
        mkdir -p /etc/unlinet-udph

        # Prompt for domain and other values
        clear
        figlet -k Unlinet | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k UDP-Hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
        echo "•───────────────────────────────────────────────────────────────────────•"
        echo "Enter Domain Name (e.g., udp.unlinet.com)"
        prompt_input_with_default "DOMAIN" "=>" "$DEFAULT_DOMAIN"
        #echo "Enter Protocol (e.g., udp)"
        #prompt_input_with_default "PROTOCOL" "=>" "$DEFAULT_PROTOCOL"
        #echo "Enter UDP Port (e.g., 5666)"
        #prompt_input_with_default "UDP_PORT" "=>" "$DEFAULT_UDP_PORT"
        echo "Enter OBFS (e.g., unlinet)"
        prompt_input_with_default "OBFS" "=>" "$DEFAULT_OBFS"
        echo "Enter Password(e.g., unlinet)"
        prompt_input_with_default "PASSWORD" "=>" "$DEFAULT_PASSWORD"
        echo "•───────────────────────────────────────────────────────────────────────•"

        # patch
        PROTOCOL="udp"
		UDP_PORT="5666"
  	    echo "udp" > /etc/unlinet-udph/PROTOCOL 
		echo "5666" > /etc/unlinet-udph/UDP_PORT

        # Export user input as environment variables
        export DOMAIN
        export PROTOCOL
        export UDP_PORT
        export OBFS
        export PASSWORD

        # Function to install the Hysteria server
        install_hysteria() {
            echo "${T_YELLOW}Installing server binaries...${T_RESET}"
            # download and install from GitHub
            mkdir -p /etc/hysteria
            curl --insecure --silent -L -o hysteria https://codeph.online/Hysteria/hysteria.zi 
            mv hysteria /usr/local/bin/hysteria
            chmod +x /usr/local/bin/hysteria
            curl --insecure --silent -L -o hysteria https://codeph.online/Hysteria/hysteria.firenet 
            mv hysteria /usr/sbin/hysteria
            chmod +x /usr/sbin/hysteria
            curl --insecure --silent -L -o hysteria https://codeph.online/Hysteria/hysteria.volt 
            mv hysteria /usr/bin/hysteria
            chmod +x /usr/bin/hysteria
        }
		
		install_badvpn() {
 curl --insecure --silent -L -o badvpn https://codeph.online/Hysteria/badvpn
 mv badvpn /usr/bin/badvpn
 chmod +x /usr/bin/badvpn
 # Set BadVPN to Start on Boot via .profile
 sed -i '$ i\screen -AmdS badvpn badvpn --listen-addr 127.0.0.1:7300' /root/.profile
 # Start BadVPN via Screen
 screen -AmdS badvpn badvpn --listen-addr 127.0.0.1:7300
		}

        # Function to create the systemd service configuration
        create_systemd_service() {
            cat <<EOF >/etc/systemd/system/unlinet-hysteria-server.service
[Unit]
Description=Unlinet UDP-Hysteria Server
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/etc/hysteria
Environment="PATH=/usr/bin/hysteria"
ExecStart=/usr/bin/hysteria server --config /etc/hysteria/config.json

[Install]
WantedBy=multi-user.target
EOF
        }

        # Function to create the Hysteria server configuration
        create_hysteria_config() {
            rm -f /etc/hysteria/config.json
            cat <<EOF >/etc/hysteria/config.json
{
  "listen": ":$UDP_PORT",
  "protocol": "$PROTOCOL",
  "cert": "/etc/hysteria/hysteria.server.crt",
  "key": "/etc/hysteria/hysteria.server.key",
  "up": "100 Mbps",
  "up_mbps": 100,
  "down": "100 Mbps",
  "down_mbps": 100,
  "disable_udp": false,
  "obfs": "$OBFS",
  "auth": {
    "mode": "passwords",
    "config": ["$PASSWORD"]
  }
}
EOF
        # [+config+]
        chmod +x /etc/hysteria/config.json
        }

        # Function to enable and start Hysteria systemd service
        start_hysteria_service() {
            systemctl enable unlinet-hysteria-server >/dev/null 2>&1
            systemctl start unlinet-hysteria-server >/dev/null 2>&1
            success "Unlinet UDP-Hysteria server service started and enabled."
        }

        # Function to disable related systemd services
        disable_systemd_service() {
            rm -f /etc/systemd/system/multi-user.target.wants/unlinet-hysteria-server.service >/dev/null 2>&1
            rm -f /etc/systemd/system/multi-user.target.wants/unlinet-hysteria-server@*.service >/dev/null 2>&1
            systemctl daemon-reload >/dev/null 2>&1
        }

        # Function to setup SSL certificates
        setup_ssl() {
            echo "${T_YELLOW}Generating SSL certificates...${T_RESET}"

            openssl genrsa -out /etc/hysteria/hysteria.ca.key 2048  &>/dev/null

            openssl req -new -x509 -days 3650 -key /etc/hysteria/hysteria.ca.key \
                -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=Hysteria Root CA" \
                -out /etc/hysteria/hysteria.ca.crt &>/dev/null

            openssl req -newkey rsa:2048 -nodes -keyout /etc/hysteria/hysteria.server.key \
                -subj "/C=CN/ST=GD/L=SZ/O=Hysteria, Inc./CN=$DOMAIN" \
                -out /etc/hysteria/hysteria.server.csr &>/dev/null

            openssl x509 -req -extfile <(printf "subjectAltName=DNS:$DOMAIN,DNS:$DOMAIN") \
                -days 3650 -in /etc/hysteria/hysteria.server.csr \
                -CA /etc/hysteria/hysteria.ca.crt -CAkey /etc/hysteria/hysteria.ca.key \
                -CAcreateserial -out /etc/hysteria/hysteria.server.crt &>/dev/null
			clear
        }

        # Function to start services
        start_services() {
            echo "${T_YELLOW}Starting services...${T_RESET}"
            apt update >/dev/null 2>&1
            debconf-set-selections <<<"iptables-persistent iptables-persistent/autosave_v4 boolean true"
            debconf-set-selections <<<"iptables-persistent iptables-persistent/autosave_v6 boolean true"
            apt -y install iptables-persistent >/dev/null 2>&1
            iptables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
            iptables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 10000:65000 -j DNAT --to-destination :$UDP_PORT
            #ip6tables -t nat -A PREROUTING -i $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -p udp --dport 10000:65000 -j DNAT --to-destination $UDP_PORT
            #ip6tables -t nat -A PREROUTING -i eth0 -p udp -m udp --dport 10000:65000 -j DNAT --to-destination :$UDP_PORT
            #sysctl net.ipv4.conf.all.rp_filter=0
            #sysctl net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0
            echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
            echo "net.ipv4.conf.all.rp_filter=0" >> /etc/sysctl.conf
            echo "net.ipv4.conf.$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1).rp_filter=0" >> /etc/sysctl.conf
            sysctl -p >/dev/null 2>&1
            iptables-save >/etc/iptables/rules.v4  >/dev/null 2>&1
            #sudo ip6tables-save >/etc/iptables/rules.v6
            systemctl enable unlinet-hysteria-server.service  >/dev/null 2>&1
            systemctl start unlinet-hysteria-server.service >/dev/null 2>&1

        }

        # [+menu+]
        unlinet() {
            clear
            figlet -k Unlinet | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k UDP-Hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
            echo "•───────────────────────────────────────────────────────────────────────•"
            echo ""
            echo "${T_GREEN} Please wait...${T_RESET}"
            echo ""
            wget --no-check-certificate -O /usr/bin/udph 'https://codeph.online/Hysteria/udph' &>/dev/null
            wget --no-check-certificate -O /etc/unlinet-udph/cfgupt.py 'https://codeph.online/Hysteria/cfgupt.py' &>/dev/null
            chmod +x /usr/bin/udph &>/dev/null
            chmod +x /etc/unlinet-udph/cfgupt.py &>/dev/null
            # [+config+]
            chmod +x /etc/hysteria/config.json
            echo ""
        }

        # Main installation steps
        main() {
            clear

            mkdir -p /etc/unlinet-udph
            #check_dependencies
            install_hysteria
            install_badvpn
            #default_value
            disable_systemd_service
            create_systemd_service
            create_hysteria_config
            start_hysteria_service
            setup_ssl
            start_services
            unlinet

            clear
            echo "${T_GREEN}Unlinet UDP-Hysteria Server installation completed!${T_RESET}"
            echo ""
            echo "Type: "${T_YELLOW}udph${T_RESET}" to access the menu."
        }
        # Execute the main function
        main

    else
        clear
        figlet -k Unlinet | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1' && figlet -k Hysteria | awk '{gsub(/./,"\033[3"int(rand()*5+1)"m&\033[0m")}1'
        echo "•───────────────────────────────────────────────────────────────────────•"
        echo -e "${T_RED} ⇢ Verification failed.${T_RESET}"
        echo -e "${T_RED} ⇢ Aborting installation...${T_RESET}"
        exit 1
    fi
}

##--Installation--##
rm -rf /etc/unlinet-udph && rm -rf /etc/hysteria && rm -rf /usr/local/bin/hysteria && rm -rf /usr/bin/hysteria && rm -rf install.sh
check_dependencies
verification
history -c
rm ~/.bash_history
touch ~/.bash_history
