# JanusPot 🍯

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-20.10-2496ED?logo=docker&logoColor=white)
![Shell Script](https://img.shields.io/badge/Shell_Script-GNU_Bash-4EAA25?logo=gnubash&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-EC2-FF9900?logo=amazonaws&logoColor=white)
![Git](https://img.shields.io/badge/Git-F05032?logo=git&logoColor=white)

This project is a modular, Dockerized, medium-interaction **honeypot** designed to attract, deceive, and log automated attack vectors in real-time. It emulates common services (like Telnet and FTP) on multiple ports, captures credentials (usernames, passwords), and logs the shell commands attackers attempt to execute after a "successful" login.

The entire project is packaged with Docker and automated with shell scripts, allowing deployment on any server (like an AWS EC2 instance).

<img width="1450" height="218" alt="honeypotexample" src="https://github.com/user-attachments/assets/5339b6e2-9371-4525-bcf0-9e38e4d20b12" />

---

## ✨ Key Features

* **Multi-Port Listener:** Uses `threading` to listen on multiple ports simultaneously (e.g., 21, 23).
* **Modular Service Emulation:** Loads service profiles from `banners.py` to emulate different services (Telnet, FTP, Cisco Routers, etc.).
* **Medium-Interaction Honeypot:** Simulates a state machine (Login -> Password -> Shell) to deceive bots into revealing their full payloads.
* **Threat Intelligence:** Captures attacker IP, Geolocation (Country, ASN), and all interactions (usernames, passwords, commands).
* **Docker-Ready:** Fully containerized for rapid, isolated, and secure deployment.
* **Deployment Automation:** Includes a `run.sh` script that automatically stops, rebuilds, and relaunches the container with the correct configuration.
* **Persistent & Safe Logging:** Creates a separate log file for each monitored port (e.g., `logs/honeypot_port_23.log`).

---

## 🚀 Getting Started

This project is designed to run in a **Linux** environment with Docker and Git installed.

### 1. Prerequisites

* **Git:** To clone the repository.
* **Docker:** To build and run the container. (See [Docker install instructions for Ubuntu](https://docs.docker.com/engine/install/ubuntu/)).

### 2. Configuration

The project is configured using environment variables.

**a.** Create your `.env` file from the template:
```bash
cp .env.example .env
```

**b.** Edit the `.env` file with your values:
```bash
nano .env
```

The `.env` file **MUST** contain the following:

```ini
# .env

# (Required) Your free token from https://ipinfo.io/ for geolocation
IPINFO_TOKEN="YOUR_TOKEN_HERE"

# (Optional) Message limit per connection to prevent DoS
MAX_NUMBER_MESSAGES="20"

# (Required) Comma-separated list of ports and banner profiles to use
# Format: "PORT1:banner_profile1,PORT2:banner_profile2"
# Banner profiles must match the keys in banners.py
HONEYPOT_PORTS="21:ftp_vsftpd,23:telnet_ubuntu"

# (Required) Fixes a Python output buffering issue inside Docker
PYTHONUNBUFFERED=1
```

### 3. Network Configuration (Firewall)

For the honeypot to receive "attacks", the ports you configured in the .env file must be open to the public internet.

> Example: if using AWS EC2 (Security Groups):
> - Go to your EC2 Instance Console.
> - Navigate to Security Groups -> Edit inbound rules.
> - Add a Custom TCP Rule for each port in your HONEYPOT_PORTS (e.g., 21, 23, 6379, 8080).
> - Source: Set to Anywhere-IPv4 (0.0.0.0/0).

> [!IMPORTANT]
> SSH Security: If you are monitoring port 22 as a honeypot, move your real SSH service to a different port (e.g., 2222) before opening port 22 to the world.

### 4. Build and Run the Honeypot

The entire build and run process is automated with a shell script.

**a.** Make the script executable:
```bash
chmod +x run.sh
```

**b.** Run the script:
```bash
./run.sh
```

This script will automatically:
1.  Stop and remove any old container.
2.  Build (or rebuild) the Docker image.
3.  Prune any old, dangling Docker images (`<none>`).
4.  Read your `.env` file to discover which ports to map.
5.  Start the new container in detached (`-d`) mode with logs mapped to the `./logs` folder.
6.  Show you the live logs (`docker logs -f`).

### 5. Monitoring

There are two ways to see what your honeypot is doing:

* **Live Console Logs:**
    ```bash
    sudo docker logs -f my-honeypot-container
    ```
* **Persistent File Logs:**
    Logs for each port are saved permanently in the `logs/` folder on your host server.
    ```bash
    ls -l logs/
    # honeypot_port_21.log
    # honeypot_port_23.log

    tail -f logs/honeypot_port_23.log
    ```

### 6. Stopping the Honeypot

To stop the container, use the standard Docker command:
```bash
sudo docker stop my-honeypot-container
```
> - Because the `run.sh` is using the option `--rm`, the honeypot will automatically stop and remove the container.
> - If you want the honeypot container to restart when reboot, use the option `--restart=always`.

---

## 📁 Project Structure

```
.
├── .dockerignore     
├── .env.example      # Example file for configuration
├── .gitignore        
├── Dockerfile        
├── banners.py        # Emulation profiles
├── honeypot.py       # Main honeypot logic
├── logs/             # Where persistent logs are saved
├── requirements.txt  
└── run.sh            
```
