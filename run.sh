#!/bin/bash

# --- Configs ---
IMAGE_NAME="my-honeypot"
CONTAINER_NAME="my-honeypot-container"
LOG_HOST_DIR="$(pwd)/logs"

mkdir -p $LOG_HOST_DIR

# --- stop and remove old container ---
echo "[*] Stopping and removing '$CONTAINER_NAME' (if exists)..."
sudo docker stop $CONTAINER_NAME || true
sudo docker rm $CONTAINER_NAME || true

# --- rebuild image ---
echo "[*] Building image '$IMAGE_NAME'..."
sudo docker build -t $IMAGE_NAME .
if [ $? -ne 0 ]; then
    echo "[!!] Docker image build error"
    exit 1
fi

sudo docker image prune -f

# --- read .env ports ---
echo "[*] Reading .env ports configs..."
ports_config=$(grep '^HONEYPOT_PORTS' .env | cut -d '=' -f 2- | tr -d '"')

if [ -z "$ports_config" ]; then
    echo "[!!] Variable HONEYPOT_PORTS not found in the .env file!"
    echo "[*] Default port: 23"
    ports_config="23:telnet_ubuntu"
fi

# docker -p flags
docker_port_flags=""
IFS=',' read -ra port_pairs <<< "$ports_config"
for pair in "${port_pairs[@]}"; do
    port_num=$(echo $pair | cut -d ':' -f 1)
    echo "    - Mapping port: $port_num"
    docker_port_flags="$docker_port_flags -p $port_num:$port_num"
done

# --- execute new Container ---
echo "[*] Booting new container '$CONTAINER_NAME'..."
echo "Ports commands: $docker_port_flags"

sudo docker run -d --rm \
    --name $CONTAINER_NAME \
    $docker_port_flags \
    --env-file .env \
    -v $LOG_HOST_DIR:/app/logs \
    $IMAGE_NAME

if [ $? -ne 0 ]; then
    echo "[!!] Error booting the contêiner"
    exit 1
fi

echo "[*] Container started!"
echo "[*] Entering container terminal"
echo "[*] Enter 'exit' to exit the terminal"
sudo docker exec -it $CONTAINER_NAME /bin/bash

#echo "[*] Press [Ctrl+C] to stop viewing logs"
#echo "--- Honeypot Logs (Live) ---"
#sudo docker logs -f $CONTAINER_NAME
