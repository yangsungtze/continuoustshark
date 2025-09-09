# continuoustshark

## Build UDP_Generator
docker build -f Dockerfile.udpgenerator -t udp-generator .
## Run UDP_Generator
docker run --rm --net=host udp-generator

## Build Supervisor
docker build -f Dockerfile.supervisor -t net-sniffer .
## Run Supervisor
docker run --rm -it \
    --net=host \
    --cap-add=NET_ADMIN \
    --cap-add=NET_RAW \
    -v ./pcaps:/captures \
    net-sniffer