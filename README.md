# qutwh-pwn-challenge

~~Connect to the challenge at `nc 139.180.162.37 9000`~~

The challenge is over! If you want to spin up the service yourself, the easiest way is via docker.

On kali / any debian derivative, simply:

```bash
sudo apt update && sudo apt install docker.io docker-compose -y
cd qutwh-pwn-challenge
docker-compose up -d
```

On Windows / Mac, assuming you have [Docker Desktop](https://www.docker.com/products/docker-desktop/) up and running, just:

```bash
cd qutwh-pwn-challenge
docker compose up -d
```

This will build the container image, and then start a container. You will find the service listening on localhost, port 9000.
