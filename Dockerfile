FROM ubuntu:20.04

# insatll the goods
RUN apt update && apt install socat libc6-i386 -y

# add users
RUN useradd -m -s /bin/bash challenge

# add challenges
COPY challenge flag /home/challenge/
COPY init.sh /root/init.sh

# perms
RUN chown -R root:challenge /home/challenge && chmod -R 750 /home/challenge

EXPOSE 9000

ENTRYPOINT ["/root/init.sh"]
