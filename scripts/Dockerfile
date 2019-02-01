FROM ubuntu:trusty
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/ftp.daumkakao.com/g" /etc/apt/sources.list

RUN apt update
RUN apt -yy install qemu make gcc python wget git python-pip libpython3.4
RUN chmod 4755 `which qemu-system-x86_64`

WORKDIR /tmp
RUN wget http://cs492virt.kaist.ac.kr/gdb_7.7.1-0ubuntu5~14.04.2_amd64.deb
RUN dpkg -i gdb_7.7.1-0ubuntu5~14.04.2_amd64.deb
RUN git clone https://github.com/pwndbg/pwndbg.git
RUN sed -i "s/sudo apt-get -y install gdb python-dev python3-dev python-pip python3-pip libglib2.0-dev libc6-dbg/sudo apt-get -y install python-dev python3-dev python-pip python3-pip libglib2.0-dev libc6-dbg/g" /tmp/pwndbg/setup.sh
WORKDIR /tmp/pwndbg
RUN ./setup.sh

ADD entry.sh /entry.sh
RUN chmod +x /entry.sh

ENTRYPOINT ["/entry.sh"]
