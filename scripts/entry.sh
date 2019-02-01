#!/bin/sh

useradd -u $UID -m $USER
cd /virt
echo 'source /tmp/pwndbg/gdbinit.py' > /home/$USER/.gdbinit
su $USER -s /bin/bash
