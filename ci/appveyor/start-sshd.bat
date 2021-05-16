C:\msys64\usr\bin\sh -l -c "/usr/bin/whoami"
C:\msys64\usr\bin\sh -l -c "/usr/bin/ssh-keygen -b 2048 -t rsa -f ci -q -N '' && mkdir .ssh && mv ci.pub .ssh/authorized_keys && cat ci"
C:\msys64\usr\bin\sh -l -c "/usr/bin/ssh-keygen -A"
C:\msys64\usr\bin\sh -l -c "/usr/bin/sshd"
