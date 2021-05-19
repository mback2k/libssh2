@echo off

netsh interface portproxy add v4tov4 listenport=3389 listenaddress=%1 connectport=22 connectaddress=127.0.0.1
netsh interface portproxy show all

C:\msys64\usr\bin\sh -l -c "/usr/bin/ssh-keygen -b 2048 -t rsa -f auth -q -N '' && mkdir .ssh && mv auth.pub .ssh/authorized_keys"
C:\msys64\usr\bin\sh -l -c "/usr/bin/ssh-keygen -A"
C:\msys64\usr\bin\sh -l -c "/usr/bin/sshd"

C:\msys64\usr\bin\sh -l -c '/usr/bin/curl -d "{\"ref\": \"%APPVEYOR_REPO_BRANCH%\", \"inputs\": {\"ssh_host\": \"%2\", \"ssh_port\": \"%3\", \"ssh_user\": \"`whoami`\", \"ssh_hostcfg\": \"RemoteForward 127.0.0.1:%OPENSSH_SERVER_PORT% 127.0.0.1:%OPENSSH_SERVER_PORT%,RemoteForward 127.0.0.1:2375 /var/run/docker.sock\", \"ssh_hostkey\": \"`paste -d , /etc/ssh/ssh_host_*_key.pub`\", \"ssh_privkey\": \"`paste -sd , auth`\"}}" -u "%github_authorization%" -H "Content-Type: application/json" -H "Accept: application/vnd.github.v3+json" -s "https://api.github.com/repos/%APPVEYOR_REPO_NAME%/actions/workflows/appveyor.yml/dispatches"'
