C:\msys64\usr\bin\sh -l -c "/usr/bin/whoami"
C:\msys64\usr\bin\sh -l -c "/usr/bin/curl -u '%github_authorization%' -H 'Accept: application/vnd.github.v3+json' 'https://api.github.com/repos/%APPVEYOR_REPO_NAME%/actions/workflows/docker.yml/dispatches' -d \"{'ref':'%APPVEYOR_REPO_COMMIT%'}\" }"
