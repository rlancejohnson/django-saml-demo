# SAML Demo in Django
## Prerequesites
1. python version 3.9 or greater installed
1. pyenv installed
1. poetry installed
1. mkcert installed

## Setup the project
1. Clone and cd into the repo
1. `pyenv install 3.9.10`
1. `poetry env use $(pyenv which python)`
1. `mkcert -install`
1. `mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1`
1. `poetry shell`
1. `poetry install`
1. `./manage.py runsslserver --cert cert.pem --key key.pem`
1. Update IDP saml settings in the get_saml_settings function in demo/views.py 
