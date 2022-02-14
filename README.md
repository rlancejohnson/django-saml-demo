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
1. Update IDP saml settings in the get_idp_id_info and get_saml_settings functions in demo/views.py

## Contributions
This is a demo of the python3-saml package made available by OneLogin at https://github.com/onelogin/python3-saml. 
