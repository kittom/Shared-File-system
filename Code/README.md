# File sharing system

## Run the project

first you need to either source the virtual environment (venv), or create a new one and install the requirements via requirements.txt

### Server

To run the server you need to run the following command

```zsh
cd sharedFiles/
python3 manage.py runsslserver --certificate cert.pem --key key.pem 0.0.0.0:8000
```

### Client

to run the client, you need to change directory to the client files and run the client via the client.py file

```zsh
cd client/screens/
python3 client.py
```
