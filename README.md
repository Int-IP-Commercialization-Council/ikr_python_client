# ikr_python_client
IKR is a digital witness tool for proving the existence of documents, data, valuable knowledge, intellectual properties (IP), and contents.
 
It combines digital fingerprint (SHA2 and SHA3) and time stamp to earmark submission time of documents. This ensures that proper priority dates for acknowledging and memorializing IP:
· The evolution of song composition; 
· Laboratory experiments and data prior to a patent application; 
· The existence of the trade secret (without revealing its content),
· Use of a technology for prior use purposes, etc.
 
This is a Python server version that can be run as a cron job or at command line.  It runs under Python 2.x and 3.x.

## Registration
In order to use IKR, you have to register first at https://ikr.iipcc.org.  

## Installation
Download ikr_client.py client_config.json and requirements_2x.txt (or requirements_3x.txt depending on your Python version) to a directory.  Then edit client cileng_config.json with your user id, password, and directories that you need to generate the digital fingerprints.  The user id and password are the user id and password you registered with https://ikr.iipcc.org.

Go to the directory and type the following commands to install the required Python modules:
```
pip install -r requirements_2x.txt
```
or
```
pip install -r requirements_3x.txt
```

## Running
After updating client_config.json and installed the required Python modules.  You can now run ikr_client:
```
python ik_client.py
```
