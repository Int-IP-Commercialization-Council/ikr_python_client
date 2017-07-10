# ikr_python_client
The IKR is a digital witness tool evidencing the existence of documents, data, valuable knowledge, intellectual properties (IP), and contents.

It combines digital fingerprints (SHA2 and SHA3) and a time stamp to earmark your document showing exactly the time of your submission and maintains this in a publically-available database for future legal purposes.
 
This ensures that you have proper priority dates for acknowledging and memorializing:
· The evolution of your song composition; 
· Laboratory experiments and data prior to a patent application; 
· The existence of the trade secret (without revealing its content),
· Your use of a technology for prior use purposes, etc.

The IKR offers the additional protection IP rights alone cannot protecting your ability to create (new music); earn money and/or receive recognition from your creations, inventions, etc.
 
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
Ensure the directory is writable as a SQLite database will be created by the script at the directory.

## Running
After updating client_config.json and installed the required Python modules.  You can now run ikr_client:
```
python ik_client.py
```
