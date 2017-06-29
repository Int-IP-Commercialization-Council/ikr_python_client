#The MIT License
#
# Copyright (c) 2015-2017 International IP Commercialization Council. https://www.iipcc.org
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# -*- coding: utf-8 -*-
#
#
# Directory sync client
#
#
import hashlib
import json
import logging
import os
import sqlite3
import sys
import time
if sys.version_info < (3, 6):
   import sha3
import zlib
import base64
import sys
import requests
from requests.adapters import HTTPAdapter
import ntpath
import requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

old_data = []
ret = []
# Reading config file
CONFIG_FILE = 'client_config.json'
with open(CONFIG_FILE) as json_data_file:
    config = json.load(json_data_file)

TOKEN_URL = '%s/sync/api/v1.0/token' % config['server_url']
TOKEN_REFRESH_URL = "%s/sync/api/v1.0/token/refresh" % config['server_url']
PUSH_URL = '%s/sync/api/v1.0/data' % config['server_url']

# SSL Verification DISABLED for DEBUG - self-signed cert
SSL_VERIFY = True

# HTTP requests with 3 retries
s = requests.Session()
s.mount(config['server_url'], HTTPAdapter(max_retries=3))


# Init logger
def logging_init(log_file):
    # Setup logging
    # TODO: add logging file output
    tlogger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    tlogger.addHandler(handler)
    tlogger.setLevel(logging.INFO)
    return tlogger


log_file = config['logpath'] if 'logpath' in config else None
logger = logging_init(log_file)

# DB connection
# Open SQLite DB
sql_conn = sqlite3.connect(config['sqlitepath'])
sql_conn.row_factory = sqlite3.Row
cur = sql_conn.cursor()
# Open database if not create table
sql = ("CREATE TABLE IF NOT EXISTS files\n"
       "    (\n"
       "        created_at INTEGER,\n"
       "        updated_at INTEGER,\n"
       "        filename TEXT PRIMARY KEY NOT NULL,\n"
       "        size INTEGER,\n"
       "        hash TEXT\n"
       "    );\n"
       "    ")
cur.execute(sql)
sql_conn.commit()


def get_file_hash(file_name):
   blocksize = 65536
   #generate SHA2-256 and SHA3-256
   sha2_256 = hashlib.sha256()
   sha3_256 = hashlib.sha3_256()
   try:
      with open(file_name, 'rb') as f:
         for block in iter(lambda: f.read(blocksize), b''):
            sha2_256.update(block)
            sha3_256.update(block)
   except IOError as e:
      logger.error("I/O error({0}): {1}".format(e.errno, e.strerror))
   except:
      logger.error("Unexpected error:", sys.exc_info()[0])
   return sha2_256.hexdigest()+sha3_256.hexdigest()#+blake2.hexdigest()

def process_dir(dir, recursive_type):
   # Process dir generating hashes
   global ret
   last_dir=""
   dir_counter=0
   for root, dirs, files in os.walk(dir):
      if ((recursive_type=="O" and dir_counter==0) or recursive_type=="R"):
         print ("Processing the directory of "+root+" ...")
         for file in files:
            try:
               file_name = os.path.join(root, file)
               ret.append({
               'filename': file_name,
               'size': os.path.getsize(file_name),
               'hash': get_file_hash(file_name),
               'created_at': time.time(),
               })
            except IOError as e:
               logger.error("I/O error({0}): {1}".format(e.errno, e.strerror))
            except os.error as e:
               logger.error("Cannot read file of "+file_name)
            except:
               exc_type, exc_obj, exc_tb = sys.exc_info()
               fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
               logger.error("Unexpected error:", str(sys.exc_info()[0]))
               logger.info(exc_type)
               logger.info(fname)
               logger.info(exc_tb.tb_lineno)
         send_to_server (ret)
         dir_counter = dir_counter + 1
      else:
         break;
   return []

#only to send hash of new files
def compare_dicts(old_dict, new_dict):
    # Get new items and changed items
    old_filenames = [x['filename'] for x in old_dict]
    new_filenames = [x['filename'] for x in new_dict]

    new_items = [x for x in new_dict if x['filename'] not in old_filenames]

    old_indexed = {}
    for item in [x for x in old_dict if x['filename'] in new_filenames]:
        old_indexed[(item['filename'], item['hash'])] = item

    chg_items = []
    for item in new_dict:
        if (item['filename'], item['hash']) not in old_indexed and \
                        item['filename'] in old_filenames:
            item['updated_at'] = time.time()
            chg_items.append(item)
    return new_items, chg_items

def send_to_server (ret):
   global old_data
   new_items, changed_items = compare_dicts(old_data, ret)
   chunk_size = 500
   lni = len(new_items)
   lci = len(changed_items)
   if lni >0 or lci > 0:
      # Process server communication in chunks
      for idx in range(0, int(max(lci, lni) / chunk_size) + 1):
         ni_chunk = new_items[idx * chunk_size:idx * chunk_size + chunk_size]
         ci_chunk = changed_items[idx * chunk_size:idx * chunk_size + chunk_size]
         for k, v in enumerate (ni_chunk):
            temp_chunk_filename=v["filename"]
            ni_chunk[k]["filename"]=ntpath.basename(temp_chunk_filename)
         for k, v in enumerate (ci_chunk):
            temp_chunk_filename=v["filename"]
            ci_chunk[k]["filename"]=ntpath.basename(temp_chunk_filename)
         data = {'new': ni_chunk, 'changed': ci_chunk}

         #inform user on the number of hashs sent
         logger.info("Number of digital fingerprints to be sent: %s", (str(len(data['new'])) ))

         token = get_token()
         if token:
            status_code = post_data(data=data, token=token)
            if status_code == 202:
               logger.info('Post to server was successful')
               save_to_db(new_items, changed_items)
               #logger.info("Local DB updated")
            else:
               logger.error('Error on server side.  Trying again ...')
               status_code = post_data(data=data, token=token)
               if status_code == 202:
                  logger.info('2nd try, post to server was successful')
                  save_to_db(new_items, changed_items)
                  #logger.info("Local DB updated")
               else:
                  logger.error('Error on server side. 2nd try failed.')

def process_dirs():
   # process each dir
   global sql_conn
   global old_data
   # Get existing data from DB
   cur = sql_conn.cursor()
   cur.execute('SELECT filename, hash FROM files')
   old_data = [dict(x) for x in cur.fetchall()]
   data = []
   for d in config['directories']:
      data.extend(process_dir(d['dirpath'], d['type']))



def save_to_db(new_items, changed_items):
    # Update date to DB
    global sql_conn
    # Get existing data from DB
    cur = sql_conn.cursor()
    # Inserting new items
    sql_conn.executemany(
        'INSERT OR IGNORE INTO files(filename, size, hash, created_at) '
        'VALUES (:filename, :size, :hash, :created_at)',
        new_items)
    # Updating old items
    sql_conn.executemany(
        'UPDATE files SET hash = :hash, updated_at = :updated_at WHERE filename = :filename',
        changed_items)
    sql_conn.commit()


def refresh_token():
    # refresh token
    try:
        response = s.get(TOKEN_REFRESH_URL,
                         auth=(config['userid'], config['password']),
                         verify=SSL_VERIFY)
    except requests.exceptions.ConnectionError:
        logger.error('Error connecting to the server.')
        #sys.exit(1)

    # If all fine return token
    #logger.info("refresh_token - return code %s", response.status_code)
    if response.status_code == 201:
        logger.info("Successfully renewed token")
        return response.json()['token']
    else:
        return None


def post_data(data, token):
    # Post data to DB
    return_code=0
    try:
        data_json_upload=json.dumps(data)
        zipped = zlib.compress(data_json_upload.encode("utf-8"))
        base64_bytes = base64.b64encode(zipped)
        base64_string = base64_bytes.decode('utf-8')
        json_upload= {'data': base64_string}
        response = s.post(PUSH_URL,
                          headers={'Authorization': 'Bearer %s' % token},
                          json=json_upload,
                          verify=SSL_VERIFY)
        return_code=response.status_code

    except requests.exceptions.ConnectionError:
        logger.error('Error connecting to the server.')
    #logger.info("post_data - return code %s", response.status_code)
    return return_code


def get_token():
    # Get token and if not fresh do token refresh
    try:
       response = s.get(TOKEN_URL,
                         auth=(config['userid'], config['password']),
                         verify=SSL_VERIFY)
       # If all fine return token
       #logger.info("get_token - return code %s", response.status_code)
       if response.status_code == 200:
           return response.json()['token']
       elif response.status_code == 401:
           logger.info("Incorrect userid and/or password.  No digital fingerprint is sent")
           return refresh_token()
       elif response.status_code==0:
           logger.info("Unknown error")
           return None
       else:
           logger.info("Unknown error")
           return None
    except requests.exceptions.ConnectionError:
        logger.error('Error connecting to the server.')
        #sys.exit(1)
        return None


def main():
    # main
    global old_data
    logger.info("Client started")
    #new_items, changed_items = process_dirs()
    process_dirs()



if __name__ == '__main__':
    main()
