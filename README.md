# AES-256 Password manager

This script securely encrypts or decrypts passwords and stores them locally on disk within a custom database file, it also features functionality to retrieve passwords from a previously generated database file. This script takes a master password from stdin/from memory. It then hashes the password using the specified hashing algorithm (scrypt, sha256) and finally AES-256 encrypts/decrypts the file's data using the algorithm's hash as the AES-256 key. When providing the 'scrypt' argument to the algorithm parameter the script will generate a custom scrypt salt per each database file edit or creation. The uniquely generated salt is base64 encoded and prepended to each database file's encrypted bytes separated by carriage return line feed bytes (for parsing) as meta-data. When using the change password parameter/-cp the script will write random bytes*WIPE_PASSES to the previous database file, effectively making data recovery/forensics difficult.

# Example usage using scrypt as the hashing algorithm:
  Create a database file:
  ```
  python3 aespasswd_store.py -a scrypt -c <filename>
  ```
  Change master password for a database file:
  ```
  python3 aespasswd_store.py -a scrypt -cp <filename>
  ```
  Edit a database file:
  ```
  python3 aespasswd_store.py -a scrypt -e <filename>
  ````
  Query data from within the database file:
  ```
  python3 aespasswd_store.py -a scrypt -q <filename>
  ```
  
  Examples:
  ```
  # Add entry to the database/modify existing data:
  pass_id1=password
  pass_id2=password
  pass_id3=password
  
  # Delete existing data:
  pass_id1=delete
  pass_id2=delete
  
  # -q parameter: Query data (entering nothing dumps all data):
  pass_id1
  pass_id3
  
  # Press ctrl+D (linux) or ctrl+Z (windows) to save data from stardard input.
  ```
