# Crypture
Crypture is a utility for storing sensitive data on Windows using certificates.  It can be used for everything from passwords to sensitive personal information that you aren’t comfortable storing as plaintext on storage device.
## Prerequisites
* Microsoft Windows 7 or Later
* Microsoft .NET Framework 4.6.1 or Later
## The Basics
Crypture uses encryption to securely store textual data in a lightweight database.  Crypture encrypts data using a randomly generated symmetric Advanced Encryption Standard (AES) 256-bit encryption key.  The AES encryption key is then encrypted with an RSA public key stored on a selected certificate.  The RSA-encrypted AES key and the AES-encrypted data is then stored in an SQL Lite database for later retrieval.  
  
When the user wishes to retrieve the data, Crypture will use the RSA private key to decrypt the AES key.  If the RSA private key is stored on a hardware token, the user will be prompted to enter their PIN to decrypt the AES key.  The AES key is then used to decrypt the stored data.
Crypture can also be used to share data between users by storing the Crypture database on a network share and allowing the user to select multiple certificate (and their associated RSA public keys) to encrypt the AES key.  This can be useful in an organization where you might have sensitive information (e.g., safe combinations, infrequently used passwords) that might be want to be shared between users.

Both Crypture and any databases it creates are portable.
## Getting Started
### Creating A New Database
* Open Crypture
* Click on the ‘New’ icon on the ‘Home’ ribbon tab.
* Choose a location on a local, network, or removable drive.
### Publishing Your Certificate
* Click on the ‘Certificates’ ribbon tab. 
* Click on the ‘Store’ button to load your certificate from the personal certificate store.
* When prompted, confirm that the selected certificate is yours and you own the private key for it.  
* If sharing data, have any other users repeat these steps on the same database for their certificates.
### Creating & Encrypting A New Item
* Click on the ‘Add New Item’ icon on the ‘Home’ tab.
    * The Item Viewer dialog will launch.
* Populate the ‘Item Label’ field with a topical description of the item.
    * This data is used to distinguish the item from other items; it is not encrypted.
* Populate the ‘Protected Item’ text block with the data you which to encrypt and store.
* Use the ‘Share With...’ button to select any other user you wish to encrypt the data for.
    * Any certificates that you own are automatically added to the list. 
* Click the ‘Encrypt & Save’ button to encrypt and save the data.
### Opening An Existing Item
* Double-click on the item you wish to open.
    * The Item Viewer dialog will launch.
* Click the ‘Open & Decrypt’ button on the ribbon tab.
    * You will be prompted to enter a PIN or password if the certificate requires it to utilize the private key.
### Other Notes
* Crypture uses the Windows cryptography subsystem to perform encryption and decryption operations.  If FIPS Compliance is enforced by local or group policy, Crypture will ensure only FIPS Complaint algorithms are used for RSA encryption and decryption.  AES 256-bit algorithms are FIPS compliant. 


