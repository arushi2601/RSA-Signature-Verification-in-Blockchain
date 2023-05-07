# RSA-Signature-Verification-in-Blockchain
A verification procedure to identify the validity of RSA signatures on medical data or Electronic Health Records created to secure the transaction of public keys of both patients and medical authorities.
This code demonstrates the creation of transaction data using SHA-256 encryption which is further mined to a block using RSA signatures. Finally, through the PKCS1 verification procedure, the validity of the patient's and medical authority's keys is authenticated to further add the block to the blockchain.
It was written in Python 2.7 and utilizes the "pycrypto" library for RSA and SHA256 encryption and hashing algorithms, including signature generation and verification.
To install pycrypto, ensure that python pip is installed and then type:
"pip install pycrypto"
