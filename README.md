# DiSE

Firstly, install all the libraries:
Pip install Crypto
pip install lagrange
pip install salsa20

After installing the required libraries, the adaptive DiSE can be run in 3 cases by whatever version of Python you are using:
Case 1: The following instruction will run the adaptive DiSE and demonstrate that the same party j plays the role of encryptor and decryptor. Moreover, contacted parties in encryption and decryption stay the same. Run case 1 as follows:
python DiSE/case1.py
Case 2: The following instruction will run the adaptive DiSE and demonstrate that the same party j plays the role of encryptor and decryptor. Moreover, contacted parties in encryption and decryption are different. Run case 2 as follows:
python DiSE/case2.py
Case 3: The following instruction will run the adaptive DiSE and demonstrate that the different party j and j’ plays the role of encryptor and decryptor, respectively. With contacted parties in encryption and decryption stay the same. Run case 3 as follows:
python DiSE/case3.py
