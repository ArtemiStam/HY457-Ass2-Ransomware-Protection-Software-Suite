/* HY457 Introduction to Secure Systems
Assignment 2 "Implementation of a Ransomware Protection Software Suite"
Artemisia Stamataki csd4742

-------------------------------------Compilation Instructions------------------------------------
How to compile antivitus:
    $ make all

How to clean .o files and executable(antivirus):
    $ make clean

-------------------------------------Running Instructions----------------------------------------
1. Scanning for Infected Files
Everythings is implemented as the assignment suggests.
How to run:
    $ make scan //scans the test_files directory 


2. Detecting Potential Harmful Network Traffic 
Everythings is implemented as the assignment suggests.
How to run:
    $ make inspect //inspects the test_files directory for harmful network traffic


3. Securing Valuable Files
Everythings is implemented as the assignment suggests.
How to run:
    $ make monitor //monitors the test_files directory for file system events and notifies if events that could be ransomware happen


4. Protecting from Unauthorized Access
Everythings is implemented as the assignment suggests.
How to run split mode:
    $ make slice KEY=key/secret // key/secret is a number

How to run reconstruction mode:
    $ make unock SHARES="number,number number,number ..." // shares must have the number of the persion comma(,) the slice the got for example: $ make unlock SHARES="1,5 2,58 3,24" 


5. Disseminating Findings 
I could find how to run arya with the Hash(openssl) module of YARA so i put comments on those strings and conditions
*/

rule KozaliBear
{
    meta:
        descriptor = "Detects KozaliBear Ransomware"
        author = "Artemisia Stamataki csd4742"
        date = "20-4-2024"
    strings:
        //$MD5_hash = "85578cd4404c6d586cd0ae1b36c98aca"
        //$SHA256_hash = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849"
        $bitcoin_wallet = "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6"
        $virus_signature = { 98 1D 00 00 EC 33 FF FF FB 06 00 00 00 46 0E 10 }
        $malicious_domain1 = "biawwer.com"
        $malicious_domain2 = "alphaxiom.com"
        $non_malicious_domain = "google.com"

    condition:
        $bitcoin_wallet or $virus_signature or $malicious_domain1 or $malicious_domain2 or $non_malicious_domain //or hash.md5(0, filesize) == $MD5_hash or hash.sha256(0, filesize) == $SHA256_hash
}

/* Arya Command: 
$ python3 arya/src/arya.py -i README.md -o test_files/KozaliBearTest.exe */