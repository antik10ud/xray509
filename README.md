X-RAY 509
===

###Warnig

DO NOT USE THIS PROJECT IN PRODUCTION 
IT IS AN UNFINISHED WORK AND SUBJECT 
TO CHANGES THAT ARE NOT BACKWARD COMPATIBLE

###Intro

This is a quick & dirty work done in my free time that began primarily 
to learn and as a need for a tool to visualize the contents of an 
X509 certificate in a simple, complete and detailed way.

It is only a toy but after all t is a tool that has turned out to be very 
useful in the day-to-day work and that's he main reason why I publish this code.

I also hope to get feedback and discuss many aspects of the certificates 
technical aspects and PKI in general. This will allow to improve the tool.
It can be very rewarding and fun.

Who knows, maybe one day it will even be a useful tool.

###Tools

The following tools are currently provided:
* [XRAY-Cert] (doc / xray-cert.md)  View and query certificates
* [XRAY-OCSP] (doc / xray-ocsp.md) Check the online status of a certificate
* [XRAY-CRL] (doc / xray-crl.md) View certificates revocation lists
* [XRAY-TS] (doc / xray-ts.md) Generation of time stamps
* [XRAY-TS-Check] (doc / xray-ts-chk.md) Time stamp verification

This is a small demonstration of the xray-cert command:


###Example

![Example](doc/term.svg)

## Requirements
Java 1.8

## Compile, Test & Package
    $ mvn package
				
## License
MIT License


