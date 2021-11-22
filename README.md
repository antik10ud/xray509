X-RAY 509
===

## Warning

DO NOT USE THIS PROJECT IN PRODUCTION 
IT IS AN UNFINISHED WORK AND SUBJECT 
TO CHANGES THAT ARE NOT BACKWARD COMPATIBLE

## Intro

This is a quick & dirty work done in my free time that began primarily 
to learn and as a need for a tool to visualize the contents of an 
X509 certificate in a simple, complete and detailed way.

It is only a toy but after all t is a tool that has turned out to be very 
useful in the day-to-day work and that's he main reason why I publish this code.

I also hope to get feedback and discuss many aspects of the certificates 
technical aspects and PKI in general. This will allow to improve the tool.
It can be very rewarding and fun.

Who knows, maybe one day it will even be a useful tool.

## Tools

The following tools are currently provided but in progress:
* [XRAY-Cert](doc/xray-cert.md)  View and query certificates
* [XRAY-OCSP](doc/xray-ocsp.md) Check the online status of a certificate
* [XRAY-OSQ](doc/xray-osq.md) Dump RFC 6960 OCSP Request
* [XRAY-CRL](doc/xray-crl.md) View certificate revocation lists
* [XRAY-TS](doc/xray-ts.md) Generation of time stamps
* [XRAY-TSR](doc/xray-tsr.md) Dump RFC 3161 Timestamp Response
* [XRAY-TSQ](doc/xray-tsq.md) Dump RFC 3161 Timestamp Query
* [XRAY-TS-Check](doc/xray-ts-chk.md) Time stamp verification


## How To

[How To](doc/how-to.md) do weird things with xray

## Requirements
Java >= 1.8

## Compile, Test & Package
```
    $ mvn clean package
```
  
## Install
```
   $ chmod +x target/appassembler/bin/*
   $ export PATH=target/appassembler/bin:$PATH	
```

## Usage
```
   $ xray-cert --help
```

## More Info

* [Slides](doc/20191108-slides-imaginecode/pdf/presentation.pdf) de la charla de presentación de las herramientas en el [ImagineCode 2019](http://imaginecode.org/) 

* [Artículo](https://espublicogestiona.com/el-registro-descentralizado-de-certificados-digitales-revocados/) El registro descentralizado de certificados digitales revocados. Una introducción práctica a la infraestructura web de clave pública y los contratos inteligentes con la excusa de mejorar la consulta del estado de revocación de un certificado digital.
  	
## License
MIT License


