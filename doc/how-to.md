###### View Certificate QCStatements
```
$ xray-cert --query MATCH Extensions/**/1.3.6.1.5.5.7.1.3 src/test/java/docgen/eidas.pem
/Extensions/[8]/1.3.6.1.5.5.7.1.3 ([desc=QcStatements]): 
    [0] -> 0.4.0.1862.1.1 (QcCompliance)
    [1] -> 0.4.0.1862.1.4 (QcSSCD)
    [2] -> 0.4.0.1862.1.6 (QcType) -> 0.4.0.1862.1.6.1 (esign)
    [3] -> 0.4.0.1862.1.3 (QcRetentionPeriod) -> Years: 15 (0xf)
    [4] -> 0.4.0.1862.1.5 (QcPDS): 
            Location[0]: 
                lang: en (type: PrintableString)
                url: https://www.esfirma.com/doc-pki/PDS2/ES2-ALTO-SMARTCARD-EN/ (type: IA5String)
            Location[1]: 
                lang: es (type: PrintableString)
                url: https://www.esfirma.com/doc-pki/PDS2/ES2-ALTO-SMARTCARD-ES/ (type: IA5String)
    [5] -> 1.3.6.1.5.5.7.11.2 (id-qcs-pkixQCSyntax-v2) -> keyIdentifier: 0.4.0.194121.1.2 (Id-etsi-qcs-SemanticsId-Legal)
    [6] -> 1.3.6.1.5.5.7.11.2 (id-qcs-pkixQCSyntax-v2) -> keyIdentifier: 0.4.0.194121.1.1 (Id-etsi-qcs-SemanticsId-Natural)

```
NOTE: you can view the section without the query arg, but you must find the section yourself
###### Check If Certificate is affected by CVE-2008-0166 (Openssl predictable random number generator) or CVE-2017-15361 (ROCA)
```
$ xray-cert --query MATCH Security src/test/java/docgen/eidas.pem
/Security: 
    CVE-2008-0166 (Openssl predictable random number generator): NotAffected (synthetic)
    CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)

```
NOTE: you can view the section without the query arg, but you must find the section yourself
###### Search Serial Numbers Of All Certificates
```
$ xray-cert --query MATCH $sn:=SerialNumber RETURN $sn{} @src/test/java/docgen/allcerts.list
sn: 29678605170626207038353124618

sn: 600000000

sn: 976

sn: 14687230137476495499685885963567393969

sn: 1361

sn: 920

sn: 889

sn: 773696552

sn: 103572795170259082775702975230952369063

sn: 5052939008007111506

```
And If I want the hex number and the CN in CSV:
```
$ xray-cert -f csv --query MATCH $sn:=SerialNumber, Subject/*/$cn:=2.5.4.3 RETURN $sn{hex}, $cn{} @src/test/java/docgen/allcerts.list
0x5fe5911a1ddb0026c36b2d0a,Qualified e-Szigno TSA 2015 03
0x23c34600,B-Trust Qualified OCSP Authority
0x3d0,CA Signtrust 7:PN
0xb0ca85a954118aebcad510a22286cb1,ADACOM Qualified Certificate Services CA
0x551,D-Trust.HBA-qCA 1:PN
0x398,AuthentiDate TSA for Healthcare IT Solutions C055 1:PN
0x379,D-TRUST akkr 2012 CA 5 1:PN
0x2e1dac28,TSU4
0x4deb650f44bc2ca44ae5f89940cc6ba7,ALFATRUST ROOT CA
0x461fa54193fa8352,HRIDCA
```
NOTE: Query interface if a highly experimental feature
