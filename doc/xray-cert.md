###### Usage
```
$ xray-cert --help
xray-cert 0.0.1
Usage: xray-cert [-h] [--show-encodings] [--show-sourcenames]
                 [--text-format-compact-lines] [--query=<text>] [-c=<mode>]
                 [-f=<format>] SOURCE [SOURCE...]
Dump x509 certificates
      SOURCE                  X509Certificate sources such as pem or der files,
                                URLs, tls:<host>, data:<base64data>
      --query=<text>          Query certificates
                                Default: null
      --show-encodings        Show encodings
      --show-sourcenames      Show sourcenames, default to false
      --text-format-compact-lines
                              Specify output must compact single elements in
                                one line
  -c, --color=<mode>          Show colored output
                              The color parameter is optional (defaults to
                                `auto`)
                              The possible options are:
                               * auto - Only show colors if the platform
                                supports it.
                               * always - Turn on colored output.
                               * never - Turn off colored output.
                                Default: auto
  -f, --format=<format>       Specify output format
                              The format parameter is optional (defaults to
                                `text`)
                              The possible options are:
                               * text - Text output.
                               * json - JSON output.
                               * keys - KV output.
                               * csv - Comma Separated Values output.
                               * der - DER output (i.e. crt, cer)
                               * pem - PEM output.
                                Default: text
  -h, --help                  Displays this help message and quits.
```
###### Sample 1
View Certificate Content
```
$ xray-cert src/test/java/docgen/google.pem
Version: v3
SerialNumber: 315689065623421815864785010228154928589 (hex: 0xed7f80a1379302560800000000190dcd, bits: 136)
Signature: 
    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    params: NULL
Issuer: 
    [0] -> 2.5.4.6 (countryName): US (type: printableString)
    [1] -> 2.5.4.10 (organizationName): Google Trust Services (type: printableString)
    [2] -> 2.5.4.3 (commonName): GTS CA 1O1 (type: printableString)
Subject: 
    [0] -> 2.5.4.6 (countryName): US (type: printableString)
    [1] -> 2.5.4.8 (stateOrProvinceName): California (type: printableString)
    [2] -> 2.5.4.7 (localityName): Mountain View (type: printableString)
    [3] -> 2.5.4.10 (organizationName): Google LLC (type: printableString)
    [4] -> 2.5.4.3 (commonName): www.google.com (type: printableString)
Validity: 
    Duration: 2 months 23 days (synthetic)
    NotBefore: 2019-10-10T20:56:23Z
    NotAfter: 2020-01-02T20:56:23Z
SubjectPublicKeyInfo: 
    Algorithm: 1.2.840.10045.2.1 (ecPublicKey)
    Named curve: 1.2.840.10045.3.1.7 (NIST-P256/secp256r1)
    EC point: 0b:dc:3b:c1
    SHA1: [B@43bd930a (synthetic)
    SHA2-256: [B@553a3d88 (synthetic)
    SHA3-256: [B@74a10858 (synthetic)
Extensions: 
    [0] -> 2.5.29.15 (Key usage, critical) -> 0 (0x0): DigitalSignature
    [1] -> 2.5.29.37 (Extended key usage) -> 1.3.6.1.5.5.7.3.1 (serverAuth)
    [2] -> 2.5.29.19 (Basic constraints, critical) -> None
    [3] -> 2.5.29.14 (Subject key identifier) -> Value: 19:79:86:24:4a:e6:9a:46:af:ac:ec:e4:8e:43:8d:1a:
                                                        60:6e:bc:f4
    [4] -> 2.5.29.35 (Authority key identifier) -> Identifier: 98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:
                                                               7d:09:fd:2b
    [5] -> 1.3.6.1.5.5.7.1.1 (Authority Information Access): 
            AccessDescription[0]: 
                Method: 1.3.6.1.5.5.7.48.1 (ocsp)
                Location -> uniformResourceIdentifier: http://ocsp.pki.goog/gts1o1 (type: IA5String)
            AccessDescription[1]: 
                Method: 1.3.6.1.5.5.7.48.2 (caIssuers)
                Location -> uniformResourceIdentifier: http://pki.goog/gsr2/GTS1O1.crt (type: IA5String)
    [6] -> 2.5.29.17 (Subject alternative name): 
            [0] -> DNSName: www.google.com (type: IA5String)
    [7] -> 2.5.29.32 (Certificate policies): 
            [0] -> 2.23.140.1.2.2 (organization-validated CA/Browser Forum's Baseline Requirements)
            [1] -> 1.3.6.1.4.1.11129.2.5.3 (United States Department of Defense (DoD))
    [8] -> 2.5.29.31 (Revocation List distribution points) -> DistributionPoint[0] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://crl.pki.goog/GTS1O1.crl (type: IA5String)
    [9] -> 1.3.6.1.4.1.11129.2.4.2 (Certificate Transparency Precertificate SCTs): 
            [0]: 
                sct_version: 0 (v1)
                id: b2:1e:05:cc:8b:a2:cd:8a:20:4e:87:66:f9:2b:b9:8a:
                    25:20:67:6b:da:fa:70:e7:b2:49:53:2d:ef:8b:90:5e
                timestamp: 2019-10-10T21:56:23.869Z
                extensions -> none
                digitally-signed: 
                    algorithms: 
                        hash: 4 (sha256)
                        signature: 3 (ecdsa)
                    signature: 00:47:30:45:02:20:67:77:56:d7:0a:c6:3e:0c:8d:cd:
                               7e:3d:38:22:e7:46:f9:e5:c9:12:12:9b:23:97:e3:b9:
                               19:3f:68:51:2d:12:02:21:00:a1:96:ce:5d:2d:5f:42:
                               c2:5e:c6:1f:5b:3f:73:d2:f1:5c:c5:74:04:f9:a0:3d:
                               9b:0e:77:6f:88:ce:63:8f:aa
            [1]: 
                sct_version: 0 (v1)
                id: 5e:a7:73:f9:df:56:c0:e7:b5:36:48:7d:d0:49:e0:32:
                    7a:91:9a:0c:84:a1:12:12:84:18:75:96:81:71:45:58
                timestamp: 2019-10-10T21:56:23.896Z
                extensions -> none
                digitally-signed: 
                    algorithms: 
                        hash: 4 (sha256)
                        signature: 3 (ecdsa)
                    signature: 00:46:30:44:02:20:70:28:b7:34:89:88:26:06:22:97:
                               e6:d0:f1:85:61:c1:17:06:66:ab:d6:8f:9d:06:47:9a:
                               f0:87:77:c5:8d:02:02:20:3b:e0:b6:6b:ac:9c:85:14:
                               74:cd:ba:28:9e:85:e9:51:6c:a0:f8:b0:b2:10:8d:6b:
                               e3:de:ee:c8:3a:49:04:dd
Fingerprints: 
    MD5: [B@a74868d (synthetic)
    SHA1: [B@12c8a2c0 (synthetic)
    SHA2-256: [B@7e0e6aa2 (synthetic)
    SHA3-256: [B@365185bd (synthetic)
Security: 
    CVE-2008-0166 (Openssl predictable random number generator): Unknown (synthetic)
    CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)

```
###### Sample 2
View EIDAS Certificate Content
```
$ xray-cert src/test/java/docgen/eidas.pem
Version: v3
SerialNumber: 79465530382284231527981644753374548139 (hex: 0x3bc88123b3251a22c45f1ea889c010ab, bits: 128)
Signature: 
    algo: 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
    params: NULL
Issuer: 
    [0] -> 2.5.4.6 (countryName): ES (type: printableString)
    [1] -> 2.5.4.7 (localityName): ZARAGOZA (type: printableString)
    [2] -> 2.5.4.10 (organizationName): ESPUBLICO SERVICIOS PARA LA ADMINISTRACION SA (type: printableString)
    [3] -> 2.5.4.11 (organizationalUnitName): AUTORIDAD DE CERTIFICACION ESFIRMA - AAPP (type: printableString)
    [4] -> 2.5.4.5 (serialNumber): A50878842 (type: printableString)
    [5] -> 2.5.4.3 (commonName): ESFIRMA AC AAPP 2 (type: printableString)
Subject: 
    [0] -> 2.5.4.6 (countryName): ES (type: printableString)
    [1] -> 2.5.4.10 (organizationName): PRUEBAS (type: printableString)
    [2] -> 2.5.4.11 (organizationalUnitName): CERTIFICADO ELECTRONICO DE EMPLEADO PUBLICO CON SEUDONIMO (type: printableString)
    [3] -> 2.5.4.97 (organizationIdentifier): VATES-P0200001F (type: printableString)
    [4] -> 2.5.4.65 (pseudonym): 94784686 (type: printableString)
    [5] -> 2.5.4.3 (commonName): SEUDONIMO - 94784686 - PRUEBAS (FIRMA) (type: printableString)
Validity: 
    Duration: 1 year 11 months 30 days (synthetic)
    NotBefore: 2019-06-11T09:34:57Z
    NotAfter: 2021-06-10T09:34:57Z
SubjectPublicKeyInfo: 
    Algorithm: 1.2.840.113549.1.1.1 (RSA)
    modulus: 00:94:6a:d5:57:81:23:ab:79:a3:dd:b5:e2:a1:af:76:
             c5:fe:54:4f:7d:e5:69:03:64:42:88:4f:93:a1:b7:f0:
             6c:f9:dd:ee:54:83:f4:8c:15:ac:2f:8f:fb:72:f0:b6:
             aa:6b:4b:19:d7:20:20:af:c1:ef:31:00:46:91:e7:c1:
             ea:d2:9b:da:5f:40:9d:87:e8:9c:8e:2c:8c:51:82:cf:
             d4:4a:80:e5:80:5c:05:2c:48:34:29:22:61:46:0f:f2:
             35:88:bf:e9:7f:a8:44:3a:38:cf:60:01:e9:28:36:bf:
             1a:e2:61:f1:63:73:3f:27:a4:f6:52:e6:43:63:4b:85:
             67:1e:c0:62:88:5f:5e:80:95:34:8e:02:57:3c:3c:e4:
             d8:68:ce:2a:a5:46:83:d9:26:56:a0:e1:b9:a3:2b:16:
             f2:61:02:02:07:fd:f8:2d:64:fc:ba:28:39:3e:d9:4e:
             28:35:28:64:ba:60:84:c1:0f:07:84:ad:64:f9:7b:18:
             68:6e:22:44:9e:18:a6:e9:53:df:8b:05:7f:18:45:27:
             42:25:0a:b9:3b:f6:e3:a5:6a:91:9e:e0:0e:82:2c:3d:
             9a:1b:0c:1f:37:ca:03:db:40:ff:d3:e9:bf:6c:af:6b:
             f7:32:3c:36:63:cd:cf:b2:e1:72:67:cb:38:7d:e2:9e:
             0d
    publicExponent: 01:00:01
    Key length: 2048 (0x800)
    SHA1: [B@401e7803 (synthetic)
    SHA2-256: [B@10dba097 (synthetic)
    SHA3-256: [B@1786f9d5 (synthetic)
Extensions: 
    [0] -> 2.5.29.32 (Certificate policies): 
            [0] -> 2.16.724.1.3.5.4.1 (CERTIFICADO ELECTRONICO DE EMPLEADO PUBLICO CON SEUDONIMO (Nivel Alto))
            [1] -> 0.4.0.194112.1.2 (Qcp-natural-qscd)
            [2] -> 1.3.6.1.4.1.47281.1.3.1 (esFIRMA DPC Empleado Público con Seudónimo - ALTO en DSCF-tarjeta FIRMA): 
                    [0] -> 1.3.6.1.5.5.7.2.1 (CPS) -> URI: https://www.esfirma.com/doc-pki/ (type: IA5String)
                    [1] -> 1.3.6.1.5.5.7.2.2 (User Notice) -> ExplicitText: Certificado cualificado de firma electrónica de empleado público con seudónimo nivel alto. Consulte https://www.esfirma.com/doc-pki/ (type: utf8String)
    [1] -> 2.5.29.14 (Subject key identifier) -> Value: 27:af:9d:1d:26:e9:a0:b8:f0:5d:34:9e:87:9e:99:c0:
                                                        12:1b:e3:ee
    [2] -> 2.5.29.35 (Authority key identifier) -> Identifier: f6:40:ef:c3:a7:2b:4d:e5:bf:31:e9:fa:ee:c3:79:79:
                                                               1f:2a:03:58
    [3] -> 2.5.29.19 (Basic constraints) -> None
    [4] -> 2.5.29.15 (Key usage, critical) -> 1 (0x1): ContentCommitment
    [5] -> 2.5.29.31 (Revocation List distribution points): 
            DistributionPoint[0] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://crls1.esfirma.com/acaapp/acaapp2.crl (type: IA5String)
            DistributionPoint[1] -> Name -> FullName -> [0] -> uniformResourceIdentifier: http://crls2.esfirma.com/acaapp/acaapp2.crl (type: IA5String)
    [6] -> 1.3.6.1.5.5.7.1.1 (Authority Information Access): 
            AccessDescription[0]: 
                Method: 1.3.6.1.5.5.7.48.1 (ocsp)
                Location -> uniformResourceIdentifier: http://ocsp1.esfirma.com/acaapp2/ (type: IA5String)
            AccessDescription[1]: 
                Method: 1.3.6.1.5.5.7.48.1 (ocsp)
                Location -> uniformResourceIdentifier: http://ocsp2.esfirma.com/acaapp2/ (type: IA5String)
            AccessDescription[2]: 
                Method: 1.3.6.1.5.5.7.48.2 (caIssuers)
                Location -> uniformResourceIdentifier: http://www.esfirma.com/doc-pki/acaapp2.crt (type: IA5String)
    [7] -> 2.5.29.17 (Subject alternative name): 
            [0] -> rfc822Name: nombre_apellidos@pruebas.esfirma.com (type: IA5String)
            [1] -> directoryName: 
                    [0] -> 2.16.724.1.3.5.4.1.1 (CEEPS Alto, Tipo de certificado): CERTIFICADO CUALIFICADO DE FIRMA ELECTRONICA DE EMPLEADO PUBLICO CON SEUDONIMO DE NIVEL ALTO (type: utf8String)
                    [1] -> 2.16.724.1.3.5.4.1.2 (CEEPS Alto, Nombre de la entidad suscriptora): PRUEBAS (type: utf8String)
                    [2] -> 2.16.724.1.3.5.4.1.3 (CEEPS Alto, NIF entidad suscriptora): P0200001F (type: utf8String)
                    [3] -> 2.16.724.1.3.5.4.1.9 (CEEPS Alto, Correo electrónico del firmante): nombre_apellidos@pruebas.esfirma.com (type: IA5String)
                    [4] -> 2.16.724.1.3.5.4.1.12 (CEEPS Alto, Seudónimo): 94784686 (type: utf8String)
    [8] -> 1.3.6.1.5.5.7.1.3 (QcStatements): 
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
Fingerprints: 
    MD5: [B@78186a70 (synthetic)
    SHA1: [B@306279ee (synthetic)
    SHA2-256: [B@545997b1 (synthetic)
    SHA3-256: [B@4cf4d528 (synthetic)
Security: 
    CVE-2008-0166 (Openssl predictable random number generator): NotAffected (synthetic)
    CVE-2017-15361 (ROCA: Vulnerable RSA generation): NotAffected (synthetic)

```
###### Sample 3
Query certificate elements using the x509 Query Language. You can also use multiple certs to do a certificate filtered search
```
$ xray-cert --query MATCH Extensions/**/$qcType:=0.4.0.1862.1.6 RETURN $qcType src/test/java/docgen/eidas.pem
qcType -> 0.4.0.1862.1.6.1 (esign)

```
