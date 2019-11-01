NO USES ESTE PROYECTO EN PRODUCCIÓN - ES UN TRABAJO NO ACABADO Y SUJETO A CAMBIOS QUE NO SON COMPATIBLES HACIA ATRÁS


Este es un trabajo quick&dirty realizado en mi poco tiempo libre que empezó fundamentalmente para aprender y como necesidad de una herramienta para poder visualizar el contenido de un certificado X509 de forma sencilla y detallada.
Es un juguete pero pese a todo es una herramienta que ha resultado ser muy util en el trabajo del día a día y creo que es la razón principal por la cual publico este código.
Además espero obtener feedback y discutir sobre muchos aspectos de los certificados y PKI en generar. Esto permitirá mejorar la herramienta poco a poco, lo que puede ser muy gratificante y sobre todo divertido.
Quién sabe, quizá algún día hasta sea una herramienta útil.


En estos momentos se proporcionan las siguientes herramientas:
* [XRAY-Cert](doc/xray-cert.md) Para la visualización y consulta de certificados
* [XRAY-OCSP](doc/xray-ocsp.md) Para la consulta del estado de los certificados Online
* [XRAY-CRL](doc/xray-crl.md) Para la consulta del estado de los certificados con listas
* [XRAY-TS](doc/xray-ts.md) Para la generación de sellos de tiempo
* [XRAY-TS-Check](doc/xray-ts-chk.md) Para la verificación de sellos de tiempo

Esta es una pequeña demostración del comando xray-cert:

![Example](term.svg)


