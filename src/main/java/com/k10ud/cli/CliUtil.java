/*
 * Copyright (c) 2019 David Castañón <antik10ud@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.k10ud.cli;

import com.k10ud.certs.*;
import com.k10ud.certs.util.Base64;
import com.k10ud.certs.util.RelaxedPemReader;

import javax.net.SocketFactory;
import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class CliUtil {


    //TODO: add pkcs11 and pkcs12 and jks, with input passwrd entry callbacks?
    public static byte[] readData(String optionalPEMType, String f) {
        if (f.startsWith("data:")) {
            return readData(optionalPEMType, Base64.decode(f.substring(5)));
        } else if (f.startsWith("tls:")) {
            return readTLScerts(f.substring(4));
        }
        return readData(optionalPEMType, readFile(f));
    }


    public static byte[] readData(String optionalPEMType, byte[] src) {
        if (src == null)
            return null;
        byte[] data = null;
        //fix this file detection,check fisrt bytes!!!
        try {
            try {
                try (RelaxedPemReader r = new RelaxedPemReader(new InputStreamReader(new ByteArrayInputStream(src)))) {
                    data = r.read(optionalPEMType);
                }
            } catch (java.nio.charset.MalformedInputException x) {
                //so, ok
            }

            if (data == null||data.length==0)
                data = src;

            return data;

        } catch (NoSuchFileException x) {
            System.err.println(x.getMessage() + " not found");
            return null;
        } catch (IOException x) {
            System.err.println("io error: " + x.getMessage());
            return null;
        }
    }


    public static byte[] readFile(String url) {
        if (url == null)
            return null;
        if (url.startsWith("https://") || url.startsWith("http://")) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            InputStream is = null;
            HttpURLConnection con = null;
            try {
                URL u = new URL(url);

                con = (HttpURLConnection) u.openConnection();

                con.setDoOutput(true);
                con.setDoInput(true);
                if (con.getResponseCode() == HttpURLConnection.HTTP_SEE_OTHER || con.getResponseCode() == HttpURLConnection.HTTP_MOVED_PERM || con.getResponseCode() == HttpURLConnection.HTTP_MOVED_TEMP) {
                    //warn:loops!
                    return readFile(con.getHeaderField("Location"));

                }
                if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    try (InputStream in = con.getInputStream()) {
                        return IOUtil.readAllBytes(in);
                    }
                } else {
                    System.err.printf("Failed reading %s: %d\n", url, con.getResponseCode());
                }

            } catch (IOException e) {
                System.err.printf("Failed while reading bytes from %s: %s\n", url, e.getMessage());
            } finally {
                if (is != null) {
                    try {
                        is.close();
                    } catch (IOException e) {
                        //...
                    }
                }

                if (con != null)
                    con.disconnect();
            }
        } else {
            try {
                return Files.readAllBytes(Paths.get(url));
            } catch (IOException e) {
                System.err.printf("Failed while reading bytes from %s: %s\n", url, e.getMessage());
                return null;

            }

        }
        return null;
    }

    public static IItemDumper dumper(CommonArgs app) {
        switch (app.format) {
            case csv:
                return new CSVDumper();
            case json:
                return new JSONDumper();
            case keys:
                return new KeyDumper();
            case text:
            default:
                return new ItemDumper(app.colorScheme(), app.textFormatCompactLines, app.showEncodings);

        }

    }

    public static byte[] readCertificate(String s) {
        return CliUtil.readData("CERTIFICATE", s);
    }


    public static byte[] readTSR(String s) {
        return CliUtil.readData("TIMESTAMP RESPONSE", s);
    }

    public static byte[] readTSQ(String s) {
        return CliUtil.readData("TIMESTAMP REQUEST", s);
    }

    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private static final String CONT = "-----\n";


    public static String toPem(String name, byte[] bytes) {

        return BEGIN + name + CONT + Base64.encodeBytes(bytes) + "\n" + END + name + CONT;
    }


    private static byte[] readTLScerts(String surl) {
        String host;
        int port = 443;

        try {
            URL url = new URL(surl);
            host = url.getHost();
            port = url.getPort() == -1 ? 443 : url.getPort();

        } catch (MalformedURLException e) {
            if (surl.contains(":")) {
                String[] parts = surl.split(":");
                host = parts[0];
                try {
                    port = Integer.parseInt(parts[1]);
                } catch (Exception x) {
                    host = surl;
                }
            } else {
                host = surl;
            }
        }


        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };


        try {
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            SocketFactory factory = sc.getSocketFactory();
            SSLSocket socket;

            socket = (SSLSocket) factory.createSocket(host, port);
            socket.startHandshake();
            Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs.length == 0) {
                System.err.println("no certs found");
            } else {
                for (Certificate cert : certs) {
                    if (cert instanceof X509Certificate) {

                        try {
                            return cert.getEncoded();
                        } catch (CertificateEncodingException e) {
                            System.err.println("certificate encoding failed");
                        }
                    }
                }
            }

        } catch (Exception e) {
            System.err.println("error: " + e.getMessage());
        }

        return null;
    }


}
