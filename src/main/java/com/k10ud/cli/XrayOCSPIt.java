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

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.CertificateProc;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.Base64;
import com.k10ud.help.QueryableMap;
import com.k10ud.ocsp.OCSPHelper;
import com.k10ud.ocsp.OCSPReqProc;
import com.k10ud.ocsp.OCSPResProc;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.types.BerBoolean;
import org.openmuc.jasn1.ber.types.BerObjectIdentifier;
import org.openmuc.jasn1.ber.types.BerOctetString;
import org.openmuc.jasn1.ber.types.string.BerIA5String;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import static picocli.CommandLine.*;


public class XrayOCSPIt {

    public static class Args extends CommonArgs {

        @Option(names = {"-o", "--output-filename-base"}, description = "OCSP file output base (it'll generate .ors and .orq files if specified)")
        public String outputFileBase;


        @Option(names = {"--requestor-name"}, description = "Requestor name")
        public String requestorName;


        @Option(names = {"--ocsp-server"}, description = "OCSP Server URL, we'll try to take it from certificate AIA when not specified")
        // xN
        public String ocspServer;


        @Option(names = {"-a", "--algo"}, description = "CertId hash algo")
        public SupportedDigest hashAlgo = SupportedDigest.SHA1; //RFC 2560 - OCSP responders SHALL support the SHA1 hashing algorithm

        @Option(names = {"--issuer-cert"}, description = "Issuer certificate, we'll try to obtain it from AIA when not specified")
        public String issuerCert;


        @Option(names = {"--dump-checked-cert"}, description = "Dump checked certificate")
        public boolean dumpChekedCert = false;

        @Option(names = {"--dump-checked-issuer-cert"}, description = "Dump checked issuer certificate")
        public boolean dumpChekedIssuerCert = false;


        @Option(names = {"--nonce"}, description = "Use OCSP nonce extension")
        public boolean nonce = false;

        @Option(names = {"--use-get"}, description = "Use OCSP GET request")
        public boolean useGet;


        @Option(names = {"--cert"}, description = "Issuer certificate, we'll try to obtain it from AIA when not specified")
        public String cert;

        @Option(names = {"--serial"}, description = "Serial of certificate to check")
        public String serial;


  /*      @Parameters(arity = "1", paramLabel = "<cert>", description = "Certificates to check")
        public String cert;
*/

        @Option(names = {"--all"}, description = "Process all available OCSPs in source certificate")
        public boolean processAll;
    }

    public static Args run(String[] args) throws IOException {
        Args app;
        try {
            app = populateCommand(new Args(), args);
        } catch (Exception x) {
            throw new IOException(x);
        }
        return app;
    }

    public static Item run(Args app) throws IOException {
        Item run = new Item();
        Context context = app.context != null ? app.context : new Context(() -> null);
        {
            OCSPRequest ocspRcreq = new OCSPRequest();
            OCSPTBSRequest req = new OCSPTBSRequest();
            ocspRcreq.tbsRequest = req;

            req.version = new OCSPVersion(0);
            if (app.requestorName != null) {
                GeneralName gn = new GeneralName();
                gn.rfc822Name = new BerIA5String(app.requestorName.getBytes());//!!!
                req.requestorName = gn;
            }

            OCSPTBSRequest.RequestList list = new OCSPTBSRequest.RequestList();

            //  IItemDumper dumper = CliUtil.dumper(app);

            req.requestList = list;
            CertID certId = new CertID();
            ArrayList<String> certOcspServers = new ArrayList<>();
            if (app.ocspServer != null)
                certOcspServers.add(app.ocspServer);

            String location = app.issuerCert;
            String serialNumber = app.serial;


            if (app.cert != null && app.serial != null) {
                throw new UnmatchedArgumentException("Cannot use cert and serial parameter at the same time");

            }
            if (app.cert == null && app.serial == null) {
                throw new UnmatchedArgumentException("Must use cert or serial");

            }


            if (app.cert != null) {
                byte[] data = CliUtil.readCertificate(app.cert);

                if (data == null)
                    throw new UnmatchedArgumentException("Cannot obtain certificate from location " + app.cert);


                Item items = new CertificateProc(context).parse(data);//.prop("@encoded", data);

                if (app.dumpChekedCert) {
                    run.prop("Certificate to check", items);
                }

                QueryableMap map = new QueryableMap(items);

                if (certOcspServers.size() == 0) {

                    List<String> ocspsEntries = map.q("(Extensions/1.3.6.1.5.5.7.1.1[*]/AccessDescription[*])/Method=1.3.6.1.5.5.7.48.1");
                    List<String> ocsps = map.v("*/Location/uri", ocspsEntries);
                    for (String i : ocsps) {
                        //  if (ocsps.size() > 0) {
                        //    certOcspServer = ocsps.get(0)
                        certOcspServers.add(i);
                        run.prop("ocsp server location from certificate AIA", i);
                        //  System.out.println(dumper.toString(new Item("ocsp server location from certificate AIA: ", i)));
                        if (!app.processAll)
                            break;
                    }

                }


                if (location == null) {
                    List<String> caIssuers = map.q("(Extensions/1.3.6.1.5.5.7.1.1[*]/AccessDescription[*])/Method=1.3.6.1.5.5.7.48.2");
                    List<String> locations = map.v("*/Location/uri", caIssuers);
                    if (locations.size() > 0) {
                        location = locations.get(0);
                        run.prop("caIssuers location from certificate AIA " + (locations.size() > 1 ? "(first entry)" : ""), location);
                        // System.out.println(dumper.toString(new Item("caIssuers location from certificate AIA (first entry)", location)));
                    }
                }

                if (location == null) {
                    //obtain issuer from (Authority key identifier) 2.5.29.35
                    List<String> aki = map.q("Extensions/2.5.29.35[*]/Identifier=(*)");
                    if (aki.size() > 0) {
                        byte[] kvs = context.trustedListInfoByAKI(aki.get(0));
                        if (kvs != null) {
                            location = "data:" + Base64.encodeBytes(kvs);
                        }
                    }
                }


                serialNumber = String.valueOf(map.k("SerialNumber"));
            }

            if (location == null)
                throw new UnmatchedArgumentException("Cannot obtain issuer certificate location from certificate nor parameters");


            {
                byte[] issuerData = CliUtil.readCertificate(location);

                if (issuerData == null)
                    throw new UnmatchedArgumentException("Cannot obtain issuer certificate from location " + location);

                Item issuerItems = new CertificateProc(context).parse(issuerData);//.prop("@encoded", issuerData);


                if (app.dumpChekedIssuerCert) {
                    run.prop("Issuer Certificate", issuerItems);
                    //  System.out.println(dumper.toString(new Item("Issuer Certificate", items)));
                }

                QueryableMap issuerMap = new QueryableMap(issuerItems);


                byte[] issuerPublicKey = issuerMap.encodedImplicit(issuerData, "SubjectPublicKeyInfo/PublicKey");
          /*      System.out.println( "O:"+ASN1Helper.bytesToHex(issuerPublicKey,""));

                issuerPublicKey = (byte[]) issuerMap.k("SubjectPublicKeyInfo/@encoded");
*/
                 if (issuerPublicKey == null) {
                    throw new RuntimeException("cannot extract SubjectPublicKeyInfo");
                }
  //              System.out.println( "O:"+ASN1Helper.bytesToHex(issuerPublicKey,""));

                /*{
                    SubjectPublicKeyInfo xy=new SubjectPublicKeyInfo();
                    xy.decode(0,issuerPublicKey,false);
                    issuerPublicKey=xy.encoded();
                    System.out.println( "O:"+ASN1Helper.bytesToHex(issuerPublicKey,""));


                }*/


                byte[] issuerSubject = issuerMap.encoded(issuerData, "Subject");
                if (issuerSubject == null) {
                    throw new RuntimeException("cannot extract Subject");
                }

//                String hash = app.hashAlgo"SHA-256";//app.hash todo
                certId.hashAlgorithm = app.hashAlgo.getAlgorithmIdentifier();
                certId.issuerNameHash = new BerOctetString(ASN1Helper.hash(app.hashAlgo.getJalg(), issuerSubject));
                certId.issuerKeyHash = new BerOctetString(ASN1Helper.hash(app.hashAlgo.getJalg(), issuerPublicKey));
                try {
                    certId.serialNumber = new CertificateSerialNumber(serialNumber.toLowerCase().startsWith("0x") ? new BigInteger(serialNumber.substring(2), 16) : new BigInteger(serialNumber));
                } catch ( Exception x) {
                    throw new RuntimeException("Invalid serial number " + serialNumber);
                }
            }


            if (certOcspServers.size() == 0) {
                run.prop("error", "Cannot obtain OCSP server from certificate nor parameters");
                return run;
                //  throw new UnmatchedArgumentException("Cannot obtain OCSP server from certificate nor parameters");
            }

            Item res = new Item();
            for (String certOcspServer : certOcspServers) {
                Item ires;
                if (certOcspServers.size() > 1) {
                    ires = new Item();
                    res.prop(certOcspServer, ires);
                } else {
                    ires = res;
                }

                Extensions sre = null;
                if (app.nonce) {
                    Extension e = new Extension();
                    {
                        e.extnID = new BerObjectIdentifier(ASN1Helper.intArray("1.3.6.1.5.5.7.48.1.2"));
                        e.critical = new BerBoolean(true);
                        byte[] rnd = new byte[6];
                        new Random().nextBytes(rnd);
                        e.extnValue = new BerOctetString(rnd);


                    }
                    sre = new Extensions();
                    req.requestExtensions = sre;
                    sre.seqOf.add(e);
                }
                {
                    list.seqOf.add(new OCSPCertRequest(certId, sre));

                }
                BerByteArrayOutputStream baos = new BerByteArrayOutputStream(8192);

                ocspRcreq.encode(baos, true);


                byte[] query = baos.getArray();

                if (app.outputFileBase != null) {
                    Files.write(Paths.get(app.outputFileBase + ".ors"), query);
                }


                ires.prop("OCSPRequest", new OCSPReqProc(context).parse(query));

                HTTPItem.SendResponse response;
                if (app.useGet) {
                    String url =
                            OCSPHelper.forGet(
                                    certOcspServer, query);
                    response = HTTPItem.sendGet(url);
                } else {
                    response = HTTPItem.send(certOcspServer, query, "application/ocsp-request");
                }
                ires.prop("response", response.item);


                if (response.response != null) {
                    if (app.outputFileBase != null) {
                        Files.write(Paths.get(app.outputFileBase + ".orq"), query);
                    }
                    ires.prop("OCSPResponse", new OCSPResProc(context).parse(response.response));
                }
            }
            run.prop("ops", res);
            //  System.out.println(dumper.toString(res));
        }
        return run;
    }


}



