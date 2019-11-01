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

import com.k10ud.asn1.x509_certificate.MessageImprint;
import com.k10ud.asn1.x509_certificate.TSAPolicyId;
import com.k10ud.asn1.x509_certificate.TimeStampReq;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.timestamps.ItemChecker;
import com.k10ud.timestamps.TimeStampReqProc;
import com.k10ud.timestamps.TimeStampRespProc;
import com.k10ud.timestamps.TimeStampRespVfer;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.types.BerBoolean;
import org.openmuc.jasn1.ber.types.BerInteger;
import org.openmuc.jasn1.ber.types.BerOctetString;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;

import static com.k10ud.certs.util.ASN1Helper.*;
import static picocli.CommandLine.*;


public class XrayTimestampIt {


    @Command(name = "xray-ts",
            header = "xray-ts 0.0.1",
            showDefaultValues = true,
            description = "Analyze a RFC 3161 Timestamp"
    )
    public static class Args extends CommonArgs {

        @Option(names = {"-o", "--output-filename-base"}, description = "Timestamp file output base (it'll generate .tsr and .tsq files if specified)")
        public String outputFileBase;

        @Option(names = {"-F", "--source-file"}, description = "Input file to hash")
        public String inputFile;

        @Option(names = {"-E", "--source-text"}, description = "Input text to hash")
        public String inputText;

        @Option(names = {"-i", "--imprint"}, description = "Hexadecimal value as message imprint")
        public String messageImprint;
        @Option(names = {"-a", "--algo"}, description = "Message imprint hash algo")
        public SupportedDigest hashAlgo = SupportedDigest.SHA2_256;

        @Option(names = {"-C", "--cert-path"}, description = "Require certificates")
        public boolean certReq;

        @Option(names = {"-p", "--policy"}, description = "Request policy")
        public String reqPolicy;

        @Option(names = {"-n", "--nonce"}, description = "Long value as nonce (64 bit)")
        public String nonce;

        @Option(names = {"-N", "--nonce-random"}, description = "Use random nonce")
        public boolean randomNonce = true;

        @Option(names = {"-X", "--allow-invalid-imprint-len"}, description = "Allow invalid imprint hash len for algo")
        public boolean allowInvalidImprintLen = false;
/*
        @Option(names = {"-T", "--tsa"}, description = "TSA URL")
        private String tsa;*/

        @Parameters(arity = "1", paramLabel = "<tsa>", description = "TimeStamp Server Authority URL")
        public String tsa;

        @Option(names = {"--check-profile"}, description = "Check response against specified profile")
        public XrayTimestampCheck.TSCheckProfiles checkProfile;

        @Option(names = {"--dump"}, description = "Dump provided timestamp issuer cert")
        public boolean dump;

    }


    public static XrayTimestampIt.Args run(String[] args) throws IOException {
        XrayTimestampIt.Args app;
        try {
            app = populateCommand(new XrayTimestampIt.Args(), args);
        } catch (Exception x) {
            throw new IOException(x);
        }
        return app;
    }

    public static Item run(XrayTimestampIt.Args app) throws IOException {
        Item run = new Item();
        Context context = app.context != null ? app.context : new Context(() -> null);
        TimeStampReq req = new TimeStampReq();
        req.version = new BerInteger(1);
        byte[] data = null;


        if (app.inputFile != null) {
            data = Files.readAllBytes(Paths.get(app.inputFile));
        } else if (app.inputText != null) {
            data = app.inputText.getBytes();
        } else {
            data = "test".getBytes();
        }

        if (app.outputFileBase != null) {
            Files.write(Paths.get(app.outputFileBase + ".dat"), data);
        }


        byte[] mi;
        if (app.messageImprint != null) {
            mi = hexToBytes(app.messageImprint);
        } else {
            mi = hash(app.hashAlgo.getSalg(), data);
        }


        MessageImprint msgImp = new MessageImprint();
        msgImp.hashAlgorithm = app.hashAlgo.getAlgorithmIdentifier();
        msgImp.hashedMessage = new BerOctetString(mi);

        {
            byte x[] = hash(app.hashAlgo.getSalg(), new byte[1]);
            if (x.length != mi.length && !app.allowInvalidImprintLen)
                throw new IllegalArgumentException("Invalid hash size for specified algo");
        }


        req.messageImprint = msgImp;

        Long nonce = null;
        if (app.nonce != null) {
            nonce = Long.parseLong(app.nonce);
        } else if (app.randomNonce) {
            nonce = new SecureRandom().nextLong();
        }
        if (nonce != null)
            req.nonce = new BerInteger(nonce);


        TSAPolicyId policyId = null;
        if (app.reqPolicy != null&&app.reqPolicy.length()>0) {
            policyId = new TSAPolicyId();
            policyId.value = intArray(app.reqPolicy);
        }

        req.reqPolicy = policyId;

        if (app.certReq)
            req.certReq = new BerBoolean(app.certReq);

        BerByteArrayOutputStream baos = new BerByteArrayOutputStream(8192);

        req.encode(baos, true);
        byte[] query = baos.getArray();

        if (app.outputFileBase != null) {
            Files.write(Paths.get(app.outputFileBase + ".tsq"), query);
        }

        run.prop("TimeStampReq", new TimeStampReqProc(context).parse(0,query));


        if (app.tsa != null) {


            HTTPItem.SendResponse response = HTTPItem.send(app.tsa, query, "application/timestamp-query");


            run.prop("response", response.item);


            if (response.response != null) {
                if (app.outputFileBase != null) {
                    Files.write(Paths.get(app.outputFileBase + ".tsr"), response.response);
                }

                run.prop("TimeStampResp", new TimeStampRespProc(context).parse(0,response.response));


                if (app.checkProfile != null) {
                    ItemChecker ver = new TimeStampRespVfer(app.checkProfile.newChecker(),
                            context, response.response, null, new PrecalculatedHash(mi), query, app.dump).verify();
                    run.prop(app.checkProfile.name() + " check", ver.getItem());

                }

            }
        } else {
            run.prop("error","No TSA specified");
        }
        return run;

    }


}



