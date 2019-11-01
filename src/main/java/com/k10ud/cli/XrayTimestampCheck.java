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

import com.k10ud.certs.Context;
import com.k10ud.certs.IItemDumper;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.timestamps.ItemChecker;
import com.k10ud.timestamps.TimeStampRespVfer;
import com.k10ud.timestamps.checkprofiles.TSCheckETSI319421;
import com.k10ud.timestamps.checkprofiles.TSCheckProfile;
import com.k10ud.timestamps.checkprofiles.TSCheckRFC3161;

import java.io.IOException;

import static picocli.CommandLine.*;


public class XrayTimestampCheck {

    public enum TSCheckProfiles {
        RFC3161(TSCheckRFC3161.class),
        ETSI319421(TSCheckETSI319421.class),;
        private final Class<? extends TSCheckProfile> checker;

        TSCheckProfiles(Class<? extends TSCheckProfile> checker) {
            this.checker = checker;
        }


        public Class<?> getChecker() {
            return checker;
        }

        public TSCheckProfile newChecker() {
            try {
                return checker.newInstance();
            } catch (Exception e) {
               throw new RuntimeException(e);
            }
        }
    }


    @Command(name = "xray-ts-chk",
            header = "xray-ts-chk 0.0.1",
            showDefaultValues = true,
            description = "Verify a RFC 3161/5816 Timestamp"
    )
    private static class Args extends CommonArgs {


        @Option(names = {"--data-file"}, description = "Input file to hash")
        private String dataFile;

        @Option(names = {"--data-text"}, description = "Text data  to hash")
        private String dataText;

        @Option(names = {"--data-hash"}, description = "Precalculated data hash as hexstring")
        private String dataHash;

        @Option(names = {"--tsq"}, description = "Timestamp request file")
        private String tsq;

        @Option(required = true, names = {"--tsr"}, description = "Timestamp response file")
        private String tsr;

        @Option(names = {"--tsa-cert"}, description = "Timestamp issuer cert file")
        private String issuerCert;

        @Option(names = {"--dump"}, description = "Dump provided timestamp issuer cert, tsr and tsq")
        private boolean dump;


        @Option(names = {"--profile"}, description = "Timestamp validation profile")
        private TSCheckProfiles profile = TSCheckProfiles.RFC3161;


    }


    public static void main(String[] args)  {
        Context context = null;
        try {
            context = new Context(() -> null);
        } catch (IOException e) {
            System.err.println(e.getMessage());
            return;
        }
        Args app = null;
        try {
            app = populateCommand(new Args(), args);
        } catch (Exception x) {
            System.err.println(x.getMessage());
            usage(new Args(), System.err);
            System.exit(-1);
        }
        if (app.helpRequested) {
            usage(new Args(), System.out);

        } else {
            TSCheckProfile checker = null;
            try {
                checker = (TSCheckProfile) app.profile.getChecker().newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }

            byte[] issuerCertBytes = null;
            if (app.issuerCert != null)
                issuerCertBytes = CliUtil.readCertificate(app.issuerCert);
            byte[] responseBytes = CliUtil.readTSR(app.tsr);
            byte[] tsqBytes = null;
            if (app.tsq != null)
                tsqBytes = CliUtil.readCertificate(app.tsq);

            if ((app.dataFile != null ? 1 : 0) + (app.dataHash != null ? 1 : 0) + (app.dataText != null ? 1 : 0) > 1)
                throw new ParameterException("You must specifiy only one data-* option");

            Hasher hasher = null;
            if (app.dataFile != null)
                hasher = new FileHasher(app.dataFile);
            else if (app.dataText != null)
                hasher = new TextHasher(app.dataText);
            if (app.dataHash != null)
                hasher = new PrecalculatedHash(ASN1Helper.hexToBytes(app.dataHash));


            IItemDumper dumper = CliUtil.dumper(app);
            ItemChecker ver = new TimeStampRespVfer(checker, context, responseBytes, issuerCertBytes, hasher, tsqBytes, app.dump).verify();
            System.out.println(dumper.toString(responseBytes,ver.getItem()));

        }
    }


}



