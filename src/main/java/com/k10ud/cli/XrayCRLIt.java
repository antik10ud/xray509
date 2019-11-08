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

import com.k10ud.certs.CertificateProc;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.KV;
import com.k10ud.crl.CRLProc;
import com.k10ud.help.QueryableMap;

import java.io.IOException;
import java.util.List;

import static picocli.CommandLine.*;


public class XrayCRLIt {


    @Command(name = "xray-crl",
            header = "xray-crl 0.0.1",
            showDefaultValues = true,
            description = "Dump RFC 6818 CRL Request"
    )
    public static class Args extends CommonArgs {

        @Parameters(arity = "1", paramLabel = "SOURCE", description = "CRL file, certificate or URL to process.")
        public String inputFile;

        @Option(names = {"--dump-source-cert"}, description = "Dump source certificate")
        public boolean dumpSourceCert = false;

        @Option(names = {"--all"}, description = "Process all available CRL in source certificate")
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
            if (app.inputFile.startsWith("tls:") ||!crlProc(run, context, app.inputFile, false)) {
                byte[] data = CliUtil.readCertificate(app.inputFile);

                if (data == null) {
                    run.prop("error", "Cannot obtain CRLS nor certificates from location " + app.inputFile);
                    return run;
                }

                Item items = new CertificateProc(context).parse(data).prop("@encoded", data);

                if (app.dumpSourceCert) {
                    run.prop("Certificate source", items);

                }
                QueryableMap map = new QueryableMap(items);
                List<String> crlURLs = map.q("Extensions/*/2.5.29.31/DistributionPoint[*]/*/uniformResourceIdentifier=(*)");
                for (String i : crlURLs)
                    if (crlProc(run, context, i, true) && !app.processAll) return run;
            }
        }
        return run;
    }

    private static boolean crlProc(Item dumper, Context context, String inputFile, boolean showFile) {

        byte[] data = CliUtil.readData("CRL", inputFile);
        if (data == null)
            return false;
        Item items = new CRLProc(context).parse(data);
        // Unable to process data as CertificateList
        if (items.size() > 1) { //!! return error from processors
            KV kv = items.get(0);
            if ("Unable to process data as CertificateList".equals(kv.getKey())) {
                 dumper.prop("error", "Unable to process data as CRL from " + inputFile);
                return false;
            }
        }
       // if (showFile)
            dumper.prop("Source " + inputFile, items);
        //else
          //  dumper.prop(items);
        return true;

    }


}

