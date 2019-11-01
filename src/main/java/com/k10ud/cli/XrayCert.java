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
import com.k10ud.certs.IItemDumper;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.PemWriter;

import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;

import static picocli.CommandLine.*;


public class XrayCert {


    @Command(name = "xray-cert",
            header = "xray-cert 0.0.1",
            showDefaultValues = true,
            description = "Dump x509 certificates"
    )
    public static class CertDumpArgs extends CommonArgs {

        @Parameters(arity = "1..*", paramLabel = "SOURCE", description = "X509Certificate sources such as pem or der files, URLs, tls:<host>, data:<base64data>")
        private String[] inputFile;


        @Option(names = {"--query"}, paramLabel = "<text>", description = "Query certificates")
        private String query;
    }


    public static void main(String[] args)  {
        Context context = null;
        try {
            context = new Context(() -> null);
        } catch (IOException e) {
            throw new RuntimeException("Cannot load context");
        }
        CertDumpArgs app = null;
        try {
            app = populateCommand(new CertDumpArgs(), args);
        } catch (Exception x) {
            System.err.println(x.getMessage());
            usage(new CertDumpArgs(), System.err);
            System.exit(-1);
        }
        if (app.helpRequested) {
            usage(new CertDumpArgs(), System.out);

        } else {
            switch (app.format) {
                case der:
                case pem:
                    if (app.query != null && app.query.length() > 0) {
                        throw new RuntimeException("Invalid format for query operation");
                    }
                    break;
            }
            QueryCert query = null;
            if (app.query != null) {
                query = QueryCert.parse(loadQuery(app.query));
            }
            for (String i : app.inputFile) {
                StreamFiles sf = new StreamFiles(i);
                while (sf.hasMore()) {
                    String next = sf.next();

                    processCert(query, app, context, next);
                }
            }

        }
    }


    private static void processCert(QueryCert query, CertDumpArgs app, Context context, String f) {
        byte[] data = CliUtil.readData("CERTIFICATE", f);
        if (data == null) {
            System.err.println("cannot load certificate from " + f);
            return;
        }
        Item items = null;
        if (query != null || app.format == CommonArgs.Format.text || app.format == CommonArgs.Format.json || app.format == CommonArgs.Format.keys || app.format == CommonArgs.Format.csv) {
            items = new CertificateProc(context).parse(data);
        }
        if (query != null && app.query.length() > 0) {
            if (!query.match(items))
                return;

            if (query.hasProjection()) {
                HashMap<String, String> ctx = new HashMap<>();
                ctx.put("ξsource", f);
                items = query.project(items, ctx);
                if (items.size() == 0)
                    return;
            }

        }
        if (app.showSourceName) {
            System.out.println(f);
        }
        switch (app.format) {
            case der:
                try {
                    PrintStream w = new PrintStream(System.out);
                    w.write(data);
                    w.flush();
                } catch (IOException e) {
                    System.out.println("unsupported");
                }
                break;
            case pem:
                try {
                    PrintWriter w = new PrintWriter(System.out);
                    new PemWriter(w).write("CERTIFICATE", data);
                    w.flush();
                } catch (IOException e) {
                    System.out.println("unsupported");
                }
                break;
            default:
                IItemDumper dumper = CliUtil.dumper(app);
                try {
                    System.out.println(dumper.toString(data, items));
                } catch (Exception x) {
                    System.out.println("unsupported");//x.printStackTrace();
                }
                break;
        }


    }

    private static String loadQuery(String query) {
        if (query.startsWith("@")) {
            try {
                return new String(Files.readAllBytes(Paths.get(query.substring(1))));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        return query;
    }

}

