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
import com.k10ud.ocsp.OCSPReqProc;

import java.io.IOException;

import static picocli.CommandLine.*;


public class XrayOCSPReq {


    @Command(name = "xray-ocspq",
            header = "xray-ocspq 0.0.1",
            showDefaultValues = true,
            description = "Dump RFC 6960 OCSP Request"
    )
    private static class Args extends CommonArgs {

        @Parameters(arity = "1", paramLabel = "SOURCE", description = "OCSP Request file or URL to process.")
        private String inputFile;

    }


    public static void main(String[] args) throws IOException {
        Context context = new Context(() -> null);
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
            byte[] data = CliUtil.readData("OCSPREQ", app.inputFile);
            if (data == null)
                throw new UnmatchedArgumentException("Cannot obtain OCSP request from location " + app.inputFile);

            IItemDumper dumper = CliUtil.dumper(app);
            System.out.println(dumper.toString(data,new OCSPReqProc(context).parse(data)));

        }

    }


}

