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

package docgen;

import com.k10ud.cli.XrayTimestamp;
import com.k10ud.cli.XrayTimestampReq;
import com.k10ud.cli.XrayTimestampRes;


public class TimestampResponeDumpDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
       new TimestampResponeDumpDocGen().gen("xray-tsr");
    }

    public void section10_Usage() {
        String[] args = new String[]{
                "--help"
        };
        outTitle3("Usage");
        outCmd(args, XrayTimestampRes::main);
    }

    public void section20_sample1() {

        XrayTimestamp.main(new String[]{
                "--cert-path",
                "--dump",
                "-o", "/tmp/ts",
                "--source-text", "data",
                "http://tsa.belgium.be/connect"
        });


        String[] args= new String[]{
                 "/tmp/ts.tsr",

        };
        outTitle3("Sample 1");
        out("Dump Timestamp Response");
        outCmd(args, XrayTimestampRes::main);
    }



}