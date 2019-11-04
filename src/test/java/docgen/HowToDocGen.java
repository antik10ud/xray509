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

import com.k10ud.cli.XrayCert;


public class HowToDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
        new HowToDocGen().gen("how-to");
    }

    public void section10() {

        String[] args = new String[]{
                "--query", "MATCH Extensions/**/1.3.6.1.5.5.7.1.3",
                "src/test/java/docgen/eidas.pem"
        };
        outTitle3("View Certificate QCStatements");
        outCmd("xray-cert", args, XrayCert::main);
        out("NOTE: you can view the section without the query arg, but you must find the section yourself");

    }


    public void section20() {

        String[] args = new String[]{
                "--query", "MATCH Security",
                "src/test/java/docgen/eidas.pem"
        };
        outTitle3("Check If Certificate is affected by CVE-2008-0166 (Openssl predictable random number generator) or CVE-2017-15361 (ROCA)");
        outCmd("xray-cert", args, XrayCert::main);
        out("NOTE: you can view the section without the query arg, but you must find the section yourself");

    }

    public void section30() {

        String[] args = new String[]{
                "--query", "MATCH $sn:=SerialNumber RETURN $sn{}",
                "@src/test/java/docgen/allcerts.list"
        };
        outTitle3("Search Serial Numbers Of All Certificates");
        outCmd("xray-cert", args, XrayCert::main);

        out("And If I want the hex number and the CN in CSV:");

        String[] args2 = new String[]{
                "-f", "csv",
                "--query", "MATCH $sn:=SerialNumber, Subject/*/$cn:=2.5.4.3 RETURN $sn{hex}, $cn{}",
                "@src/test/java/docgen/allcerts.list"
        };
        outCmd("xray-cert", args2, XrayCert::main);

        out("NOTE: Query interface if a highly experimental feature");


    }
}