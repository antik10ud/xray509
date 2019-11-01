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

import static picocli.CommandLine.Help.Ansi;
import static picocli.CommandLine.Option;


public class CommonArgs {
    @Option(names = {"-h", "--help"}, usageHelp = true,
            description = "Displays this help message and quits.")
    public boolean helpRequested = false;
    public Context context;


    enum ColorMode {auto, always, never}

    /*
Encodings (also used as extensions)
.DER = The DER extension is used for binary DER encoded certificates. These files may also bear the CER or the CRT extension.   Proper English usage would be “I have a DER encoded certificate” not “I have a DER certificate”.
.PEM = The PEM extension is used for different types of X.509v3 files which contain ASCII (Base64) armored data prefixed with a “—– BEGIN …” line.
Common Extensions
.CRT = The CRT extension is used for certificates. The certificates may be encoded as binary DER or as ASCII PEM. The CER and CRT extensions are nearly synonymous.  Most common among *nix systems
CER = alternate form of .crt (Microsoft Convention) You can use MS to convert .crt to .cer (.both DER encoded .cer, or base64[PEM] encoded .cer)  The .cer file extension is also recognized by IE as a command to run a MS cryptoAPI command (specifically rundll32.exe cryptext.dll,CryptExtOpenCER) which displays a dialogue for importing and/or viewing certificate contents.
.KEY = The KEY extension is used both for public and private PKCS#8 keys. The keys may be encoded as binary DER or as ASCII PEM.
T
 */
    enum Format {csv, json, text, keys, der, pem}


    @Option(names = {"-c", "--color"}, paramLabel = "<mode>", description = {
            "Show colored output",
            "The color parameter is optional (defaults to `auto`)",
            "The possible options are:",
            " * @|yellow auto|@ - Only show colors if the platform supports it.",
            " * @|yellow always|@ - Turn on colored output.",
            " * @|yellow never|@ - Turn off colored output."
    })
    public ColorMode color = ColorMode.auto;

    @Option(names = {"-f", "--format"}, paramLabel = "<format>", description = {
            "Specify output format",
            "The format parameter is optional (defaults to `text`)",
            "The possible options are:",
            " * @|yellow text|@ - Text output.",
            " * @|yellow json|@ - JSON output.",
            " * @|yellow keys|@ - KV output.",
            " * @|yellow csv|@ - Comma Separated Values output.",
            " * @|yellow der|@ - DER output (i.e. crt, cer)",
            " * @|yellow pem|@ - PEM output."
    })
    public Format format = Format.text;




    @Option(names = {"--text-format-compact-lines"}, paramLabel = "<text-format-compact-lines>", description = {
            "Specify output must compact single elements in one line"
    })
    public boolean textFormatCompactLines = true;


    @Option(names = {"--show-encodings"}, paramLabel = "<show-encodings>", description = {
            "Show encodings"
    })
    public boolean showEncodings;


    @Option(names = {"--show-sourcenames"}, paramLabel = "<show-sourcenames>", description = {
            "Show sourcenames, default to false"
    })
    public boolean showSourceName;



    public Ansi colorScheme() {
        ColorMode x = color;
        switch (x) {
            case always:
                return Ansi.ON;
            case never:
                return Ansi.OFF;

            case auto:
            default:
                return Ansi.AUTO;

        }
    }

}


