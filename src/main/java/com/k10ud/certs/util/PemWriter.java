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

package com.k10ud.certs.util;

import java.io.IOException;
import java.io.Writer;

public class PemWriter {
    private static final String BEGIN = "-----BEGIN ";
    private static final String END = "-----END ";
    private final Writer out;

    public PemWriter(Writer out) {
        this.out = out;
    }

    public void write(String type, byte[] data) throws IOException {
        String beginMarker = (BEGIN + type + "-----").toUpperCase();
        String endMarker = (END + type + "-----").toUpperCase();
        out.append(beginMarker);
        out.append("\n");
        out.write(Base64.encodeBytes(data, 0));
        out.append("\n");
        out.append(endMarker);
        out.append("\n");
    }

}
