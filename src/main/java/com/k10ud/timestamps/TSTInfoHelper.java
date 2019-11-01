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

package com.k10ud.timestamps;

import com.k10ud.asn1.x509_certificate.Accuracy;

public class TSTInfoHelper {

    public static  long accurancyNanos(Accuracy accuracy) {
        if (accuracy==null)
            return 0;
        long nanoprec = 0;
        nanoprec += accuracy.micros == null ? 0 : accuracy.micros.getLongExact() * 1000;
        nanoprec += accuracy.millis == null ? 0 : accuracy.millis.getLongExact() * 1000_000;
        nanoprec += accuracy.seconds == null ? 0 : accuracy.seconds.getLongExact() * 1000_000_000;
        return nanoprec;
    }

}
