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

package com.k10ud.certs.extensions;

import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.certs.*;

import java.io.IOException;

public abstract class BaseExtensionProc implements ExtensionProc {

    public Item process(Context ctx, Extension e) {
        if (e == null)
            return null;
      //  TaggedString st = ctx.nameAndOid(e.extnID);
        boolean critical = e.critical != null && e.critical.value;
        try {
            Item inner = processContent(ctx, e);
            Item out=new Item();
            if (critical) {
                out.prop("Critical");
            }
            out.transfer(inner);
            return out;
        } catch (Exception x) {
            Item out = new Item();
            out.prop("Raw Value", e.extnValue);
            return out;
        }
    }

    protected abstract Item processContent(Context ctx, Extension e) throws IOException;
}
