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

import com.k10ud.asn1.x509_certificate.BasicConstraints;
import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;

import java.io.ByteArrayInputStream;
import java.io.IOException;

public class BasicConstraintsProc extends BaseExtensionProc{

    @Override
    public Item processContent(Context ctx, Extension e) throws IOException{
        Item out = new Item();
        BasicConstraints bc;
        bc = new BasicConstraints();
        bc.decode(e.extnValue.from,e.extnValue.value, true);
        if (bc.cA != null)
            out.prop("CA", bc.cA.value);
        if (bc.pathLenConstraint != null)
            out.prop("pathLenConstraint", bc.pathLenConstraint.getLong());
        if (out.size()==0)
            out.prop("None");
        return out;
    }

}