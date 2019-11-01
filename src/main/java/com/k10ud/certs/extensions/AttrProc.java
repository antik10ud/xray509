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

import com.k10ud.asn1.x509_certificate.Attribute;
import com.k10ud.asn1.x509_certificate.AttributeValue;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ItemHelper;
import org.openmuc.jasn1.ber.types.BerGeneralizedTime;
import org.openmuc.jasn1.ber.types.Util;

import java.io.IOException;
import java.util.List;

public class AttrProc {

    private final Context ctx;

    public AttrProc(Context ctx) {
        this.ctx = ctx;
    }

    public Item parse(Attribute a) {
        Item out = new Item();
        if (a.attrValues != null) {
            List<AttributeValue> seqOf = a.attrValues.seqOf;
            for (int i1 = 0, n = seqOf.size(); i1 < n; i1++) {
                AttributeValue i = seqOf.get(i1);
                Object v = null;
                try {

                    switch (a.attrType.toString()) {
                        case "1.3.6.1.5.5.7.9.1": //dateOfBirth
                            v = ItemHelper.generalizedTime(Util.decodeAny(BerGeneralizedTime.class, a.attrValues.from,a.attrValues.encodedImplicit()));
                            break;
                        default:

                    }
                } catch (IOException e) {
                    //...
                }

                if (v == null)
                    v = i.value;

                out.prop(ItemHelper.index(i1), v);
            }
        }
        return new Item(ctx.nameAndOid(a.attrType), out);
    }


}
