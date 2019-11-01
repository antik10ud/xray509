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

import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.asn1.x509_certificate.MessageImprint;
import com.k10ud.asn1.x509_certificate.TimeStampReq;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;
import java.util.List;

import static com.k10ud.certs.util.ItemHelper.algorithm;


public class TimeStampReqProc {


    private final Context context;

    public TimeStampReqProc(Context context) {
        this.context = context;
    }

    public Item parse(long offset,byte[] timestampReq) {
        Item out = new Item();
        if (timestampReq == null)
            return out.prop("No Data");

        TimeStampReq tsq = new TimeStampReq();
        try {
            tsq.decode(offset,timestampReq, true);
        } catch (IOException e) {
            out.prop("Unable to process data as TimeStampReq", e);
            out.prop("Raw Value", ItemHelper.xprint(timestampReq));
            return out;
        }


        if (tsq.version != null)
            out.prop("Version", tsq.version.getPositiveValue());
        if (tsq.messageImprint != null)
            out.prop("MessageImprint", messageImprint(tsq.messageImprint));

        if (tsq.reqPolicy != null)
            out.prop("Request Policy", context.nameAndOid(tsq.reqPolicy));


        if (tsq.nonce != null)
            out.prop("Nonce", tsq.nonce.getPositiveValue());

        if (tsq.certReq != null)
            out.prop("Include certs", tsq.certReq.value);

        if (tsq.extensions != null)
            out.prop("Extensions", extensions(tsq.extensions.seqOf));

        return out;

    }

    private Item extensions(List<Extension> list) {
        int i = 0;
        Item item = new Item();
        for (Extension e : list) {
            i++;
            item.prop(ItemHelper.index( i), extension(e));
        }
        return item;
    }

    private Item extension(Extension e) {
        Item item = new Item();
        item.prop("Id", context.nameAndOid(e.extnID));
        if (e.critical != null)
            item.prop("Critical", e.critical.value);
        if (e.extnValue != null)
            item.prop("Value", e.extnValue.value);
        return item;
    }


    private Item messageImprint(MessageImprint mi) {
        Item item = new Item();
        if (mi == null) {
            return item;
        }
        item.prop("hashAlgorithm",
                algorithm(context, mi.hashAlgorithm));
        if (mi.hashedMessage != null)
            item.prop("hashedMessage", mi.hashedMessage.value);
        return item;
    }

}