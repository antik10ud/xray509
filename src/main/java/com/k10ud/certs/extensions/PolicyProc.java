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

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;

public class PolicyProc extends BaseExtensionProc {

    @Override
    public Item processContent(Context ctx, Extension e) throws IOException {
        Item out = new Item();
        CertificatePolicies cp = new CertificatePolicies();
        cp.decode(e.extnValue.from,e.extnValue.value, true);
        if (cp.seqOf != null) {
            int k=0;
            for (PolicyInformation pi : cp.seqOf)
                out.prop(ItemHelper.index(k++),policyInformation(ctx, pi));
        }
        return out;
    }

    private Item policyInformation(Context ctx, PolicyInformation pi) {
        if (pi == null)
            return null;
        Item out = new Item();
        if (pi.policyQualifiers != null && pi.policyQualifiers.seqOf != null) {
            int k=0;
            for (PolicyQualifierInfo i : pi.policyQualifiers.seqOf)
                out.prop(ItemHelper.index(k++),policyQualifier(ctx, i));
        }
        return new Item(ctx.nameAndOid(pi.policyIdentifier), out);
    }

    private Item policyQualifier(Context ctx, PolicyQualifierInfo i) {
        if (i==null)
            return null;

        Item item = new Item();
        try {
            switch (i.policyQualifierId.toString()) {
                case "1.3.6.1.5.5.7.2.1":
                    CPSuri uri = new CPSuri();
                    uri.decode(i.qualifier.from,i.qualifier.value, true);
                    item.prop("URI", new TaggedString(uri.toString()).addTag("type","IA5String"));
                    break;
                case "1.3.6.1.5.5.7.2.2":
                    UserNotice un = new UserNotice();
                    un.decode(i.qualifier.from,i.qualifier.value, true);
                    if (un.noticeRef != null)
                        item.prop("NoticeRef", un.noticeRef);
                    if (un.explicitText != null)
                        item.prop("ExplicitText", ItemHelper.displayText(un.explicitText));
                    break;
            }
        } catch (IOException e) {
            //e.printStackTrace();
            if (i.qualifier!=null)
                item.prop("Value", i.qualifier.value);
        }
        return new Item(ctx.nameAndOid(i.policyQualifierId), item);
    }
}
