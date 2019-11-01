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

import com.k10ud.asn1.x509_certificate.CRLDistributionPoints;
import com.k10ud.asn1.x509_certificate.DistributionPoint;
import com.k10ud.asn1.x509_certificate.DistributionPointName;
import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;
import java.util.List;

public class CRLDistPointsProc extends BaseExtensionProc {

    @Override
    public Item processContent(Context ctx, Extension e) throws IOException {
        Item out = new Item();
        CRLDistributionPoints crldp = new CRLDistributionPoints();
        crldp.decode(e.extnValue.from,e.extnValue.value, true);
        List<DistributionPoint> seqOf = crldp.seqOf;
        if (crldp.seqOf != null)
            for (int i = 0, n = seqOf.size(); i < n; i++)
                out.prop("DistributionPoint[" + i + "]", distributionPoint(ctx, seqOf.get(i)));
        return out;
    }

    private Item distributionPoint(Context ctx, DistributionPoint dp) {
        Item out = new Item();
        if (dp.distributionPoint != null)
            out.prop("Name", dpName(ctx, dp.distributionPoint));
        if (dp.cRLIssuer != null)
            out.prop("CRLIssuer", ItemHelper.generalNames(ctx, dp.cRLIssuer));
        if (dp.reasons != null)
            out.prop("Reasons", dp.reasons);
        return out;
    }

    private Item dpName(Context ctx, DistributionPointName distributionPoint) {
        if (distributionPoint.fullName != null) {
            Item out = new Item();
            out.prop("FullName", ItemHelper.generalNames(ctx, distributionPoint.fullName));
            return out;
        } else if (distributionPoint.nameRelativeToCRLIssuer != null) {
            Item out = new Item();
            out.prop("NameRelativeToCRLIssuer", ItemHelper.relativeDistinguishedName(ctx, distributionPoint.nameRelativeToCRLIssuer));
            return out;
        }
        return Item.EMPTY;
    }

}