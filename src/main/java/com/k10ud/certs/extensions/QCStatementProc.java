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
import org.openmuc.jasn1.ber.types.BerObjectIdentifier;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;

public class QCStatementProc extends BaseExtensionProc {

    private final Map<String, BiFunction<Context, QCStatement, Item>> map;
    private final BiFunction<Context, QCStatement, Item> defaultProc;

    public QCStatementProc() {
        map = new HashMap<>();

        defaultProc = (ctx, qcs) -> {
            if (qcs != null && qcs.statementInfo != null) {
                Item out = new Item();
                out.prop("statementInfo", qcs.statementInfo);
                return out;
            }
            return null;
        };

        map.put("0.4.0.1862.1.3", (ctx, qcs) -> {
            Item out = new Item();
            QcEuRetentionPeriod q = new QcEuRetentionPeriod();
            try {
                q.decode(qcs.statementInfo.from, qcs.statementInfo.value, true);
                out.prop("Years", q.getInt());
            } catch (IOException e) {
                //  e.printStackTrace();
                return defaultProc.apply(ctx, qcs);
            }
            return out;
        });


        map.put("0.4.0.1862.1.5", (ctx, qcs) -> {
            Item out = new Item();
            QcEuPDS q = new QcEuPDS();
            try {
                q.decode(qcs.statementInfo.from, qcs.statementInfo.value, true);
                List<PdsLocation> seqOf = q.seqOf;
                for (int i = 0; i < seqOf.size(); i++) {
                    PdsLocation location = seqOf.get(i);
                    out.prop(ItemHelper.index(i, "Location"), pds(location));
                }
            } catch (IOException e) {
                return defaultProc.apply(ctx, qcs);
            }
            return out;
        });


        map.put("0.4.0.1862.1.6", (ctx, qcs) -> {
            Item out = new Item();
            QcType q = new QcType();
            try {
                q.decode(qcs.statementInfo.from, qcs.statementInfo.value, true);
                List<BerObjectIdentifier> seqOf = q.seqOf;
                for (int i = 0; i < seqOf.size(); i++) {
                    //  PdsLocation location = seqOf.get(i);
                    out.prop(ctx.nameAndOid(seqOf.get(i)));

                }
            } catch (IOException e) {
                // e.printStackTrace();
                return defaultProc.apply(ctx, qcs);
            }
            return out;
        });


        map.put("0.4.0.1862.1.2", (ctx, qcs) -> {
            Item out = new Item();
            QcEuLimitValue q = new QcEuLimitValue();
            try {
                q.decode(qcs.statementInfo.from, qcs.statementInfo.value, true);
                // value = amount * 10^exponent
                double value = q.amount.getLong() * Math.pow(10, q.exponent.getLong());
                TaggedString ts = new TaggedString(String.valueOf(value)).addTag("synthetic");
                out.prop("value", ts);
                out.prop("amount", q.amount.getValue());
                out.prop("exponent", q.exponent.getValue());
                out.prop("currency", q.currency);
            } catch (IOException e) {
                //  e.printStackTrace();
                return defaultProc.apply(ctx, qcs);
            }
            return out;
        });
        map.put("1.3.6.1.5.5.7.11.2", (ctx, qcs) -> {
            Item out = new Item();
            SemanticsInformation q = new SemanticsInformation();
            try {
                if (qcs.statementInfo != null) {
                    q.decode(qcs.statementInfo.from, qcs.statementInfo.value, true);
                    out.prop("keyIdentifier", ctx.nameAndOid(q.keyIdentifier));
                }
                if (q.nameRegistrationAuthorities != null && q.nameRegistrationAuthorities.seqOf.size() > 0) {
                    List<GeneralName> seqOf = q.nameRegistrationAuthorities.seqOf;
                    for (int i1 = 0; i1 < seqOf.size(); i1++) {
                        GeneralName i = seqOf.get(i1);
                        out.prop(ItemHelper.index(i1), ItemHelper.generalName(ctx, i));
                    }
                }
            } catch (IOException e) {
                // e.printStackTrace();
                return defaultProc.apply(ctx, qcs);
            }
            return out;
        });

    }

    private Item pds(PdsLocation location) {
        Item out = new Item();
        out.prop("lang", new TaggedString(String.valueOf(location.language)).addTag("type", "PrintableString"));
        out.prop("url", new TaggedString(String.valueOf(location.url)).addTag("type", "IA5String"));
        return out;
    }

    @Override
    public Item processContent(Context ctx, Extension e) throws IOException {
        QCStatements list = new QCStatements();
        list.decode(e.extnValue.from, e.extnValue.value, true);
        Item out = new Item();

        if (list.seqOf != null) {
            List<QCStatement> seqOf = list.seqOf;
            for (int i1 = 0; i1 < seqOf.size(); i1++) {
                QCStatement i = seqOf.get(i1);
                out.prop(ctx.nameAndOid(i.statementId).addIndexTag(i1), qcProc(i.statementId).apply(ctx, i));
                //       out.prop(ItemHelper.index((k++)), qcProc(i.statementId).apply(ctx, i));
            }
        }
        return out;
    }

    private BiFunction<Context, QCStatement, Item> qcProc(BerObjectIdentifier statementId) {
        if (statementId == null)
            return defaultProc;
        return map.getOrDefault(statementId.toString(), defaultProc);
    }

}
