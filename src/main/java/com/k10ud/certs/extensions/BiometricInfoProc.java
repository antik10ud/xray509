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

import com.k10ud.asn1.x509_certificate.BiometricData;
import com.k10ud.asn1.x509_certificate.BiometricInfo;
import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.asn1.x509_certificate.PredefinedBiometricType;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;
import java.util.List;

public class BiometricInfoProc extends BaseExtensionProc {

    @Override
    public Item processContent(Context ctx, Extension e) throws IOException {
        Item out = new Item();
        BiometricInfo bi = new BiometricInfo();
        bi.decode(e.extnValue.from,e.extnValue.value, true);
        List<BiometricData> seqOf = bi.seqOf;
        if (seqOf != null)
            for (int i1 = 0; i1 < seqOf.size(); i1++)
                out.prop(ItemHelper.index(i1, "BiometricData"), biometricData(ctx, seqOf.get(i1)));

        return out;
    }

    private Item biometricData(Context ctx, BiometricData bd) {
        Item type = new Item();
        if (bd.typeOfBiometricData != null) {
            if (bd.typeOfBiometricData.biometricDataOid != null) {
                type.prop("oid", ctx.nameAndOid(bd.typeOfBiometricData.biometricDataOid));
            }

            if (bd.typeOfBiometricData.predefinedBiometricType != null) {
                PredefinedBiometricType pbt = bd.typeOfBiometricData.predefinedBiometricType;
                if (type != null) {
                    switch (pbt.getInt()) {
                        case 0:
                            type.prop("type", "(0) picture");
                            break;
                        case 1:
                            type.prop("type", "(1) handwritten-signature");
                            break;
                        default:
                            type.prop("type", pbt.getPositiveValue());

                    }
                }
            }
        }
        Item out = new Item();
        out.prop("type", type);
        if (bd.hashAlgorithm != null)
            out.prop("HashAlgorithm", ctx.nameAndOid(bd.hashAlgorithm.algorithm));
        if (bd.biometricDataHash != null)
            out.prop("DataHash", bd.biometricDataHash);
        if (bd.sourceDataUri != null)
            out.prop("SourceDataUri", bd.sourceDataUri);

        return out;
    }

}