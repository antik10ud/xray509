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

package com.k10ud.ocsp;

import com.k10ud.asn1.x509_certificate.CertID;
import com.k10ud.asn1.x509_certificate.Certificate;
import com.k10ud.asn1.x509_certificate.Extension;
import com.k10ud.asn1.x509_certificate.OCSPVersion;
import com.k10ud.certs.CertificateProc;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;
import com.k10ud.certs.util.ItemHelper;

import java.util.List;

public class OCSPItem {

    public static Item certs(Context context, List<Certificate> list) {
        Item out = new Item();
        int i = 0;
        for (Certificate c : list)
            out.prop(ItemHelper.index(i++), cert(context,c));
        return out;

    }

    private  static Item cert(Context context,Certificate c) {
        return new CertificateProc(context).parse(c);
    }



    public static  Object version(OCSPVersion version) {
        if (version == null){
           return new TaggedString(String.valueOf(0)).addTag("v1").addTag("default");
        }

        switch (version.getInt()) {
            case 0:
                return new TaggedString(String.valueOf(version.getPositiveValue())).addTag("v1");
        }
        return version.getValue();

    }

    public static  Item extensions(Context context,List<Extension> list) {
        int i = 0;
        Item item = new Item();
        for (Extension e : list) {
            i++;
            item.prop(ItemHelper.index( i), extension(context,e));
        }
        return item;
    }

    public static  Item  extension(Context context,Extension e) {
        Item item = new Item();
        item.prop("Id", context.nameAndOid(e.extnID));
        if (e.critical != null)
            item.prop("Critical", e.critical.value);
        if (e.extnValue != null)
            item.prop("Value", e.extnValue.value);
        return item;
    }


    /*

CertID ::= SEQUENCE {
    hashAlgorithm            AlgorithmIdentifier,
    issuerNameHash     OCTET STRING, -- Hash of Issuer's DN
    issuerKeyHash      OCTET STRING, -- Hash of Issuers public key
    serialNumber       CertificateSerialNumber }

     */
    public static Item certId(Context context,CertID id) {
        Item item = new Item();
        if (id.hashAlgorithm != null)
            item.prop("hashAlgorithm", ItemHelper.algorithm(context, id.hashAlgorithm));
        if (id.issuerNameHash != null)
            item.prop("issuerNameHash", id.issuerNameHash.value);
        if (id.issuerKeyHash != null)
            item.prop("issuerKeyHash", id.issuerKeyHash.value);
        if (id.serialNumber != null)
            item.prop("serialNumber", id.serialNumber.getRawValue());

        return item;
    }

}
