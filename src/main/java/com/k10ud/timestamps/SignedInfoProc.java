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

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.extensions.AttrProc;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.ItemHelper;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.types.BerUtcTime;
import org.openmuc.jasn1.ber.types.Util;

import java.io.IOException;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;


public class SignedInfoProc {
    private final Context context;

    public SignedInfoProc(Context context) {
        this.context = context;
    }

    public Item parse(SignerInfo info) {
        if (info == null)
            return null;

        Item out = new Item();
        if (info.version != null)
            out.prop("version", info.version.getPositiveValue());
        if (info.sid != null)
            out.prop("signerIdentifier", signer(info.sid));
        if (info.digestAlgorithm != null)
            out.prop("digestAlgorithm", context.nameAndOid(info.digestAlgorithm.algorithm));
        if (info.signedAttrs != null)
            out.prop("signedAttrs", attributes(info.signedAttrs.seqOf));
        if (info.signatureAlgorithm != null)
            out.prop("signatureAlgorithm", context.nameAndOid(info.signatureAlgorithm.algorithm));
        if (info.signature != null)
            out.prop("signature", info.signature.value);
        if (info.unsignedAttrs != null)
            out.prop("unsignedAttrs", attributes(info.unsignedAttrs.seqOf));

        return out;
    }

    private Item signer(SignerIdentifier sid) {
        if (sid == null)
            return null;
        Item out = new Item();
        if (sid.subjectKeyIdentifier != null)
            out.prop("subjectKeyIdentifier", sid.subjectKeyIdentifier.value);
        if (sid.issuerAndSerialNumber != null) {
            out.prop("issuerName", ItemHelper.name(context, sid.issuerAndSerialNumber.issuer));
            out.prop("serialNumber", sid.issuerAndSerialNumber.serialNumber.getPositiveValue());
        }

        return out;
    }

    private Item attributes(List<Attribute> attrs) {
        if (attrs == null)
            return null;
        Item out = new Item();
        for (int i1 = 0; i1 < attrs.size(); i1++) {
            Attribute i = attrs.get(i1);
            out.prop(ItemHelper.index(i1), attribute(i));
        }
        return out;
    }

    private Item attribute(Attribute a) {
        String s = a.attrType.toString();
        Object out;
        switch (s) {
            case "1.2.840.113549.1.9.16.2.12":
                out = processSigningCertificate(a);
                break;
            case "1.2.840.113549.1.9.16.2.47":
                out = processSigningCertificateV2(a);
                break;
            case "1.2.840.113549.1.9.5":
                out = signingTime(a);
                break;
            case "1.2.840.113549.1.9.52":
                out = cmsapa(a);
                break;
            case "1.2.840.113549.1.9.3":
                out = contentType(a);
                break;
            default:
                out = new AttrProc(context).parse(a);
        }
        return ItemHelper.withOID(context,a.attrType, out);
    }

    private Item cmsapa(Attribute a) {
        Item out = new Item();

        byte[] value = flatValues(a);

        CMSAlgorithmProtection ct;
        try {
            ct=Util.decodeAny(CMSAlgorithmProtection.class,a.attrValues.from, a.attrValues.encodedImplicit());
        } catch (IOException e) {
            out.prop("Unable to process data as CMSAlgorithmProtection", e);
            out.prop("Raw Value", Base64.getEncoder().encodeToString(value));
            return out;
        }
        if (ct.digestAlgorithm != null)
            out.prop("digestAlgorithm", ItemHelper.algorithm(context, ct.digestAlgorithm));
        if (ct.macAlgorithm != null)
            out.prop("macAlgorithm", ItemHelper.algorithm(context, ct.macAlgorithm));
        if (ct.signatureAlgorithm != null)
            out.prop("signatureAlgorithm", ItemHelper.algorithm(context, ct.signatureAlgorithm));

        return out;
    }

    private Object signingTime(Attribute a) {
        Item out = new Item();
        byte[] value = flatValues(a);

        ZonedDateTime ct;
        try {
            ct=ASN1Helper.time(Util.decodeAny(Time.class, a.attrValues.from,a.attrValues.encodedImplicit()));
        } catch (IOException e) {
            out.prop("Unable to process data as Time", e);
            out.prop("Raw Value", Base64.getEncoder().encodeToString(value));
            return out;
        }
        //ZonedDateTime z = ASN1Helper.time(ct);//.toInstant().atZone(ZoneOffset.UTC);
        return ct;
    }

    private Object contentType(Attribute a) {
        Item out = new Item();
        byte[] value = flatValues(a);

        ContentType ct;
        try {
            ct=Util.decodeAny(ContentType.class, a.attrValues.from,a.attrValues.encodedImplicit());
        } catch (IOException e) {
            out.prop("Unable to process data as ContentType", e);
            out.prop("Raw Value", Base64.getEncoder().encodeToString(value));
            return out;
        }
        return context.nameAndOid(ct.toString());
    }

    private Item processSigningCertificate(Attribute a) {
        Item out = new Item();
        byte[] value = flatValues(a);
        SigningCertificate sc;// = new SigningCertificate();
        try {
            sc=Util.decodeAny(SigningCertificate.class,a.attrValues.from, a.attrValues.encodedImplicit());
        } catch (IOException e) {
            out.prop("Unable to process data as SigningCertificate", e);
            out.prop("Raw Value", Base64.getEncoder().encodeToString(value));
            return out;
        }
        for (ESSCertID id : sc.certs.seqOf) {
            Item item = new Item();
            if (id.certHash != null)
                item.prop("certHash", id.certHash.value);
            if (id.issuerSerial != null)
                item.prop("issuerSerial", ItemHelper.generalNames(context, id.issuerSerial.issuer));
            out.prop("ESSCertID", item);
        }

        return out;
    }

    private Item processSigningCertificateV2(Attribute a) {
        Item out = new Item();

        byte[] value = flatValues(a);
        SigningCertificateV2 sc ;//= new SigningCertificateV2();
        try {
            sc=Util.decodeAny(SigningCertificateV2.class, a.attrValues.from,a.attrValues.encodedImplicit());
        } catch (IOException e) {
            out.prop("Unable to process data as SigningCertificate", e);
            out.prop("Raw Value", Base64.getEncoder().encodeToString(value));
            return out;
        }
        if (sc.certs != null) {
            Item outCerts = new Item();
            out.prop("certs", outCerts);
            int k = 0;
            for (ESSCertIDv2 id : sc.certs.seqOf) {
                Item item = new Item();
                if (id.hashAlgorithm != null)
                    item.prop("hashAlgorithm", ItemHelper.algorithm(context, id.hashAlgorithm));
                else
                    item.prop("hashAlgorithm", context.nameAndOid("2.16.840.1.101.3.4.2.1").addTag("default")); //params?

                if (id.certHash != null)
                    item.prop("certHash", id.certHash.value);
                if (id.issuerSerial != null)
                    item.prop("issuerSerial", ItemHelper.generalNames(context, id.issuerSerial.issuer));

                outCerts.prop(ItemHelper.index(k), item);
            }
        }

        if (sc.policies != null) {

            Item outPols = new Item();
            out.prop("policies", outPols);

            int k = 0;
            for (PolicyInformation id : sc.policies.seqOf) {
                Item item = new Item();
                if (id.policyIdentifier != null)
                    item.prop("policyIdentifier", context.nameAndOid(id.policyIdentifier));
                if (id.policyQualifiers != null) {
                    Item pq = new Item();
                    List<PolicyQualifierInfo> seqOf = id.policyQualifiers.seqOf;
                    for (int i = 0; i < seqOf.size(); i++) {
                        PolicyQualifierInfo info = seqOf.get(i);
                        pq.prop(ItemHelper.index(i), ItemHelper.withOID(context,info.policyQualifierId, info.qualifier.value));
                    }
                    item.prop("policyQualifiers", pq);
                }
                outPols.prop(ItemHelper.index(k), item);
            }


        }
        return out;
    }


    private byte[] flatValues(Attribute a) {
        BerByteArrayOutputStream o = new BerByteArrayOutputStream(8192);
        try {
            a.attrValues.encode(o, false);
        } catch (IOException e) {
            return "<<Error decoding>>".getBytes();
        }
        return o.getArray();
    }


}
