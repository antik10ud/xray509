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
import com.k10ud.certs.CertificateProc;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.ItemHelper;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;
import org.openmuc.jasn1.ber.types.BerOctetString;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static com.k10ud.certs.util.ItemHelper.encoded;

public class SignedDataProc {
    private final Context context;

    public SignedDataProc(Context context) {
        this.context = context;
    }

    public Item parse(SignedData signedData) {
        if (signedData == null)
            return null;
        Item out = new Item();
        if (signedData.version != null)
            out.prop("version", signedData.version.getPositiveValue());
        if (signedData.digestAlgorithms != null)
            out.prop("digestAlgorithms", ItemHelper.algorithms(context, signedData.digestAlgorithms));
        if (signedData.encapContentInfo != null)
            out.prop("encapContentInfo", encapContentInfo(signedData.encapContentInfo));
        if (signedData.certificates != null)
            out.prop("certificates", certificates(signedData.certificates));
        if (signedData.crls != null)
            out.prop("revocationInfoChoices", signedData.crls.toString());
        if (signedData.signerInfos != null)
            out.prop("signerInfos", signerInfos(signedData.signerInfos));
        return out;
    }

    private Item encapContentInfo(EncapsulatedContentInfo info) {
        Item out = new Item();
        String type = null;
        if (info.eContentType != null) {
            type = info.eContentType.toString();
            out.prop("eContentType", context.nameAndOid(type));
        }
        if (info.eContent != null)
            out.prop("eContent", eContent(type, info.eContent));
        return out;
    }

    private Object eContent(String type, BerOctetString eContent) {
        if (type != null) {
            Item out = new Item();
            switch (type) {
                case "1.2.840.113549.1.9.16.1.4":
                    TSTInfo info = new TSTInfo();
                    try {
                        info.decode(eContent.from,eContent.value, true);
                    } catch (IOException e) {
                        out.prop("Unable to process data as TSTInfo", e);
                        out.prop("Raw Value", Base64.getEncoder().encodeToString(eContent.value));
                        return out;
                    }
                    if (info.version != null)
                        out.prop("version", info.version.getPositiveValue());
                    if (info.policy != null)
                        out.prop("policy", context.nameAndOid(info.policy));
                    if (info.messageImprint != null) {
                        Item hash = new Item();
                        if (info.messageImprint.hashAlgorithm != null)
                            hash.prop("hashAlgorithm", ItemHelper.algorithm(context, info.messageImprint.hashAlgorithm));
                        if (info.messageImprint.hashedMessage != null)
                            hash.prop("messageImprint", info.messageImprint.hashedMessage.value);
                        out.prop("messageImprint", hash);
                    }
                    if (info.serialNumber != null)
                        out.prop("serialNumber", info.serialNumber.getPositiveValue());

                    ZonedDateTime genTime = null;
                    if (info.genTime != null) {
                        genTime = ASN1Helper.time(info.genTime);
                       // ZonedDateTime z = genTime.toInstant().atZone(ZoneOffset.UTC);
                        out.prop("genTime", genTime);
                    }
                    if (info.accuracy != null) {
                        out.prop("accuracy", accuracy(info.accuracy));
                    }

                    if (info.accuracy != null && genTime != null) {
                        long nanoprec = TSTInfoHelper.accurancyNanos(info.accuracy);

                        if (nanoprec > 0)
                            out.prop("Time window", syntheticTime(nanoprec, genTime));
                    }

                    if (info.ordering != null)
                        out.prop("ordering", info.ordering.toString());
                    if (info.nonce != null)
                        out.prop("nonce", info.nonce.getPositiveValue());

                    if (info.tsa != null)
                        out.prop("tsa", ItemHelper.generalName(context, info.tsa));
                    if (info.extensions != null)
                        out.prop("extensions", ItemHelper.extensions(context, info.extensions));

                    break;
            }
            return out;
        }
        return eContent;
    }


    private Item syntheticTime(long nanoprec, ZonedDateTime genTime) {
        Item out = new Item();

        ZonedDateTime uld = genTime.plusNanos(nanoprec);
        ZonedDateTime lld = genTime.minusNanos(nanoprec);

        TaggedString ult = new TaggedString(String.valueOf(uld)).addTag("synthetic");
        TaggedString llt = new TaggedString(String.valueOf(lld)).addTag("synthetic");

        out.prop("Lower limit", llt);
        out.prop("Upper limit", ult);
        return out;
    }


    private Item accuracy(Accuracy accuracy) {
        if (accuracy == null)
            return null;
        Item out = new Item();
        if (accuracy.micros != null)
            out.prop("micros", accuracy.micros.getPositiveValue());
        if (accuracy.millis != null)
            out.prop("millis", accuracy.millis.getPositiveValue());
        if (accuracy.seconds != null)
            out.prop("seconds", accuracy.seconds.getPositiveValue());
        if (accuracy.micros==null&&accuracy.millis==null&&accuracy.seconds==null){
            out.prop("micros",new TaggedString("0").addTag("default"));
            out.prop("millis",new TaggedString("0").addTag("default"));
            out.prop("seconds",new TaggedString("0").addTag("default"));
        }
        return out;

    }

    private Item signerInfos(SignerInfos signerInfos) {
        if (signerInfos == null)
            return null;
        Item out = new Item();
        SignedInfoProc sip = new SignedInfoProc(context);
        List<SignerInfo> seqOf = signerInfos.seqOf;
        for (int i1 = 0; i1 < seqOf.size(); i1++) {
            SignerInfo i = seqOf.get(i1);
            out.prop(ItemHelper.index(i1), sip.parse(i));
        }
        return out;

    }

    private Item certificates(CertificateSet certificates) {
        Item out = new Item();
        List<CertificateChoices> seqOf = certificates.seqOf;
        for (int i = 0; i < seqOf.size(); i++) {
            CertificateChoices cc = seqOf.get(i);
            Item xx = new CertificateProc(context).parse(cc.certificate);
                    //.prop("@encoded",encoded(cc.certificate));
            out.prop(ItemHelper.index(i), xx);
        }
        return out;
    }

    public static Object encoded(Certificate cert) {
        if (cert != null) {

        try {
            BerByteArrayOutputStream o = new BerByteArrayOutputStream(8192);
            cert.encode(o, true);
           return  new String(Base64.getMimeEncoder().encode(o.getArray()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        }
        return null;
    }
}
