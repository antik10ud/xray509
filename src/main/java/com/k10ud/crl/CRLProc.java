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

package com.k10ud.crl;

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.TaggedString;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;
import java.util.List;


public class CRLProc {


    /*



CertificateList  ::=  SEQUENCE  {
     tbsCertList          TBSCertList,
     signatureAlgorithm   AlgorithmIdentifier,
     signature            BIT STRING  }


     */
    private final Context context;

    public CRLProc(Context context) {
        this.context = context;
    }

    public Item parse(byte[] crlBytes) {
        Item out = new Item();
        if (crlBytes == null)
            return out.prop("No Data");

        CertificateList certList = new CertificateList();
        try {
            certList.decode(0,crlBytes, true);
        } catch (IOException e) {
            out.prop("Unable to process data as CertificateList", e);
            out.prop("Raw Value", ItemHelper.xprint(crlBytes));
            return out;
        }

        if (certList.tbsCertList != null) {
            if (certList.tbsCertList.issuer != null) {
                out.prop("issuer", ItemHelper.name(context, certList.tbsCertList.issuer));
            }
            out.prop("tbsCertList", tbsCertList(certList.tbsCertList));
            if (certList.tbsCertList.crlExtensions != null) {
                Extensions extensions = certList.tbsCertList.crlExtensions;
                out.prop("crlExtensions", ItemHelper.extensions(context, extensions));
            }

        }
        if (certList.signatureAlgorithm != null)
            out.prop("signatureAlgorithm", ItemHelper.algorithm(context, certList.signatureAlgorithm));
        if (certList.signature != null)
            out.prop("signature", certList.signature.value);


        return out;

    }


    /*
    TBSCertList  ::=  SEQUENCE  {
         version                 Version OPTIONAL,
                                      -- if present, MUST be v2
         signature               AlgorithmIdentifier,
         issuer                  Name,
         thisUpdate              Time,
         nextUpdate              Time OPTIONAL,
         revokedCertificates     SEQUENCE OF SEQUENCE  {
              userCertificate         CertificateSerialNumber,
              revocationDate          Time,
              crlEntryExtensions      Extensions OPTIONAL
                                             -- if present, MUST be v2
                                   }  OPTIONAL,
         crlExtensions           [0] Extensions OPTIONAL }
                                             -- if present, MUST be v2



     */
    private Item tbsCertList(TBSCertList tbsCertList) {
        Item out = new Item();
        if (tbsCertList.version != null)
            out.prop("version", version(tbsCertList.version));
        if (tbsCertList.thisUpdate != null)
            out.prop("thisUpdate", ASN1Helper.time(tbsCertList.thisUpdate));
        if (tbsCertList.nextUpdate != null)
            out.prop("nextUpdate", ASN1Helper.time(tbsCertList.nextUpdate));
        if (tbsCertList.revokedCertificates != null)
            out.prop("revokedCertificates", tbsRevokedCertificate(tbsCertList.revokedCertificates.seqOf));
        if (tbsCertList.signature != null)
            out.prop("signature", ItemHelper.algorithm(context, tbsCertList.signature));
        return out;
    }

    private Item tbsRevokedCertificate(List<TBSRevokedCertificate> list) {

        Item out = new Item();
        int k = 0;
        for (TBSRevokedCertificate i : list)
            out.prop(ItemHelper.index((k++)), tbsCertListSeqItem(i));
        return out;

    }

    /*
      userCertificate         CertificateSerialNumber,
          revocationDate          Time,
          crlEntryExtensions      Extensions OPTIONAL
                                         -- if present, MUST be v2
                               }  OPTIONAL,
     */
    private Item tbsCertListSeqItem(TBSRevokedCertificate i) {
        Item out = new Item();
        if (i.userCertificate != null)
            out.prop("userCertificate", i.userCertificate.getPositiveValue());
        if (i.revocationDate != null)
            out.prop("revocationDate", ASN1Helper.time(i.revocationDate));
        if (i.crlEntryExtensions != null)
            out.prop("crlEntryExtensions", ItemHelper.extensions(context, i.crlEntryExtensions));
        return out;
    }


    public static Object version(Version version) {
        if (version == null) {
            return new TaggedString(0).addTag("v2").addTag("default");
        }

        switch (version.getInt()) {
            case 1:
                return new TaggedString(version.getPositiveValue()).addTag("v2");
        }
        return version.getValue();

    }
}