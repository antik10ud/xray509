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

import com.k10ud.asn1.x509_certificate.OCSPCertRequest;
import com.k10ud.asn1.x509_certificate.OCSPRequest;
import com.k10ud.asn1.x509_certificate.OCSPRequestSignature;
import com.k10ud.asn1.x509_certificate.OCSPTBSRequest;
import com.k10ud.certs.Context;
import com.k10ud.certs.Item;
import com.k10ud.certs.util.ItemHelper;

import java.io.IOException;
import java.util.List;


public class OCSPReqProc {

    private final Context context;

    public OCSPReqProc(Context context) {
        this.context = context;
    }

    public Item parse(byte[] ocspReq) {
        Item out = new Item();
        if (ocspReq == null)
            return out.prop("No Data");

        OCSPRequest ocspq = new OCSPRequest();
        try {
            ocspq.decode(0,ocspReq, true);
        } catch (IOException e) {
            out.prop("Unable to process data as OCSPRequest", e);
            out.prop("Raw Value", ItemHelper.xprint(ocspReq));
            return out;
        }


        if (ocspq.tbsRequest != null)
            out.prop("tbsRequest", tbsRequest(ocspq.tbsRequest));
        if (ocspq.optionalSignature != null)
            out.prop("optionalSignature", optionalSignature(ocspq.optionalSignature));

        return out;

    }

    /*
    Signature       ::=     SEQUENCE {
    signatureAlgorithm   AlgorithmIdentifier,
    signature            BIT STRING,
    certs                [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }

     */
    private Item optionalSignature(OCSPRequestSignature s) {
        Item out = new Item();

        if (s.signatureAlgorithm != null)
            out.prop("signatureAlgorithm", ItemHelper.algorithm(context, s.signatureAlgorithm));
        if (s.signature != null)
            out.prop("signature", s.signature.value);
        if (s.certs != null)
            out.prop("certs", OCSPItem.certs(context, s.certs.seqOf));

        return out;
    }


/*
OCSPRequest     ::=     SEQUENCE {
    tbsRequest                  TBSRequest,
    optionalSignature   [0]     EXPLICIT Signature OPTIONAL }

TBSRequest      ::=     SEQUENCE {
    version             [0] EXPLICIT Version DEFAULT v1,
    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
    requestList             SEQUENCE OF Request,
    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }


 */

    private Item tbsRequest(OCSPTBSRequest tbs) {
        Item out = new Item();
        if (tbs.version != null)
            out.prop("version", OCSPItem.version(tbs.version));
        if (tbs.requestorName != null)
            out.prop("requestorName", ItemHelper.generalName(context, tbs.requestorName));
        if (tbs.requestList != null)
            out.prop("requestList", requests(tbs.requestList.seqOf));
        if (tbs.requestExtensions != null)
            out.prop("requestExtensions", OCSPItem.extensions(context, tbs.requestExtensions.seqOf));

        return out;
    }

    private Item requests(List<OCSPCertRequest> list) {
        int i = 0;
        Item item = new Item();
        for (OCSPCertRequest e : list) {
            i++;
            item.prop(ItemHelper.index( i), request(e));
        }
        return item;
    }

    /*
    Request ::=     SEQUENCE {
    reqCert                    CertID,
    singleRequestExtensions    [0] EXPLICIT Extensions OPTIONAL }
*/
    private Item request(OCSPCertRequest e) {
        if (e == null)
            return null;
        Item out = new Item();
        if (e.reqCert != null)
            out.prop("reqCert", OCSPItem.certId(context, e.reqCert));
        return out;
    }


}