
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

package com.k10ud.certs;

import com.k10ud.asn1.x509_certificate.*;
import com.k10ud.certs.util.ItemHelper;
import com.k10ud.certs.vuln.DebianWeakKeysVulnerability;
import com.k10ud.certs.vuln.ROCAVulnerability;
import com.k10ud.timestamps.CertificateHelper;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;

import static com.k10ud.certs.util.ASN1Helper.bytesToHex;
import static com.k10ud.certs.util.ASN1Helper.hash;
import static com.k10ud.certs.util.ItemHelper.encoded;


public class CertificateProc {
    private final Context context;

    public CertificateProc(Context context) {
        this.context = context;
    }

    public Item parse(byte[] certificate) {
        Item out = new Item();
        if (certificate == null)
            return out.prop("No Data");
        Certificate cert = new Certificate();
        try {
            cert.decode(0,certificate, true);
        } catch (IOException e) {
            out.prop("Unable to process data as Certificate", e);
            out.prop("Raw Value", ItemHelper.xprint(certificate));
            return out;
        }
        return parse(cert);
    }

    public Item parse(Certificate cert) {
        Item out = new Item();
        TBSCertificate tbs = cert.tbsCertificate;
        if (tbs != null) {
            out.prop("Version", version(tbs.version));
            BigInteger serialNumber = tbs.serialNumber.getPositiveValue();
            TaggedString ts = new TaggedString(serialNumber);
            ts.addTag("hex", "0x"+serialNumber.toString(16));
            ts.addTag("bits", "" + (tbs.serialNumber.getRawValue().length * 8));
            out.prop("SerialNumber", ts);

            out.prop("Signature", ItemHelper.algorithm( context,tbs.signature)
                    .src(tbs.signature));

            out.prop("Issuer", ItemHelper.name(context, tbs.issuer)
                    .src(tbs.issuer)
                    .prop("@encoded", encoded(tbs.issuer))
                    .prop("@dn", dn(tbs.issuer)));

            out.prop("Subject", ItemHelper.name(context, tbs.subject)
                    .src(tbs.subject)
                    .prop("@encoded", encoded(tbs.subject))
                    .prop("@dn", dn(tbs.subject)));

            out.prop("Validity", validity(tbs.validity).src(tbs.validity));
            if (tbs.issuerUniqueID != null)
                out.prop("IssuerUniqueID",  tbs.issuerUniqueID);
            if (tbs.subjectUniqueID != null)
                out.prop("SubjectUniqueID", tbs.subjectUniqueID);
            out.prop("SubjectPublicKeyInfo", subjectPublicKeyInfo(tbs.subjectPublicKeyInfo));
            if (tbs.extensions != null)
                out.prop("Extensions", ItemHelper.extensions(context, tbs.extensions).src(tbs.extensions));
        } else {
            out.prop("tbsCertificate", "Not Found!");
        }
        try {
            BerByteArrayOutputStream o = new BerByteArrayOutputStream(8192);
            cert.encode(o, true);
            out.prop("Fingerprints", fingerprints(o.getArray()));
        } catch (IOException e) {
            out.prop("Fingerprints", "Unable to calculate");
        }
        Item sec = new Item();

        sec.prop(new TaggedString("CVE-2008-0166")
                        .addTag("Openssl predictable random number generator"),
                new TaggedString(DebianWeakKeysVulnerability.isAffected(CertificateHelper.publicKey(cert))).addTag("synthetic"));

        sec.prop(new TaggedString("CVE-2017-15361")
                        .addTag("ROCA: Vulnerable RSA generation"),
                new TaggedString(ROCAVulnerability.isAffected(CertificateHelper.publicKey(cert))).addTag("synthetic"));

        out.prop("Security", sec);


        Item tlinfo = context.trustedListInfo(cert.code);
        if (tlinfo != null)
            out.prop("Trusted List Info", tlinfo);

        return out;
    }


    private String dn(Name name) {
        try {
            return new X500Principal(name.encoded(false)).getName(X500Principal.RFC2253);
        } catch (IOException e) {
            return "Cannot encode dn";
        }
    }


    private Object version(Version version) {
        if (version == null)
            return "v1";
        switch (version.getInt()) {
            case 0:
                return "v1";
            case 1:
                return "v2";
            case 2:
                return "v3";
        }
        return version;
    }

    private Item fingerprints(byte[] cert) {
        Item out = new Item();
        out.prop("MD5", new TaggedString(hash("MD5", cert)).addTag("synthetic"));
        out.prop("SHA1", new TaggedString(hash("SHA1", cert)).addTag("synthetic"));
        out.prop("SHA2-256", new TaggedString(hash("SHA-256", cert)).addTag("synthetic"));
        out.prop("SHA3-256", new TaggedString(hash("SHA3-256", cert)).addTag("synthetic"));

        return out;
    }


    private Item validity(Validity validity) {
        return ItemHelper.validity(validity.notBefore, validity.notAfter);
    }


    private Item subjectPublicKeyInfo(SubjectPublicKeyInfo info) {
        Item out = new Item();
        out.prop("Algorithm", context.algorithm(info.algorithm));
        try {
            String algOid = info.algorithm.algorithm.toString();
            int keySize = 0;
            switch (algOid) {
                case "1.2.840.113549.1.1.1":
                    RSAPublicKey rsapk = new RSAPublicKey();
                    rsapk.decode(info.subjectPublicKey.from,info.subjectPublicKey.value, true);
                    keySize = rsapk.modulus.getPositiveValue().bitLength();
                    out.prop("modulus", rsapk.modulus.getRawValue());
                    out.prop("publicExponent", rsapk.publicExponent.getRawValue());
                    out.prop("@encoded", info.subjectPublicKey.value);
                    break;
                case "1.2.840.10045.2.1":
                    ECParameters ecparams=new ECParameters();
                    ecparams.decode(info.algorithm.parameters.from,info.algorithm.parameters.value, null);
                    BerByteArrayOutputStream b = new BerByteArrayOutputStream(1000);
                    ecparams.namedCurve.encode(b,false);

                   // System.out.println(bytesToHex(b.getArray(),":"));
                    out.prop("Named curve",  context.nameAndOid(ecparams.namedCurve));
                    //paramsOut.prop("modulus", rsapk.modulus.getRawValue());
                    //paramsOut.prop("publicExponent", rsapk.publicExponent.getRawValue());
                    //paramsOut.prop("@encoded", info.subjectPublicKey.value);

                    ECPoint ecpk = new ECPoint();

                    ecpk.decode(info.subjectPublicKey.from,info.subjectPublicKey.value, false);
                    out.prop("EC point",  ecpk.value);
                    //System.out.println("");
                    //keySize = ecpk .modulus.getPositiveValue().bitLength();
                    break;
                //https://tools.ietf.org/rfc/rfc5912.txt
            }
            if (keySize > 0)
                out.prop("Key length", keySize);

        } catch (Exception ignored) {
            ignored.printStackTrace();
        }
        out.prop("SHA1", new TaggedString(hash("SHA1", info.subjectPublicKey.value)).addTag("synthetic"));
        out.prop("SHA2-256", new TaggedString(hash("SHA-256", info.subjectPublicKey.value)).addTag("synthetic"));
        out.prop("SHA3-256", new TaggedString(hash("SHA3-256", info.subjectPublicKey.value)).addTag("synthetic"));

        return out;
    }


}
