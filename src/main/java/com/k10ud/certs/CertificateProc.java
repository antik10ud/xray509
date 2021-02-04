
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
import com.k10ud.certs.util.Base64;
import com.k10ud.certs.util.ItemHelper;
import com.k10ud.certs.vuln.DebianWeakKeysVulnerability;
import com.k10ud.certs.vuln.ROCAVulnerability;
import com.k10ud.timestamps.CertificateHelper;
import org.openmuc.jasn1.ber.BerByteArrayOutputStream;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;

import static com.k10ud.certs.util.ASN1Helper.hash;


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
            cert.decode(0, certificate, true);
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
            out.prop(new TaggedString("Version").src(tbs.version), version(tbs.version).src(tbs.version));
            BigInteger serialNumber = tbs.serialNumber.getPositiveValue();
            TaggedString ts = new TaggedString(String.valueOf(serialNumber));
            ts.addTag("hex", "0x" + serialNumber.toString(16));
            ts.addTag("bits", "" + (tbs.serialNumber.getRawValue().length * 8));
            out.prop("SerialNumber", ts.src(tbs.serialNumber));

            out.prop(new TaggedString("Signature").src(tbs.signature), ItemHelper.algorithm(context, tbs.signature));

            out.prop(new TaggedString("Issuer").src(tbs.issuer), ItemHelper.name(context, tbs.issuer)
                    .prop("@dn", dn(tbs.issuer)));

            out.prop(new TaggedString("Subject").src(tbs.subject), ItemHelper.name(context, tbs.subject)
                    .prop("@dn", dn(tbs.subject)));

            out.prop(new TaggedString("Validity").src(tbs.validity), validity(tbs.validity));

            if (tbs.issuerUniqueID != null)
                out.prop("IssuerUniqueID", tbs.issuerUniqueID);

            if (tbs.subjectUniqueID != null)
                out.prop("SubjectUniqueID", tbs.subjectUniqueID);

            out.prop(new TaggedString("SubjectPublicKeyInfo").src(tbs.subjectPublicKeyInfo), subjectPublicKeyInfo(tbs.subjectPublicKeyInfo));
            //.prop("@from", tbs.subjectPublicKeyInfo.from).prop("@to", tbs.subjectPublicKeyInfo.to);

            if (tbs.extensions != null)
                out.prop(new TaggedString("Extensions").src(tbs.extensions), ItemHelper.extensions(context, tbs.extensions));
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

        sec.prop(new TaggedString("CVE-2008-0166").addTag("desc", "Openssl predictable random number generator"),
                DebianWeakKeysVulnerability.isAffected(CertificateHelper.publicKey(cert)));

        sec.prop(new TaggedString("CVE-2017-15361").addTag("desc", "ROCA: Vulnerable RSA generation"),
                ROCAVulnerability.isAffected(CertificateHelper.publicKey(cert)));

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


    private TaggedString version(Version version) {
        Object value;
        String desc = "v1";
        if (version == null) {
            value = "NULL";
        } else {
            value = version.getInt();
            switch (version.getInt()) {
                case 0:
                    desc = "v1";
                    break;
                case 1:
                    desc = "v2";
                    break;
                case 2:
                    desc = "v3";
                    break;
            }
        }
        TaggedString ts = new TaggedString(String.valueOf(value));
        ts.addTag("desc", desc);
        return ts;
    }

    private Item fingerprints(byte[] data) {
        Item out = new Item();

        out.prop("MD5", hash("MD5", data));
        out.prop("SHA1", hash("SHA1", data));
        out.prop("SHA2-256", hash("SHA-256", data));
        out.prop("SHA3-256", hash("SHA3-256", data));

        return out;
    }


    private Item validity(Validity validity) {
        return ItemHelper.validity(validity.notBefore, validity.notAfter);
    }


    private Item subjectPublicKeyInfo(SubjectPublicKeyInfo info) {
        Item out = new Item();
        out.prop("Algorithm", ItemHelper.algorithm(context, info.algorithm));
        try {
            String algOid = info.algorithm.algorithm.toString();
            int keySize = 0;
            Item pk = new Item();
            switch (algOid) {
                case "1.2.840.113549.1.1.1":
                    RSAPublicKey rsapk = new RSAPublicKey();
                    rsapk.decode(info.subjectPublicKey.from, info.subjectPublicKey.value, true);
                    keySize = rsapk.modulus.getPositiveValue().bitLength();
                    pk.prop("modulus", rsapk.modulus.getRawValue());
                    pk.prop("publicExponent", rsapk.publicExponent.getRawValue());

                    //   out.prop(new TaggedString("PublicKey").src(info.subjectPublicKey), pk);
                    //  out.prop("@encoded", info.subjectPublicKey.value);
                    break;
                case "1.2.840.10045.2.1":
                    ECParameters ecparams = new ECParameters();
                    ecparams.decode(info.algorithm.parameters.from, info.algorithm.parameters.value, null);
                    BerByteArrayOutputStream b = new BerByteArrayOutputStream(1000);
                    ecparams.namedCurve.encode(b, false);
                    pk.prop("Named curve", context.nameAndOid(ecparams.namedCurve));
                    ECPoint ecpk = new ECPoint();
                    ecpk.decode(info.subjectPublicKey.from, info.subjectPublicKey.value, false);
                    pk.prop("EC point", ecpk.value);
                    // out.prop(new TaggedString("PublicKey").src(ecpk), eccpk);
                    //System.out.println("");
                    //keySize = ecpk .modulus.getPositiveValue().bitLength();
                    break;
                //https://tools.ietf.org/rfc/rfc5912.txt
            }
            Item fingerPrints = fingerprints(info.subjectPublicKey.value);
            pk.prop("Fingerprints", fingerPrints);
            out.prop(new TaggedString("PublicKey").src(info.subjectPublicKey), pk);


            if (keySize > 0)
                out.prop("Key length", keySize);

        } catch (Exception ignored) {
            ignored.printStackTrace();
        }
        try {
            byte[] data = info.encoded(true);
            Item fingerPrints = fingerprints(data);
            fingerPrints.prop("HPKP PIN-SHA256", Base64.encodeBytes(hash("SHA-256", data)));
            out.prop("Fingerprints", fingerPrints);
        } catch (IOException e) {
            out.prop("Fingerprints", "Unable to calculate");
        }

        return out;
    }


}
