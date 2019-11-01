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
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.ItemHelper;
import com.k10ud.cli.Hasher;
import com.k10ud.cli.SupportedDigest;
import com.k10ud.cli.SupportedSignatureAlg;
import com.k10ud.timestamps.checkprofiles.TSCheckProfile;
import org.openmuc.jasn1.ber.types.BerOctetString;
import org.openmuc.jasn1.ber.types.Util;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Arrays;

import static com.k10ud.certs.util.ASN1Helper.DF_yyyyMMddHHmmssZ;
import static com.k10ud.certs.util.ASN1Helper.DF_yyyyMMddHHmmss_SSSZ;
import static com.k10ud.certs.util.ItemHelper.encoded;


public class TimeStampRespVfer {

    private TSCheckProfile checker;
    private Context context;
    private boolean dump;
    private byte[] tsrBytes;
    private byte[] tsaCertBytes;
    private Hasher hasher;
    private byte[] tsqBytes;
    private ItemChecker out;

    public TimeStampRespVfer(TSCheckProfile checker, Context context, byte[] tsrBytes, byte[] tsaCertBytes, Hasher hasher, byte[] tsqBytes, boolean dump) {
        this.tsrBytes = tsrBytes;
        this.tsaCertBytes = tsaCertBytes;
        this.hasher = hasher;
        this.tsqBytes = tsqBytes;
        this.checker = checker;
        this.context = context;
        this.dump = dump;
    }


    public ItemChecker verify() {
        if (out != null)
            return out;
        out = new ItemChecker();


        if (!out.assertExists("TimeStampResp bytes provided", tsrBytes))
            return out;

        Certificate providedTsaCertificate = null;
        if (tsaCertBytes != null) {
            try {
                providedTsaCertificate = Util.decode(Certificate.class, 0,tsaCertBytes);
                if (dump)
                    out.obs("TSA Certificate", new CertificateProc(context).parse(tsaCertBytes).prop("@encoded",tsaCertBytes));
            } catch (IOException x) {
                out.ioerror("Cannot decode provided TSA certificate: " + x.getMessage());
                return out;
            }
        }

        TimeStampReq timestampReq = null;
        if (tsqBytes != null) {
            try {
                timestampReq = Util.decode(TimeStampReq.class, 0,tsqBytes);
                if (dump)
                    out.obs("TSQ", new TimeStampReqProc(context).parse(0,tsqBytes));
            } catch (IOException x) {
                out.ioerror("Cannot decode TimeStampReq: " + x.getMessage());
                return out;
            }
        }
        if (!out.assertExists("TimeStampResponse provided", tsrBytes)) //- si se suministra se podrá verificar la policy y el nonce
            return out;

        boolean decodeTimeStampResp = true;
        TimeStampResp tsr = new TimeStampResp();
        try {
            tsr.decode(0,tsrBytes, true);
        } catch (IOException e) {
            return out;
        }
        if (dump)
            out.obs("TSR", new TimeStampRespProc(context).parse(0,tsrBytes));

        try {
            out.check(decodeTimeStampResp, "RFC 3161 2.4.2: Decode as TimeStampResp");
            if (decodeTimeStampResp) {

                boolean requireTimestapVerif = false;
                boolean compliantServer = true;
                TimeStampToken tst = tsr.timeStampToken;
                PKIStatusInfo statusInfo = tsr.status;
                if (out.assertExists("RFC 3161 2.4.2: PKIStatusInfo found", statusInfo)) {
                    PKIStatus status = statusInfo.status;
                    if (out.assertExists("RFC 3161 2.4.2: PKIStatus found", status)) {
                        BigInteger statusValue = status.getPositiveValue();
                        boolean valid =
                                (BigInteger.ZERO.compareTo(statusValue) <= 0 ||
                                        BigInteger.valueOf(5).compareTo(statusValue) >= 0);

                        //inconsistencia aqui
                        out.check(valid, "RFC 3161 2.4.2: One of the following values MUST be contained in status: 0,1,2,3,4,5");
                        out.checkShould(valid, "RFC 3161 2.4.2: Compliant servers SHOULD NOT produce any other values");
                        if (!valid) {
                            compliantServer = false;
                        }


                        if (statusValue.intValue() <= 1) {
                            requireTimestapVerif = true;
                            out.check(tst != null, "RFC 3161 2.4.2: When the status contains the value zero or one, a TimeStampToken MUST be present.");
                        } else {
                            requireTimestapVerif = false;
                            out.check(tst == null, "RFC 3161 2.4.2: When status contains a value other than zero or one, a TimeStampToken MUST NOT be present.");
                        }
                    }
                }
                // yesOrNo(requireTimestapVerif, "TimeStampToken verification required");

                if (requireTimestapVerif) {
                    String contentType = tst.contentType == null ? null : tst.contentType.toString();
                    boolean signedDataContent = "1.2.840.113549.1.7.2".equals(contentType);

                    out.check(signedDataContent, "RFC 3161 2.4.2: TimeStampToken [...] is defined as a ContentInfo and SHALL encapsulate a signed data content type");
                    //   byte[] eContentDigest = null;
                    if (signedDataContent) {

                        SignedData signedData = tst.content.as(SignedData.class, true);

                        boolean decodedSignedData = signedData != null;

                        out.check(decodedSignedData, "RFC 3161 2.4.2: TimeStampToken bytes decoded as SignedData");

                        if (decodedSignedData) {

                            EncapsulatedContentInfo encapContentInfo = signedData.encapContentInfo;
                            out.check(encapContentInfo != null, "RFC 3161 2.4.2: EncapsulatedContentInfo found");
                            boolean idctTSTinfo = false;
                            if (encapContentInfo != null) {
                                String type = encapContentInfo.eContentType.toString();
                                idctTSTinfo = "1.2.840.113549.1.9.16.1.4".equals(type);
                                out.check(idctTSTinfo, "RFC 3161 2.4.2: eContentType is the object identifier 1.2.840.113549.1.9.16.1.4");

                            }
                            Certificate signerCertificate = null;
                            GeneralName expectedTSA = null;
                            ZonedDateTime genTime = null;
                            if (idctTSTinfo) {


                                TSTInfo info = signedData.encapContentInfo.eContent.as(TSTInfo.class, true);
                                boolean decodedTSTInfo = info != null;

                                out.check(decodedTSTInfo, "RFC 3161 2.4.2: eContent is the content itself, carried as an octet string");

                                boolean isDerEncoded = false;

                                if (decodedTSTInfo) {
                                    isDerEncoded = Arrays.equals(signedData.encapContentInfo.eContent.getRaw(), signedData.encapContentInfo.eContent.encoded());
                                    out.check(isDerEncoded, "RFC 3161 2.4.2: The eContent SHALL be the DER-encoded value of TSTInfo");

                                    {
                                        String message = "MessageImprint has the same value as the data hash";
                                        if (hasher != null) {
                                            out.check(Arrays.equals(info.messageImprint.hashedMessage.value, hasher.hash(SupportedDigest.forValue(info.messageImprint.hashAlgorithm))), message);
                                            //todo(message);
                                        } else {
                                            out.ignored(message, "No data provided");
                                        }
                                    }

                                    {
                                        String msg = "RFC 3161 2.4.2: The messageImprint MUST have the same value as the similar field in TimeStampReq";
                                        if (timestampReq != null) {
                                            out.check(Arrays.equals(timestampReq.messageImprint.hashedMessage.value, info.messageImprint.hashedMessage.value), msg);

                                        } else {
                                            out.ignored(msg + ". No TimestampRequest provided");
                                        }
                                    }
                                    {
                                        out.check(info.policy != null, "RFC 3161 2.4.2: The policy field MUST indicate the TSA's policy under which the response was produced");

                                        String msg = "RFC 3161 2.4.2: If a policy field was present in th TimeStampReq, then it MUST have the same value";

                                        //otherwise an error (unacceptedPolicy) MUST be returned
                                        if (timestampReq != null) {
                                            if (timestampReq.reqPolicy == null)
                                                out.ok(msg, "TimeStampReq doesn't include TSA policy");
                                            else {
                                                String reqPolicy = timestampReq.reqPolicy == null ? "" : timestampReq.reqPolicy.toString();
                                                String infoPolicy = info.policy == null ? "" : info.policy.toString();
                                                out.check(reqPolicy.equals(infoPolicy), msg);
                                            }
                                        } else {
                                            out.ignored(msg, "No TimeStampReq provided");
                                        }
                                    }

                                }


                                out.check(info.version != null && BigInteger.ONE.equals(info.version.getPositiveValue()), "RFC 3161 2.4.2: Conforming time-stamping servers MUST be able to provide version 1 time-stamp tokens");


                                {
                                    String msg1 = "RFC 3161 2.4.2: The nonce field MUST be present if it was present in the TimeStampReq";
                                    String msg2 = "RFC 3161 2.4.2: The nonce field MUST be equal to the value provided in the TimeStampReq";
                                    if (timestampReq == null) {
                                        out.ignored(msg1, "No TimeStampReq provided");
                                        out.ignored(msg2, "No TimeStampReq provided");
                                    } else {
                                        BigInteger nonce = timestampReq.nonce.getValue();
                                        out.check(nonce == null || info.nonce != null, msg1);
                                        out.check(nonce == null || (info.nonce != null && nonce.equals(info.nonce.getValue())), msg2);
                                    }
                                }

                                boolean betterPrecisionThanTheSecond =
                                        TSTInfoHelper.accurancyNanos(info.accuracy) < 1000_000_000;

                                //genTime = ;
                                if (info.genTime == null)
                                    out.fail("No genTime found");
                                else {
                                    String time = ASN1Helper.toString(info.genTime.value);
                                    // -- The decimal point element, if present, MUST be the point option "."
                                    //Pattern.compile("YYYYMMDDhhmmss[.s...]Z");
                                    boolean hasFractionalSeconds = time.length() >= 14 && time.indexOf('.') == 14;

                                    if (hasFractionalSeconds && !betterPrecisionThanTheSecond)
                                        out.should("RFC 3161 2.4.2: genTime GeneralizedTime with a precision limited to one second SHOULD be used", "No precision better than the second");

                                    boolean z = time.endsWith("Z");
                                    out.check(z, "RFC 3161 2.4.2: The genTime encoding MUST terminate with a Z");
                                    SimpleDateFormat dateF;
                                    if (z) {
                                        if (hasFractionalSeconds)
                                            dateF = DF_yyyyMMddHHmmss_SSSZ;
                                        else
                                            dateF = DF_yyyyMMddHHmmssZ;
                                        if (hasFractionalSeconds) {
                                            // java misinterprets extra digits as being milliseconds...
                                            String frac = time.substring(14);

                                            out.check(!frac.endsWith("0"), "The genTime fractional-seconds elements, if present, MUST omit all trailing 0's");


                                            int index;
                                            for (index = 1; index < frac.length(); index++) {
                                                char ch = frac.charAt(index);
                                                if (!('0' <= ch && ch <= '9'))
                                                    break;
                                            }
                                            if (index - 1 > 3) {
                                                frac = frac.substring(0, 4) + frac.substring(index);
                                                time = time.substring(0, 14) + frac;
                                            } else if (index - 1 == 1) {
                                                frac = frac.substring(0, index) + "00" + frac.substring(index);
                                                time = time.substring(0, 14) + frac;
                                            } else if (index - 1 == 2) {
                                                frac = frac.substring(0, index) + "0" + frac.substring(index);
                                                time = time.substring(0, 14) + frac;
                                            }
                                        }
                                        try {
                                            genTime = ZonedDateTime.from(dateF.parse(time).toInstant().atZone(ZoneOffset.UTC));
                                            out.ok("GenTime parsed correctly");

                                        } catch (ParseException e) {
                                            out.fail("Cannot parse the genTime");
                                        }
//-- Midnight (GMT) shall be represented in the form: "YYYYMMDD000000Z"

                                    }

                                    if (info.tsa != null) {
                                        expectedTSA = info.tsa;
                                        //  System.out.println("...");
                                    }
                                }

                            }


                            boolean oneSignature = signedData.signerInfos.seqOf.size() == 1;
                            out.check(oneSignature, "RFC 3161 2.4.2: The time-stamp token MUST NOT contain any signatures other than the signature of the TSA");


                            if (oneSignature) {
                                //RFC 5652 5.4.  Message Digest Calculation Process

                                SignerInfo signerInfo = signedData.signerInfos.seqOf.get(0);


                                SigningCertificateWrangler scw = null;

/*boolean
Note: As mentioned in RFC 5035 [ESSV2], the SigningCertificateV2
            attribute MUST be used if any algorithm other than SHA-1 is
            used and SHOULD NOT be used for SHA-1.

      Note: For backwards compatibility, in line with RFC 5035, both
            ESSCertID and ESSCertIDv2 MAY be present.  Systems MAY
            ignore ESSCertIDv2 if RFC 5035 has not been implemented.
 */
                                int k = 0;
                                ZonedDateTime signingTime = null;
                                byte[] singedAttrMessageDigest = null;
                                for (Attribute i : signerInfo.signedAttrs.seqOf) {
                                    String s = i.attrType.toString();
                                    SigningCertificateWrangler scw2 = null;

                                    switch (s) {
                                        case "1.2.840.113549.1.9.16.2.12": {
                                            SigningCertificate sc = Util.decodeAny(SigningCertificate.class, i.attrValues.from, i.attrValues.encodedImplicit());
                                            scw2 = new SigningCertificateWrangler("SigningCertificate" + ItemHelper.index(k), sc);
                                        }

                                        break;
                                        case "1.2.840.113549.1.9.16.2.47":

                                        {
                                            SigningCertificateV2 sc = Util.decodeAny(SigningCertificateV2.class, i.attrValues.from, i.attrValues.encodedImplicit());
                                            scw2 = new SigningCertificateWrangler("SigningCertificateV2" + ItemHelper.index(k), sc);

                                        }
                                        break;
                                        case "1.2.840.113549.1.9.5":
                                            signingTime = ASN1Helper.time(Util.decodeAny(Time.class,  i.attrValues.from,i.attrValues.encodedImplicit()));
                                            //todo: check signing time is gentime!!
                                            //out = signingTime(a);
                                            break;
                                        case "1.2.840.113549.1.9.52":
                                            //TODO: get CMS protection data and verify!
                                            //out = cmsapa(a);
                                            break;
                                        case "1.2.840.113549.1.9.3":
                                            //out = contentType(a);
                                            break;
                                        case "1.2.840.113549.1.9.4":
                                            singedAttrMessageDigest = Util.decodeAny(BerOctetString.class,  i.attrValues.from,i.attrValues.encodedImplicit()).value;//!!
                                        default:
                                            // out = new AttrProc(context).parse(a);
                                    }
                                    if (scw2 != null) {
                                        if (scw == null)
                                            scw = scw2;
                                        else
                                            out.check(scw.isEquivalent(scw2), "SigningCertificate " + scw2.getOrigin() + " is equivalent to " + scw.getOrigin());
                                    }
                                    k++;
                                }

                                //The content-type attribute type MUST be present whenever signed attributes are present in signed-data
                                //Only one instance of a cmsAlgorithmProtect attribute can be present
                                //A cmsAlgorithmProtect attribute MUST contain exactly one value
                                //CMS Algorithm Identifier Protection check failed for digestAlgorithm
                                //CMS Algorithm Identifier Protection check failed for signatureAlgorithm
                                //the message-digest signed attribute type MUST be present when there are any signed attributes present
// If the SignedData signerInfo includes signedAttributes, then the content-type attribute value MUST match the SignedData encapContentInfo eContentType value.
                          /*      the SignedData signerInfo includes signedAttributes, then the
                                content-type attribute value MUST match the SignedData
                                encapContentInfo eContentType value
                                        */
                                out.check(singedAttrMessageDigest != null, "signed Attr Message Digest found");
                                out.check(scw != null, "SigningCertificate found");
                                out.checkShould(signingTime != null, "SigningTime found");
                                if (signingTime != null) {
                                    out.check(signingTime.equals(genTime), "SigningTime match genTime");

                                }


                                if (timestampReq == null || (timestampReq.certReq != null && timestampReq.certReq.value)) {
                                    if (signedData.certificates != null)
                                        for (CertificateChoices i : signedData.certificates.seqOf) {
                                            if (i.certificate != null) {
                                                if (scw.indetifies(i.certificate))
                                                    signerCertificate = i.certificate;
                                            } else if (i.extendedCertificate != null) {
                                                if (scw.indetifies(i.extendedCertificate.extendedCertificateInfo.certificate))
                                                    signerCertificate = i.extendedCertificate.extendedCertificateInfo.certificate;
                                            } else if (i.v1AttrCert != null) {
                                                out.todo("Unssuported certificate v1AttrCert ");
                                            } else if (i.v2AttrCert != null) {
                                                out.todo("Unssuported certificate v2AttrCert ");
                                            } else if (i.other != null) {
                                                out.todo("Unssuported certificate other ");
                                            }
                                        }

                                    out.check(signerCertificate != null, "The TSA's public key certificate that is referenced by the CertID identifier MUST be provided by SignedData certificates");

                                    if (expectedTSA != null) {
                                        out.check(signerCertificate != null &&
                                                CertificateHelper.hasAnySubjectName(expectedTSA, signerCertificate), "Name of the TSA MUST correspond to one of the subject names included in the certificate that is to be used to verify the token");
                                    }

                                }

                                if (timestampReq != null && (timestampReq.certReq == null || !timestampReq.certReq.value)) {
                                    out.check(signedData.certificates == null, "If the certReq field is missing or if the certReq field is present and set to false then the certificates field from the SignedData structure MUST not be present in the response");
                                }

                                if (signerCertificate != null && providedTsaCertificate != null) {
                                    out.check(Arrays.equals(signerCertificate.encoded(), providedTsaCertificate.encoded()), "Provider certificate match signer certificate");
                                } else if (providedTsaCertificate != null) {
                                    signerCertificate = providedTsaCertificate;
                                }

                                out.check(signerCertificate != null, "Can determine signer certificate");


                                if (signerCertificate != null) {

                                    boolean hasSignedAttrs = signerInfo.signedAttrs != null;

//check CMS protection

                                    byte[] contentHash;
                                    {
                                        MessageDigest x = SupportedDigest.forValue(signerInfo.digestAlgorithm).newMessageDigest();
                                        x.update(signedData.encapContentInfo.eContent.value);
                                        contentHash = x.digest();
                                    }
                                    byte[] dtbs;
                                    if (hasSignedAttrs) {
                                        MessageDigest x = SupportedDigest.forValue(signerInfo.digestAlgorithm).newMessageDigest();
                                        x.update(signerInfo.signedAttrs.encoded());
                                        dtbs = x.digest();
                                        //System.out.println("318201ab301a06092a864886f70d010903310d060b2a864886f70d0109100104301c06092a864886f70d010905310f170d3137313032343130343435325a302d06092a864886f70d0109343120301e300d06096086480165030402010500a10d06092a864886f70d0101010500302f06092a864886f70d0109043122042068ff55e2cf57e6db65f34b7250c3c87d01a09b7eab822e1205f64be4a5b2759e3082010d060b2a864886f70d010910022f3181fd3081fa3081f73081f404207507abd1b0a570c3e2683de6af62c85202e250314a6847f192748256ae76347a3081cf3081c2a481bf3081bc310b30090603550406130245533111300f060355040713085a415241474f5a4131363034060355040a132d45535055424c49434f20534552564943494f532050415241204c412041444d494e495354524143494f4e20534131323030060355040b13294155544f52494441442044452043455254494649434143494f4e2045534649524d41202d20414150503112301006035504051309413530383738383432311a30180603550403131145534649524d412041432041415050203202084f29548aece85a87");
                                        //  System.out.println(ASN1Helper.bytesToHex(signerInfo.signedAttrs.encoded(),""));

/*
                                        MessageDigest x = SupportedDigest.forValue(signerInfo.digestAlgorithm).newMessageDigest();
                                        BerByteArrayOutputStream bbo = new BerByteArrayOutputStream(1000, true);
                                        List<Attribute> seqOf = signerInfo.signedAttrs.seqOf;
                                        int codeLength = 0;
                                        for (int i1 = seqOf.size() - 1; i1 >= 0; i1--) {
                                            Attribute i = seqOf.get(i1);
                                            codeLength += i.encode(bbo, true);
                                        }
                                        codeLength += BerLength.encodeLength(bbo, codeLength);
                                        codeLength += new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 17).encode(bbo);
                                        System.out.println(Base64.encodeBytes(bbo.getArray()));
                                        System.out.println("--");
                                        System.out.println(Base64.encodeBytes(tsrBytes));

                                        x.update(bbo.getArray());
                                        dtbs = x.digest();
*/
                                    } else {
                                        dtbs = contentHash;
                                    }

                                    if (!out.check(Arrays.equals(singedAttrMessageDigest, contentHash), "message-digest attribute value match calculated value")) {
                                        out.debug("calculated digest", contentHash);
                                        out.debug("expected digest  ", singedAttrMessageDigest);
                                    }

                                    byte[] signature = signerInfo.signature.value;

                                    PublicKey pk = CertificateHelper.publicKey(signerCertificate);
                                   /* System.out.println(
"30820222300d06092a864886f70d01010105000382020f003082020a0282020100a5e7d3d0bec32b9e436683be017e4bae1778bb6127c177d15c6c9ffb9d605a3194ee6f1a4d191cb14360c53fd91882661c817428694bd7924aceedb6c091b9c04a7675d050dbeaf4476656491bd0980e89f1a98d60189e8194c96821237c5b1b8a925dc01fe3e56f4bb2995cab7cf71ff55520090c438bd67cb05917700ffc337684b9a6ed2ea33b0423a26eeaef1331e821c8ad970f4d9a595ed47d097fc6956233a74802cdb0b8e58af4af22e08b0133092cb58ce9f754cac923dd28a524425e2bf30903f0bb199a3ba7cba78b5dfb745e02d0a4a1a448d62b87b902a7761332282b5f02ba28ac97b287bf8092e39a94471087de6e3b999bb184ab9998b9de182fc509e3dbfd4ee049454aeafee4433df0c4753b0750cde0e7c851eddd5defba50096850429edc34438bb311f717ab01a0466053fa018fb8b2118737a73d8451e80f0c3c3f7736b747dd0712bcddd1930f52dd615e0e8331f063f269e5f7867247c02feb940ab89ee62e243ec07657f2b1cd02b6372c6b1563e0a6eec188063177968692db31559ea64721f00190a84149f96609bc151fa0ecbd556b8874b7c85faa10b02fe07a998d8fa440da67df19c121f3e08c64d0152aa1693ab828680fdf7ef55243bb1cb0a5537049a93db026c1b514edb6fe9d8e9cec3cfb901a93c6174914603b7cfe3ba8fdb22663c33942c952a33d9a2437b961c391401876ed0203010001"
        .equals(ASN1Helper.bytesToHex(pk.getEncoded(),"")
        ));*/
                                    out.check(pk != null, "It's a supported public key");

                                    String msg = "Signature verified";
                                    boolean validsig = false;
                                    try {
                                        //raw sign verification!
                                        java.security.Signature signat = SupportedSignatureAlg.forValue(signerInfo.signatureAlgorithm, signerInfo.digestAlgorithm).getSignature();
                                        try {
                                            signat.initVerify(pk);
                                            signat.update(signerInfo.signedAttrs.encoded());
                                            validsig = signat.verify(signature);
                                            out.check(validsig, msg);
                                        } catch (Exception e) {
                                            out.fail(msg, e.getMessage());
                                        }
                                    } catch (Exception e) {
                                        out.fail(msg, "Unsupported algorithm " + signerInfo.signatureAlgorithm);
                                    }
                                    if (!validsig) {
                                        out.debug("signerCertificate", certId(signerCertificate));
                                    }

                                    verifyTSCert(signerCertificate,genTime);
                                }
                            }




                            //ignored("The serialNumber MUST be unique for each TimeStampToken issued by a given TSA");
                        }
                    }
                }
            }

        } catch (
                IOException x)

        {
            x.printStackTrace();
            out.ioerror(x.getMessage());
        }
        out.todo("The TSA's certificate revocation status of the certificate SHOULD be checked");

        return out;
    }

    private void verifyTSCert(Certificate c, ZonedDateTime genTime) {
    //c.tbsCertificate.extensions.
        //basic certificate validation -- range times
        //Certificate must have an ExtendedKeyUsage extension
        // Certificate must have an ExtendedKeyUsage extension marked as critical
        // "ExtendedKeyUsage not solely time stamping.

        ZonedDateTime notAfter = ASN1Helper.time(c.tbsCertificate.validity.notAfter);
        ZonedDateTime notBefore = ASN1Helper.time(c.tbsCertificate.validity.notBefore);
        out.check(!genTime.isBefore(notBefore) && !genTime.isAfter(notAfter),"Certificate validity is en genTime range");

    }

    private static Item certId(Certificate signerCertificate) {
        Item out = new Item();
        out.prop("subject",
                ASN1Helper.name(signerCertificate.tbsCertificate.subject));
        out.prop("serial",
                signerCertificate.tbsCertificate.serialNumber.getPositiveValue());
        out.prop("issuer",
                ASN1Helper.name(signerCertificate.tbsCertificate.issuer));
        return out;
    }


}