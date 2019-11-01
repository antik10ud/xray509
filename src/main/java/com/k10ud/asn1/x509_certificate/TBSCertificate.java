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

/**
 * This class file was automatically generated by jASN1 v1.6.0 (http://www.openmuc.org)
 */

package com.k10ud.asn1.x509_certificate;

import java.io.IOException;
import java.io.EOFException;
import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.util.List;
import java.util.ArrayList;
import java.util.Iterator;
import java.io.UnsupportedEncodingException;
import org.openmuc.jasn1.ber.*;
import org.openmuc.jasn1.ber.types.*;
import org.openmuc.jasn1.ber.types.string.*;


public class TBSCertificate  implements Encodedable,Decodeable,SourcePostitionable /*3*/{

public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
protected BerIdentifier id;

public byte[] code = null; public long from,to;
public Version version = null;

public CertificateSerialNumber serialNumber = null;

public AlgorithmIdentifier signature = null;

public Name issuer = null;

public Validity validity = null;

public Name subject = null;

public SubjectPublicKeyInfo subjectPublicKeyInfo = null;

public UniqueIdentifier issuerUniqueID = null;

public UniqueIdentifier subjectUniqueID = null;

public Extensions extensions = null;

public TBSCertificate() {
id = identifier;
}

public TBSCertificate(byte[] code) {
id = identifier;
this.code = code;
}

public TBSCertificate(Version version, CertificateSerialNumber serialNumber, AlgorithmIdentifier signature, Name issuer, Validity validity, Name subject, SubjectPublicKeyInfo subjectPublicKeyInfo, UniqueIdentifier issuerUniqueID, UniqueIdentifier subjectUniqueID, Extensions extensions) {
id = identifier;
this.version = version;
this.serialNumber = serialNumber;
this.signature = signature;
this.issuer = issuer;
this.validity = validity;
this.subject = subject;
this.subjectPublicKeyInfo = subjectPublicKeyInfo;
this.issuerUniqueID = issuerUniqueID;
this.subjectUniqueID = subjectUniqueID;
this.extensions = extensions;
}

public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {

int codeLength;

if (code != null) {
codeLength = code.length;
for (int i = code.length - 1; i >= 0; i--) {
os.write(code[i]);
}
}
else {
codeLength = 0;
int sublength;

if (extensions != null) {
sublength = extensions.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 3
os.write(0xa3);
codeLength += 1;
}

if (subjectUniqueID != null) {
codeLength += subjectUniqueID.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 2
os.write(0x82);
codeLength += 1;
}

if (issuerUniqueID != null) {
codeLength += issuerUniqueID.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 1
os.write(0x81);
codeLength += 1;
}

codeLength += subjectPublicKeyInfo.encode(os, true);

codeLength += subject.encode(os, true);

codeLength += validity.encode(os, true);

codeLength += issuer.encode(os, true);

codeLength += signature.encode(os, true);

codeLength += serialNumber.encode(os, true);

if (version != null) {
sublength = version.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 0
os.write(0xa0);
codeLength += 1;
}

codeLength += BerLength.encodeLength(os, codeLength);
}

if (explicit) {
codeLength += id.encode(os);
}

return codeLength;
}

public int decode(long sourceOffset,byte[] bytes, boolean explicit) throws IOException {
return decode(new CountingInputStream(sourceOffset,new ByteArrayInputStream(bytes)), explicit);

}
public int decode(CountingInputStream is, boolean explicit) throws IOException {
int codeLength = 0;
this.from=is.getPosition();
int subCodeLength = 0;
BerIdentifier berIdentifier = new BerIdentifier();

if (explicit) {
codeLength += id.decodeAndCheck(is);
}

BerLength length = new BerLength();
codeLength += length.decode(is);

int totalLength = length.val;
codeLength += totalLength;

subCodeLength += berIdentifier.decode(is);
if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 0)) {
subCodeLength += length.decode(is);
version = new Version();
subCodeLength += version.decode(is, true);
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(CertificateSerialNumber.identifier)) {
serialNumber = new CertificateSerialNumber();
subCodeLength += serialNumber.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(AlgorithmIdentifier.identifier)) {
signature = new AlgorithmIdentifier();
subCodeLength += signature.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

issuer = new Name();
subCodeLength += issuer.decode(is, berIdentifier);
subCodeLength += berIdentifier.decode(is);

if (berIdentifier.equals(Validity.identifier)) {
validity = new Validity();
subCodeLength += validity.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

subject = new Name();
subCodeLength += subject.decode(is, berIdentifier);
subCodeLength += berIdentifier.decode(is);

if (berIdentifier.equals(SubjectPublicKeyInfo.identifier)) {
subjectPublicKeyInfo = new SubjectPublicKeyInfo();
subCodeLength += subjectPublicKeyInfo.decode(is, false);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 1)) {
issuerUniqueID = new UniqueIdentifier();
subCodeLength += issuerUniqueID.decode(is, false);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 2)) {
subjectUniqueID = new UniqueIdentifier();
subCodeLength += subjectUniqueID.decode(is, false);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 3)) {
subCodeLength += length.decode(is);
extensions = new Extensions();
subCodeLength += extensions.decode(is, true);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
}
throw new IOException("Unexpected end of sequence, length tag: " + totalLength + ", actual sequence length: " + subCodeLength);


}

public void encodeAndSave(int encodingSizeGuess) throws IOException {
BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
encode(os, false);
code = os.getArray();
}

public String toString() {
StringBuilder sb = new StringBuilder("SEQUENCE{");
boolean firstSelectedElement = true;
if (version != null) {
sb.append("version: ").append(version);
firstSelectedElement = false;
}

if (!firstSelectedElement) {
sb.append(", ");
}
sb.append("serialNumber: ").append(serialNumber);

sb.append(", ");
sb.append("signature: ").append(signature);

sb.append(", ");
sb.append("issuer: ").append(issuer);

sb.append(", ");
sb.append("validity: ").append(validity);

sb.append(", ");
sb.append("subject: ").append(subject);

sb.append(", ");
sb.append("subjectPublicKeyInfo: ").append(subjectPublicKeyInfo);

if (issuerUniqueID != null) {
sb.append(", ");
sb.append("issuerUniqueID: ").append(issuerUniqueID);
}

if (subjectUniqueID != null) {
sb.append(", ");
sb.append("subjectUniqueID: ").append(subjectUniqueID);
}

if (extensions != null) {
sb.append(", ");
sb.append("extensions: ").append(extensions);
}

sb.append("}");
return sb.toString();
}

@Override

 public long getFrom() {

     return from;

}

@Override

public long getTo() {

    return to;

}

}
