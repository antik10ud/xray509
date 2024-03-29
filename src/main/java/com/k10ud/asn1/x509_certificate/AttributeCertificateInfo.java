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


public class AttributeCertificateInfo  implements Encodedable,Decodeable,SourcePostitionable /*3*/{

public static class Attributes implements Encodedable,Decodeable,SourcePostitionable /*2*/ {

public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
protected BerIdentifier id;

public byte[] code = null; public long from, to;
public List<Attribute> seqOf = null;

public Attributes() {
id = identifier;
seqOf = new ArrayList<Attribute>();
}

public Attributes(byte[] code) {
id = identifier;
this.code = code;
}

public Attributes(List<Attribute> seqOf) {
id = identifier;
this.seqOf = seqOf;
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
for (int i = (seqOf.size() - 1); i >= 0; i--) {
codeLength += seqOf.get(i).encode(os, true);
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

while (subCodeLength < totalLength) {
Attribute element = new Attribute();
subCodeLength += element.decode(is, true);
seqOf.add(element);
}
if (subCodeLength != totalLength) {
throw new IOException("Decoded SequenceOf or SetOf has wrong length. Expected " + totalLength + " but has " + subCodeLength);

}
codeLength += subCodeLength;

this.to=is.getPosition();
return codeLength;
}

public void encodeAndSave(int encodingSizeGuess) throws IOException {
BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
encode(os, false);
code = os.getArray();
}

public String toString() {
StringBuilder sb = new StringBuilder("SEQUENCE OF{");

if (seqOf == null) {
sb.append("null");
}
else {
Iterator<Attribute> it = seqOf.iterator();
if (it.hasNext()) {
sb.append(it.next());
while (it.hasNext()) {
sb.append(", ").append(it.next());
}
}
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

public static final BerIdentifier identifier = new BerIdentifier(BerIdentifier.UNIVERSAL_CLASS, BerIdentifier.CONSTRUCTED, 16);
protected BerIdentifier id;

public byte[] code = null; public long from,to;
public AttCertVersion version = null;

public Holder holder = null;

public AttCertIssuer issuer = null;

public AlgorithmIdentifier signature = null;

public CertificateSerialNumber serialNumber = null;

public AttCertValidityPeriod attrCertValidityPeriod = null;

public Attributes attributes = null;

public UniqueIdentifier issuerUniqueID = null;

public Extensions extensions = null;

public AttributeCertificateInfo() {
id = identifier;
}

public AttributeCertificateInfo(byte[] code) {
id = identifier;
this.code = code;
}

public AttributeCertificateInfo(AttCertVersion version, Holder holder, AttCertIssuer issuer, AlgorithmIdentifier signature, CertificateSerialNumber serialNumber, AttCertValidityPeriod attrCertValidityPeriod, Attributes attributes, UniqueIdentifier issuerUniqueID, Extensions extensions) {
id = identifier;
this.version = version;
this.holder = holder;
this.issuer = issuer;
this.signature = signature;
this.serialNumber = serialNumber;
this.attrCertValidityPeriod = attrCertValidityPeriod;
this.attributes = attributes;
this.issuerUniqueID = issuerUniqueID;
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
if (extensions != null) {
codeLength += extensions.encode(os, true);
}

if (issuerUniqueID != null) {
codeLength += issuerUniqueID.encode(os, true);
}

codeLength += attributes.encode(os, true);

codeLength += attrCertValidityPeriod.encode(os, true);

codeLength += serialNumber.encode(os, true);

codeLength += signature.encode(os, true);

codeLength += issuer.encode(os, true);

codeLength += holder.encode(os, true);

codeLength += version.encode(os, true);

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
if (berIdentifier.equals(AttCertVersion.identifier)) {
version = new AttCertVersion();
subCodeLength += version.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(Holder.identifier)) {
holder = new Holder();
subCodeLength += holder.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

issuer = new AttCertIssuer();
subCodeLength += issuer.decode(is, berIdentifier);
subCodeLength += berIdentifier.decode(is);

if (berIdentifier.equals(AlgorithmIdentifier.identifier)) {
signature = new AlgorithmIdentifier();
subCodeLength += signature.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(CertificateSerialNumber.identifier)) {
serialNumber = new CertificateSerialNumber();
subCodeLength += serialNumber.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(AttCertValidityPeriod.identifier)) {
attrCertValidityPeriod = new AttCertValidityPeriod();
subCodeLength += attrCertValidityPeriod.decode(is, false);
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(Attributes.identifier)) {
attributes = new Attributes();
subCodeLength += attributes.decode(is, false);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}
else {
throw new IOException("Identifier does not match the mandatory sequence element identifer.");
}

if (berIdentifier.equals(UniqueIdentifier.identifier)) {
issuerUniqueID = new UniqueIdentifier();
subCodeLength += issuerUniqueID.decode(is, false);
if (subCodeLength == totalLength) {
this.to=is.getPosition();
return codeLength;
}
subCodeLength += berIdentifier.decode(is);
}

if (berIdentifier.equals(Extensions.identifier)) {
extensions = new Extensions();
subCodeLength += extensions.decode(is, false);
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
sb.append("version: ").append(version);

sb.append(", ");
sb.append("holder: ").append(holder);

sb.append(", ");
sb.append("issuer: ").append(issuer);

sb.append(", ");
sb.append("signature: ").append(signature);

sb.append(", ");
sb.append("serialNumber: ").append(serialNumber);

sb.append(", ");
sb.append("attrCertValidityPeriod: ").append(attrCertValidityPeriod);

sb.append(", ");
sb.append("attributes: ").append(attributes);

if (issuerUniqueID != null) {
sb.append(", ");
sb.append("issuerUniqueID: ").append(issuerUniqueID);
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

