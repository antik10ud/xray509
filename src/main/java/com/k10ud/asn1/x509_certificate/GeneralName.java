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


public class GeneralName implements Encodedable,Decodeable,SourcePostitionable /*1*/ {

public byte[] code = null; public long from,to;
public AnotherName otherName = null;

public BerIA5String rfc822Name = null;

public BerIA5String dNSName = null;

public ORAddress x400Address = null;

public Name directoryName = null;

public EDIPartyName ediPartyName = null;

public BerIA5String uniformResourceIdentifier = null;

public BerOctetString iPAddress = null;

public BerObjectIdentifier registeredID = null;

public GeneralName() {
}

public GeneralName(byte[] code) {
this.code = code;
}

public GeneralName(AnotherName otherName, BerIA5String rfc822Name, BerIA5String dNSName, ORAddress x400Address, Name directoryName, EDIPartyName ediPartyName, BerIA5String uniformResourceIdentifier, BerOctetString iPAddress, BerObjectIdentifier registeredID) {
this.otherName = otherName;
this.rfc822Name = rfc822Name;
this.dNSName = dNSName;
this.x400Address = x400Address;
this.directoryName = directoryName;
this.ediPartyName = ediPartyName;
this.uniformResourceIdentifier = uniformResourceIdentifier;
this.iPAddress = iPAddress;
this.registeredID = registeredID;
}

public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {
if (code != null) {
for (int i = code.length - 1; i >= 0; i--) {
os.write(code[i]);
}
return code.length;

}
int codeLength = 0;
int sublength;

if (registeredID != null) {
codeLength += registeredID.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 8
os.write(0x88);
codeLength += 1;
return codeLength;

}

if (iPAddress != null) {
codeLength += iPAddress.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 7
os.write(0x87);
codeLength += 1;
return codeLength;

}

if (uniformResourceIdentifier != null) {
codeLength += uniformResourceIdentifier.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 6
os.write(0x86);
codeLength += 1;
return codeLength;

}

if (ediPartyName != null) {
codeLength += ediPartyName.encode(os, false);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 5
os.write(0xa5);
codeLength += 1;
return codeLength;

}

if (directoryName != null) {
sublength = directoryName.encode(os, true);
codeLength += sublength;
codeLength += BerLength.encodeLength(os, sublength);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 4
os.write(0xa4);
codeLength += 1;
return codeLength;

}

if (x400Address != null) {
codeLength += x400Address.encode(os, false);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 3
os.write(0xa3);
codeLength += 1;
return codeLength;

}

if (dNSName != null) {
codeLength += dNSName.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 2
os.write(0x82);
codeLength += 1;
return codeLength;

}

if (rfc822Name != null) {
codeLength += rfc822Name.encode(os, false);
// write tag: CONTEXT_CLASS, PRIMITIVE, 1
os.write(0x81);
codeLength += 1;
return codeLength;

}

if (otherName != null) {
codeLength += otherName.encode(os, false);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 0
os.write(0xa0);
codeLength += 1;
return codeLength;

}

throw new IOException("Error encoding BerChoice: No item in choice was selected.");
}

public int decode(long sourceOffset,byte[] bytes, BerIdentifier berIdentifier) throws IOException {
return decode(new CountingInputStream(sourceOffset-(berIdentifier==null?0:(berIdentifier.to-berIdentifier.from)), new ByteArrayInputStream(bytes)), berIdentifier);

}
public int decode(CountingInputStream is, boolean explicit) throws IOException {;

    return decode(is, null);

 };

public int decode(CountingInputStream is, BerIdentifier berIdentifier) throws IOException {
int codeLength = 0;
this.from=is.getPosition()-(berIdentifier==null?0:(berIdentifier.to-berIdentifier.from));
BerIdentifier passedIdentifier = berIdentifier;

if (berIdentifier == null) {
berIdentifier = new BerIdentifier();
codeLength += berIdentifier.decode(is);
}

BerLength length = new BerLength();
if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 0)) {
otherName = new AnotherName();
codeLength += otherName.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 1)) {
rfc822Name = new BerIA5String();
codeLength += rfc822Name.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 2)) {
dNSName = new BerIA5String();
codeLength += dNSName.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 3)) {
x400Address = new ORAddress();
codeLength += x400Address.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 4)) {
codeLength += length.decode(is);
directoryName = new Name();
codeLength += directoryName.decode(is, null);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 5)) {
ediPartyName = new EDIPartyName();
codeLength += ediPartyName.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 6)) {
uniformResourceIdentifier = new BerIA5String();
codeLength += uniformResourceIdentifier.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 7)) {
iPAddress = new BerOctetString();
codeLength += iPAddress.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.PRIMITIVE, 8)) {
registeredID = new BerObjectIdentifier();
codeLength += registeredID.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (passedIdentifier != null) {
this.to=is.getPosition();
return 0;
}
this.to=is.getPosition();
throw new IOException("Error decoding BerChoice: Identifier matched to no item.");
}

public void encodeAndSave(int encodingSizeGuess) throws IOException {
BerByteArrayOutputStream os = new BerByteArrayOutputStream(encodingSizeGuess);
encode(os, false);
code = os.getArray();
}

public String toString() {
if ( otherName!= null) {
return "CHOICE{otherName: " + otherName + "}";
}

if ( rfc822Name!= null) {
return "CHOICE{rfc822Name: " + rfc822Name + "}";
}

if ( dNSName!= null) {
return "CHOICE{dNSName: " + dNSName + "}";
}

if ( x400Address!= null) {
return "CHOICE{x400Address: " + x400Address + "}";
}

if ( directoryName!= null) {
return "CHOICE{directoryName: " + directoryName + "}";
}

if ( ediPartyName!= null) {
return "CHOICE{ediPartyName: " + ediPartyName + "}";
}

if ( uniformResourceIdentifier!= null) {
return "CHOICE{uniformResourceIdentifier: " + uniformResourceIdentifier + "}";
}

if ( iPAddress!= null) {
return "CHOICE{iPAddress: " + iPAddress + "}";
}

if ( registeredID!= null) {
return "CHOICE{registeredID: " + registeredID + "}";
}

return "unknown";
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

