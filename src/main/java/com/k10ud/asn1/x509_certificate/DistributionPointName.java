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


public class DistributionPointName implements Encodedable,Decodeable,SourcePostitionable /*1*/ {

public byte[] code = null; public long from,to;
public GeneralNames fullName = null;

public RelativeDistinguishedName nameRelativeToCRLIssuer = null;

public DistributionPointName() {
}

public DistributionPointName(byte[] code) {
this.code = code;
}

public DistributionPointName(GeneralNames fullName, RelativeDistinguishedName nameRelativeToCRLIssuer) {
this.fullName = fullName;
this.nameRelativeToCRLIssuer = nameRelativeToCRLIssuer;
}

public int encode(BerByteArrayOutputStream os, boolean explicit) throws IOException {
if (code != null) {
for (int i = code.length - 1; i >= 0; i--) {
os.write(code[i]);
}
return code.length;

}
int codeLength = 0;
if (nameRelativeToCRLIssuer != null) {
codeLength += nameRelativeToCRLIssuer.encode(os, false);
// write tag: CONTEXT_CLASS, CONSTRUCTED, 1
os.write(0xa1);
codeLength += 1;
return codeLength;

}

if (fullName != null) {
codeLength += fullName.encode(os, false);
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
fullName = new GeneralNames();
codeLength += fullName.decode(is, false);
this.to=is.getPosition();
return codeLength;
}

if (berIdentifier.equals(BerIdentifier.CONTEXT_CLASS, BerIdentifier.CONSTRUCTED, 1)) {
nameRelativeToCRLIssuer = new RelativeDistinguishedName();
codeLength += nameRelativeToCRLIssuer.decode(is, false);
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
if ( fullName!= null) {
return "CHOICE{fullName: " + fullName + "}";
}

if ( nameRelativeToCRLIssuer!= null) {
return "CHOICE{nameRelativeToCRLIssuer: " + nameRelativeToCRLIssuer + "}";
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

