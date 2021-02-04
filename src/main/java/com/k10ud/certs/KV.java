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

import java.util.Iterator;

public final class KV {
    final Object key;

    public Object getKey() {
        return key;
    }

    public Object getValue() {
        return value;
    }

    final Object value;

    public KV(Object key, Object value) {
        this.key = key;
        this.value = value;
    }

    public KV copyAs(String newKey) {
        if (key instanceof TaggedString) {
            TaggedString ts = new TaggedString(newKey);
            Iterator<TaggedString.Attr> it = ((TaggedString) key).tags().iterator();
            while (it.hasNext()) {
                TaggedString.Attr x = it.next();
                ts.addTag(x.getAttr(), x.getValue());
            }
            return new KV(ts, value);
        }
        return new KV(newKey, value);
    }

    public String getMainKey() {
        if (key instanceof String) {
            return (String) key;
        }
        if (key instanceof TaggedString) {
            return (String) ((TaggedString) key).getId();
        }
        return String.valueOf(key);

    }
}
