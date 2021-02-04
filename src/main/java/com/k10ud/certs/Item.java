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

import org.openmuc.jasn1.ber.SourcePostitionable;

import java.util.ArrayList;
import java.util.List;

public class Item extends ArrayList<KV> {
    public static final ItemDumper idumper = new ItemDumper();
    public static final Item EMPTY = new Item();

    public List<KV> getProps() {
        return this;
    }

    public Item(String key, Object value) {
        prop(key, value);
    }

    public Item(TaggedString key, Object value) {
        prop(key, value);
    }

    public Item() {
    }

    @Override
    public String toString() {
        return idumper.toString(null, this);
    }


    public Item prop(String key, Object value) {
        if (key != null)
            prop(new KV(key, value));
        return this;
    }

    public Item prop(TaggedString key, Object value) {
        if (key != null)
            prop(new KV(key, value));
        return this;
    }

    private Item prop(KV kv) {
        if (kv != null)
            add(kv);
        return this;
    }

    public Item prop(TaggedString key) {
        if (key != null)
            add(new KV(key, null));
        return this;
    }

    public Item prop(String key) {
        if (key != null)
            add(new KV(key, null));
        return this;
    }


    public Object getProp(String key) {
        for (KV p : getProps()) {
            if (p.key.equals(key))
                return p.value;
        }
        return null;
    }


    public Item transfer(Item i) {
        for (KV p : i) {
            prop(p);
        }
        return this;
    }
}
