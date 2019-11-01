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

import com.k10ud.certs.Item;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ItemChecker {
    private Item out = new Item();

    public void obs(String key, Item value) {
        out.prop(key, value);
    }

    public void should(String s, String s1) {
        should(s + ". [" + s1 + "]");
    }

    public void ignored(String msg, String s) {
        ignored(msg + ". [" + s + "]");
    }

    public MessageDigest getMDInstance(String s) {
        try {
            return MessageDigest.getInstance(s);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean check(boolean valid, String s) {
        if (valid) ok(s);
        else fail(s);
        return valid;
    }

    public void checkShould(boolean valid, String s) {
        if (valid) ok(s);
        else should(s);
    }

    public void yesOrNo(boolean valid, String s) {
        if (valid) yes(s);
        else no(s);
    }

    public boolean assertExists(String name, Object data) {
        if (data != null) {
            //    ok(name);
            return true;
        }

        ioerror(name);
        return false;

    }

    public void ioerror(String text) {
        out.prop("IO ERROR", text);
    }

    public void fail(String text) {
        out.prop("INVALID", text);
    }

    public void obs(String text) {
        out.prop("OBS", text);
    }

    public void ok(String text) {
        out.prop("OK", text);
    }

    public void ok(String text, String cause) {
        ok(text + ": [" + cause + "]");
    }

    public void fail(String s, Exception e) {


        fail(s, e.getMessage());
    }

    public void fail(String s, String det) {


        fail(s + ": [" + det + "]");
    }

    public void should(String text) {
        out.prop("WARN", text);
    }


    public void yes(String text) {
        out.prop("YES", text);
    }


    public void no(String text) {
        out.prop("NO", text);
    }

    public void todo(String text) {
        out.prop("TODO", text);
    }

    public void ignored(String text) {
        out.prop("IGNORED", text);
    }

    public Item getItem() {
        return out;
    }

    public void debug(String text, Object value) {
        out.prop("DEBUG", new Item(text,value));
    }
}
