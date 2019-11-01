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

package com.k10ud.cli;

import com.k10ud.certs.IOUtil;
import com.k10ud.certs.Item;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class HTTPItem {

    public static class SendResponse {
        byte[] response;
        Item item;
    }


    public static SendResponse send(String tsa, byte[] query, String contentType) {
        SendResponse r = new SendResponse();
        Item i = new Item("URL", tsa);
        r.item = new Item("Http Request POST",i);
        HttpURLConnection con = null;
        try {
            URL url = new URL(tsa);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-type", contentType);
            con.setRequestProperty("Content-length", String.valueOf(query.length));

            try (OutputStream out = con.getOutputStream()) {
                out.write(query);
                out.flush();
            }

            i.prop("ResponseCode", con.getResponseCode());


            if (con.getResponseCode()==HttpURLConnection.HTTP_SEE_OTHER||con.getResponseCode()==HttpURLConnection.HTTP_MOVED_PERM||con.getResponseCode()==HttpURLConnection.HTTP_MOVED_TEMP) {
                //warn:loops!
                SendResponse rr = send(con.getHeaderField("Location"), query,contentType);
                r.response=rr.response;
                r.item.prop("Redirect",rr.item);
                return r;

            }


            if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
                try (InputStream in = con.getInputStream()) {
                    r.response = IOUtil.readAllBytes(in);
                }
            }

        } catch (Exception e) {
            i.prop("Error", e.getMessage());

        } finally {
            if (con != null)
                con.disconnect();
        }
        return r;
    }


    public static SendResponse sendGet(String tsa) {
        SendResponse r = new SendResponse();
        Item i = new Item("URL", tsa);
        r.item = new Item("Http Request GET",i);
        HttpURLConnection con = null;
        try {
            URL url = new URL(tsa);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setDoInput(true);
            con.setRequestMethod("GET");

            i.prop("ResponseCode", con.getResponseCode());


            if (con.getResponseCode()==HttpURLConnection.HTTP_SEE_OTHER||con.getResponseCode()==HttpURLConnection.HTTP_MOVED_PERM||con.getResponseCode()==HttpURLConnection.HTTP_MOVED_TEMP) {
                //warn:loops!
                SendResponse rr = sendGet(con.getHeaderField("Location"));
                r.response=rr.response;
                r.item.prop("Redirect",rr.item);
                return r;

            }

            if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
                try (InputStream in = con.getInputStream()) {
                    r.response = IOUtil.readAllBytes(in);
                }
            }

        } catch (Exception e) {
            i.prop("Error", e.getMessage());

        } finally {
            if (con != null)
                con.disconnect();
        }
        return r;
    }


}
