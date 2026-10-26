package com.github.oogasawa.utility.security.deps;

import java.io.IOException;

/** Sends requests to the OSV API. A test replaces it so that no network is used. */
public interface OsvTransport {

    /** POSTs a JSON body and returns the response body. */
    String post(String url, String json) throws IOException;

    /** GETs a URL and returns the response body, or {@code null} on HTTP 404. */
    String get(String url) throws IOException;
}
