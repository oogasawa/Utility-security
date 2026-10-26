package com.github.oogasawa.utility.security.fortinet;

import java.io.IOException;

/** Fetches the text at a URL. A test replaces it so that no network is used. */
public interface TextFetcher {

    /**
     * Fetches a URL.
     *
     * @param url the absolute URL
     * @return the response body
     * @throws IOException if the request fails
     */
    String get(String url) throws IOException;
}
