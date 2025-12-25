package com.manifestsecurity.manifest;

public class IntentDataInfo {
    private final String scheme;
    private final String host;
    private final String port;
    private final String path;
    private final String pathPrefix;
    private final String pathPattern;
    private final String mimeType;

    public IntentDataInfo(String scheme,
                          String host,
                          String port,
                          String path,
                          String pathPrefix,
                          String pathPattern,
                          String mimeType) {
        this.scheme = scheme == null ? "" : scheme;
        this.host = host == null ? "" : host;
        this.port = port == null ? "" : port;
        this.path = path == null ? "" : path;
        this.pathPrefix = pathPrefix == null ? "" : pathPrefix;
        this.pathPattern = pathPattern == null ? "" : pathPattern;
        this.mimeType = mimeType == null ? "" : mimeType;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public String getPort() {
        return port;
    }

    public String getPath() {
        return path;
    }

    public String getPathPrefix() {
        return pathPrefix;
    }

    public String getPathPattern() {
        return pathPattern;
    }

    public String getMimeType() {
        return mimeType;
    }

    public boolean isEmpty() {
        return scheme.isEmpty() && host.isEmpty() && port.isEmpty()
                && path.isEmpty() && pathPrefix.isEmpty() && pathPattern.isEmpty()
                && mimeType.isEmpty();
    }
}
