package com.skycrate.backend.skycrateBackend.dto;

public class FileDownloadRequest {
    private String filename;
    private String password;

    // Getters and Setters
    public String getFilename() {
        return filename;
    }

    public void setFilename(String filename) {
        this.filename = filename;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
