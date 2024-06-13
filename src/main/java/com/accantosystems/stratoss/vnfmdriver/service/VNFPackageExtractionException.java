package com.accantosystems.stratoss.vnfmdriver.service;

public class VNFPackageExtractionException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public VNFPackageExtractionException(String message) {
        super(message);
    }

    public VNFPackageExtractionException(String message, Throwable cause) {
        super(message, cause);
    }

}
