package com.accantosystems.stratoss.vnfmdriver.driver;

public class VNFPackageRepositoryException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public VNFPackageRepositoryException(String message) {
        super(message);
    }

    public VNFPackageRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }

}
