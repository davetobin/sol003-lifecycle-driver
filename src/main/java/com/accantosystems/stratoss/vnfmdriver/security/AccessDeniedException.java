package com.accantosystems.stratoss.vnfmdriver.security;

import java.io.IOException;

public class AccessDeniedException extends IOException {

    public AccessDeniedException() {
    }

    public AccessDeniedException(String message) {
        super(message);
    }

    public AccessDeniedException(String message, Throwable cause) {
        super(message, cause);
    }

    public AccessDeniedException(Throwable cause) {
        super(cause);
    }

}
