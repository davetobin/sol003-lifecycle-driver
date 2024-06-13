package com.accantosystems.stratoss.vnfmdriver.driver;

import org.springframework.web.client.RestClientException;

import org.etsi.sol003.common.ProblemDetails;

public class SOL003ResponseException extends RestClientException {

    public static final int DEFAULT_STATUS_VALUE = 0;

    private final ProblemDetails problemDetails;

    public SOL003ResponseException(String msg) {
        this(msg, new ProblemDetails(DEFAULT_STATUS_VALUE, msg));
    }

    public SOL003ResponseException(Throwable ex) {
        this(ex.getLocalizedMessage(), ex, new ProblemDetails(DEFAULT_STATUS_VALUE, ex.getLocalizedMessage()));
    }

    public SOL003ResponseException(String msg, Throwable ex) {
        this(msg, ex, new ProblemDetails(DEFAULT_STATUS_VALUE, String.format("%s: %s", msg, ex.getLocalizedMessage())));
    }

    public SOL003ResponseException(String msg, ProblemDetails problemDetails) {
        super(msg);
        this.problemDetails = problemDetails;
    }

    public SOL003ResponseException(String msg, Throwable ex, ProblemDetails problemDetails) {
        super(msg, ex);
        this.problemDetails = problemDetails;
    }

    public ProblemDetails getProblemDetails() {
        return problemDetails;
    }

}
