package com.accantosystems.stratoss.vnfmdriver.driver;

import java.io.IOException;

import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.stereotype.Component;

import com.accantosystems.stratoss.vnfmdriver.service.GrantRejectedException;
import com.fasterxml.jackson.databind.ObjectMapper;

@Component("GrantResponseErrorHandler")
public class GrantResponseErrorHandler extends SOL003ResponseErrorHandler {

    public GrantResponseErrorHandler(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    @Override
    public void handleError(ClientHttpResponse clientHttpResponse) throws GrantRejectedException, IOException {
        try {
            super.handleError(clientHttpResponse);
        } catch (SOL003ResponseException e) {
            if (e.getProblemDetails() != null && HttpStatus.FORBIDDEN.value() == e.getProblemDetails().getStatus()) {
                throw new GrantRejectedException(e.getProblemDetails().getDetail(), e.getCause());
            }
            throw e;
        }
    }

    protected String endpointDescription() {
        return "Grant Provider";
    }

}
