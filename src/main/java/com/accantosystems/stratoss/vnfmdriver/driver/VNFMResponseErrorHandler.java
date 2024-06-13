package com.accantosystems.stratoss.vnfmdriver.driver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

@Component("VNFMResponseErrorHandler")
public class VNFMResponseErrorHandler extends SOL003ResponseErrorHandler {

    @Autowired
    public VNFMResponseErrorHandler(ObjectMapper objectMapper) {
        super(objectMapper);
    }

    @Override
    protected String endpointDescription() {
        return "VNFM";
    }

}
