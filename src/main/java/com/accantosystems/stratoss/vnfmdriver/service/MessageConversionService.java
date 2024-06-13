package com.accantosystems.stratoss.vnfmdriver.service;

import java.util.Map;

import com.accantosystems.stratoss.vnfmdriver.model.alm.ExecutionRequest;

public interface MessageConversionService {

    String generateMessageFromRequest(String messageType, ExecutionRequest executionRequest) throws MessageConversionException;
    Map<String, Object> extractPropertiesFromMessage(String messageType, ExecutionRequest executionRequest, String message) throws MessageConversionException;

}
