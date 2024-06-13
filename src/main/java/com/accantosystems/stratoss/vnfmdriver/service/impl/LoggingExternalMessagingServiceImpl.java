package com.accantosystems.stratoss.vnfmdriver.service.impl;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.accantosystems.stratoss.vnfmdriver.model.LcmOpOccPollingRequest;
import com.accantosystems.stratoss.vnfmdriver.model.alm.ExecutionAsyncResponse;
import com.accantosystems.stratoss.vnfmdriver.service.ExternalMessagingService;

public class LoggingExternalMessagingServiceImpl implements ExternalMessagingService {

    private static final Logger logger = LoggerFactory.getLogger(LoggingExternalMessagingServiceImpl.class);

    @Override public void sendExecutionAsyncResponse(ExecutionAsyncResponse request) {
        logger.info("Would send: {}", request);
    }

    @Override public void sendDelayedExecutionAsyncResponse(ExecutionAsyncResponse request, Duration delay) {
        logger.info("Would send delayed message after {} seconds: {}", delay.getSeconds(), request);
    }

    @Override public void sendLcmOpOccPollingRequest(LcmOpOccPollingRequest request) {
        logger.info("Would submit request to poll for Lccn request [{}]", request.getVnfLcmOpOccId());
    }

}
