package com.accantosystems.stratoss.vnfmdriver.service;

import static com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverConstants.COMPLETED_OPERATIONAL_STATES;

import java.io.IOException;
import java.util.Collections;
import jakarta.annotation.PreDestroy;

import org.etsi.sol003.lifecyclemanagement.LcmOperationStateType;
import org.etsi.sol003.lifecyclemanagement.VnfLcmOpOcc;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;

import com.accantosystems.stratoss.vnfmdriver.driver.VNFLifecycleManagementDriver;
import com.accantosystems.stratoss.vnfmdriver.model.LcmOpOccPollingRequest;
import com.accantosystems.stratoss.vnfmdriver.model.alm.ExecutionAsyncResponse;
import com.accantosystems.stratoss.vnfmdriver.model.alm.ExecutionStatus;
import com.accantosystems.stratoss.vnfmdriver.model.alm.FailureDetails;
import com.fasterxml.jackson.databind.ObjectMapper;

public class LcmOpOccPollingService {

    private static final Logger logger = LoggerFactory.getLogger(LcmOpOccPollingService.class);

    private final VNFLifecycleManagementDriver driver;
    private final ExternalMessagingService externalMessagingService;
    private final ObjectMapper objectMapper;

    @Autowired
    public LcmOpOccPollingService(VNFLifecycleManagementDriver driver, ExternalMessagingService externalMessagingService, ObjectMapper objectMapper) {
        logger.info("Creating Lifecycle Management Operation Occurrence Polling Service");
        this.driver = driver;
        this.externalMessagingService = externalMessagingService;
        this.objectMapper = objectMapper;
    }

    @PreDestroy
    public void close() {
        logger.info("Shutting down Lifecycle Management Operation Occurrence Polling Service...");
    }

    @KafkaListener(topics = "${vnfmdriver.topics.lcmOpOccPollingTopic}")
    public void listenForLcmOpOccPollingRequestMessages(final String message) {
        try {
            // Deserialize message into LcmOpOccPollingRequest
            LcmOpOccPollingRequest lcmOpOccPollingRequest = objectMapper.readValue(message, LcmOpOccPollingRequest.class);

            VnfLcmOpOcc vnfLcmOpOcc = driver.queryLifecycleOperationOccurrence(lcmOpOccPollingRequest.getDeploymentLocation(), lcmOpOccPollingRequest.getVnfLcmOpOccId());
            if (COMPLETED_OPERATIONAL_STATES.contains(vnfLcmOpOcc.getOperationState())) {
                // Send back Async response to Brent
                final ExecutionAsyncResponse executionResponse;
                if (vnfLcmOpOcc.getOperationState() == LcmOperationStateType.COMPLETED) {
                    executionResponse = new ExecutionAsyncResponse(lcmOpOccPollingRequest.getVnfLcmOpOccId(), ExecutionStatus.COMPLETE, null, Collections.emptyMap(), Collections.emptyMap());
                } else {
                    executionResponse = new ExecutionAsyncResponse(lcmOpOccPollingRequest.getVnfLcmOpOccId(),
                                                                   ExecutionStatus.FAILED,
                                                                   new FailureDetails(FailureDetails.FailureCode.INFRASTRUCTURE_ERROR, vnfLcmOpOcc.getError().getDetail()),
                                                                   Collections.emptyMap(),Collections.emptyMap());
                }
                executionResponse.setTimestamp(System.currentTimeMillis());
                externalMessagingService.sendExecutionAsyncResponse(executionResponse);
            } else {
                // Keep waiting and re-enqueue polling request
                externalMessagingService.sendLcmOpOccPollingRequest(lcmOpOccPollingRequest);
            }
        } catch (Exception e) {
            logger.error("Exception caught processing LcmOpOccPollingRequest message", e);
        }
    }

}
