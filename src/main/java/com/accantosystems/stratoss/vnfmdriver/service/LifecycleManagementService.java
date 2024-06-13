package com.accantosystems.stratoss.vnfmdriver.service;

import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import com.accantosystems.stratoss.vnfmdriver.model.alm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.accantosystems.stratoss.vnfmdriver.config.VNFMDriverProperties;
import com.accantosystems.stratoss.vnfmdriver.driver.VNFLifecycleManagementDriver;

@Service("LifecycleManagementService")
public class LifecycleManagementService {

    private final static Logger logger = LoggerFactory.getLogger(LifecycleManagementService.class);

    private final VNFLifecycleManagementDriver vnfLifecycleManagementDriver;
    private final MessageConversionService messageConversionService;
    private final ExternalMessagingService externalMessagingService;
    private final VNFMDriverProperties properties;

    @Autowired
    public LifecycleManagementService(VNFLifecycleManagementDriver vnfLifecycleManagementDriver, MessageConversionService messageConversionService, ExternalMessagingService externalMessagingService,
                                      VNFMDriverProperties properties) {
        this.vnfLifecycleManagementDriver = vnfLifecycleManagementDriver;
        this.messageConversionService = messageConversionService;
        this.externalMessagingService = externalMessagingService;
        this.properties = properties;
    }

    public ExecutionAcceptedResponse executeLifecycle(ExecutionRequest executionRequest) throws MessageConversionException {
        logger.info("Processing execution request");

        try {
            if ("Create".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                final String requestId = UUID.randomUUID().toString();
                // Generate CreateVnfRequest message
                final String createVnfRequest = messageConversionService.generateMessageFromRequest("CreateVnfRequest", executionRequest);
                // Send message to VNFM
                final String vnfInstanceResponse = vnfLifecycleManagementDriver.createVnfInstance(executionRequest.getDeploymentLocation(), createVnfRequest, requestId);
                // Convert response into properties to be returned to ALM
                final Map<String, Object> outputs = messageConversionService.extractPropertiesFromMessage("VnfInstance", executionRequest, vnfInstanceResponse);

                // Delay sending the asynchronous response (from a different thread) as this method needs to complete first (to send the response back to Brent)
                externalMessagingService.sendDelayedExecutionAsyncResponse(new ExecutionAsyncResponse(requestId, ExecutionStatus.COMPLETE, null, outputs, Collections.emptyMap()), properties.getExecutionResponseDelay());

                // Send response back to ALM
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Install".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Instantiate
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String instantiateVnfRequest = messageConversionService.generateMessageFromRequest("InstantiateVnfRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.instantiateVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, instantiateVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Start".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Operate (Start)
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String operateVnfRequest = messageConversionService.generateMessageFromRequest("OperateVnfRequest-Start", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.operateVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, operateVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Stop".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Operate (Stop)
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String operateVnfRequest = messageConversionService.generateMessageFromRequest("OperateVnfRequest-Stop", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.operateVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, operateVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Uninstall".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Terminate
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String terminateVnfRequest = messageConversionService.generateMessageFromRequest("TerminateVnfRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.terminateVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, terminateVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("ScaleToLevel".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // ScaleToLevel
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String scaleVnfRequest = messageConversionService.generateMessageFromRequest("ScaleVnfRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.scaleVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, scaleVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("ScaleOut".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Scale Out
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String scaleVnfRequest = messageConversionService.generateMessageFromRequest("ScaleVnfRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.scaleVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, scaleVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("ScaleIn".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Scale In
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String scaleVnfRequest = messageConversionService.generateMessageFromRequest("ScaleVnfRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.scaleVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, scaleVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Heal".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Heal
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String healVnfRequest = messageConversionService.generateMessageFromRequest("HealVnfRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.healVnf(executionRequest.getDeploymentLocation(), vnfInstanceId, healVnfRequest);
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Delete".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // Delete
                final String requestId = UUID.randomUUID().toString();
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                vnfLifecycleManagementDriver.deleteVnfInstance(executionRequest.getDeploymentLocation(), vnfInstanceId, requestId);
                externalMessagingService.sendDelayedExecutionAsyncResponse(new ExecutionAsyncResponse(requestId, ExecutionStatus.COMPLETE, null, Collections.emptyMap(), Collections.emptyMap()), properties.getExecutionResponseDelay());
                return new ExecutionAcceptedResponse(requestId);
            } else if ("Upgrade".equalsIgnoreCase(executionRequest.getLifecycleName())) {
                // ChangeCurrentVNFPackage
                final String vnfInstanceId = executionRequest.getStringResourceProperty("vnfInstanceId");
                final String changeCurrentVnfPkgRequest = messageConversionService.generateMessageFromRequest("ChangeCurrentVnfPkgRequest", executionRequest);
                final String requestId = vnfLifecycleManagementDriver.changeCurrentVnfPkg(executionRequest.getDeploymentLocation(), vnfInstanceId, changeCurrentVnfPkgRequest);
                return new ExecutionAcceptedResponse(requestId);
            }
             else {
                throw new IllegalArgumentException(String.format("Requested transition [%s] is not supported by this lifecycle driver", executionRequest.getLifecycleName()));
            }
        } catch (MessageConversionException e) {
            logger.error("Error converting message", e);
            throw e;
        }
    }

}
