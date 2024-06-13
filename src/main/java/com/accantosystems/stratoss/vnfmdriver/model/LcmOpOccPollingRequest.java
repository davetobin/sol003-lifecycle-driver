package com.accantosystems.stratoss.vnfmdriver.model;

import com.accantosystems.stratoss.vnfmdriver.model.alm.ResourceManagerDeploymentLocation;

import static com.accantosystems.stratoss.vnfmdriver.utils.Constants.KAFKA_MESSAGE_VERSION;

public class LcmOpOccPollingRequest {

    private final ResourceManagerDeploymentLocation deploymentLocation;
    private final String vnfLcmOpOccId;
    private final String version = KAFKA_MESSAGE_VERSION;

    public LcmOpOccPollingRequest(ResourceManagerDeploymentLocation deploymentLocation, String vnfLcmOpOccId) {
        this.deploymentLocation = deploymentLocation;
        this.vnfLcmOpOccId = vnfLcmOpOccId;
    }

    public ResourceManagerDeploymentLocation getDeploymentLocation() {
        return deploymentLocation;
    }

    public String getVnfLcmOpOccId() {
        return vnfLcmOpOccId;
    }

    public String getVersion() {
        return version;
    }

}
