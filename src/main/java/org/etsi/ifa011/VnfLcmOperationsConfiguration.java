package org.etsi.ifa011;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class VnfLcmOperationsConfiguration {

    // NOTE: This does not specifically exist in the ETSI IFA011 2.4.1 version of the specification, but it allows us to define additionalParams passed in the CreateVnfRequest message
    private CreateVnfOpConfig createVnfOpConfig;
    private InstantiateVnfOpConfig instantiateVnfOpConfig;
    private ScaleVnfOpConfig scaleVnfOpConfig;
    private ScaleVnfToLevelOpConfig scaleVnfToLevelOpConfig;
    private ChangeVnfFlavourOpConfig changeVnfFlavourOpConfig;
    private HealVnfOpConfig healVnfOpConfig;
    private TerminateVnfOpConfig terminateVnfOpConfig;
    private OperateVnfOpConfig operateVnfOpConfig;
    private ChangeExtVnfConnectivityOpConfig changeExtVnfConnectivityOpConfig;

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class CreateVnfOpConfig {

        private Map<String, String> parameter;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class InstantiateVnfOpConfig {

        private Map<String, String> parameter;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ScaleVnfOpConfig {

        private Map<String, String> parameter;
        private Boolean scalingByMoreThanOneStepSupported;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ScaleVnfToLevelOpConfig {

        private Map<String, String> parameter;
        private Boolean arbitraryTargetLevelsSupported;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ChangeVnfFlavourOpConfig {

        private Map<String, String> parameter;
        private Boolean arbitraryTargetLevelsSupported;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class HealVnfOpConfig {

        private Map<String, String> parameter;
        private List<String> cause;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class TerminateVnfOpConfig {

        private Map<String, String> parameter;
        private Integer minGracefulTerminationTimeout;
        private Integer maxRecommendedGracefulTerminationTimeout;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class OperateVnfOpConfig {

        private Map<String, String> parameter;
        private Integer minGracefulStopTimeout;
        private Integer maxRecommendedGracefulStopTimeout;

    }

    @Data
    @JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ChangeExtVnfConnectivityOpConfig {

        private Map<String, String> parameter;

    }



}
