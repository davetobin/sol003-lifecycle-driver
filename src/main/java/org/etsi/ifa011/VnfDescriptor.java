package org.etsi.ifa011;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Data;

@Data
@JsonInclude(value = JsonInclude.Include.NON_EMPTY, content = JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public class VnfDescriptor {

    private String vnfdId;
    private String vnfProvider;
    private String vnfProductName;
    private String vnfSoftwareVersion;
    private String vnfdVersion;
    private String vnfProductInfoName;
    private String vnfProductInfoDescription;
    private List<String> vnfmInfo;
    private List<String> localizationLanguage;
    private String defaultLocalizationLanguage;

    // This is a deficient model, we have only implemented the sections that are currently used.
    private List<VnfDf> deploymentFlavour;

}
