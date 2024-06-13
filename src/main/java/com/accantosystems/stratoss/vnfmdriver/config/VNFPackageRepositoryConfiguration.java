package com.accantosystems.stratoss.vnfmdriver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageRepositoryDriver;
import com.accantosystems.stratoss.vnfmdriver.driver.impl.NexusVNFPackageRepositoryDriver;
import com.accantosystems.stratoss.vnfmdriver.service.AuthenticatedRestTemplateService;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration("VNFPackageRepositoryConfiguration")
public class VNFPackageRepositoryConfiguration {

    @Bean
    public VNFPackageRepositoryDriver getPackageRepositoryDriver(VNFMDriverProperties vnfmDriverProperties, AuthenticatedRestTemplateService authenticatedRestTemplateService, ObjectMapper objectMapper) {
        if (vnfmDriverProperties.getPackageManagement().getRepositoryType() == VNFMDriverProperties.PackageManagement.RepositoryType.NEXUS) {
            return new NexusVNFPackageRepositoryDriver(vnfmDriverProperties, authenticatedRestTemplateService, objectMapper);
        } else {
            throw new IllegalStateException(String.format("Invalid VNF package repository type [%s] configured", vnfmDriverProperties.getPackageManagement().getRepositoryType()));
        }
    }

}
