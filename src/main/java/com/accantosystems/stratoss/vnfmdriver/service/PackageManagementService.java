package com.accantosystems.stratoss.vnfmdriver.service;

import java.util.List;

import org.etsi.sol003.packagemanagement.VnfPkgInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageNotFoundException;
import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageRepositoryDriver;

@Service("PackageManagementService")
public class PackageManagementService {

    private final static Logger logger = LoggerFactory.getLogger(PackageManagementService.class);

    private final VNFPackageRepositoryDriver vnfPackageDriver;
    private final VNFPackageExtractor vnfPackageExtractor;

    @Autowired
    public PackageManagementService(VNFPackageRepositoryDriver vnfPackageDriver, VNFPackageExtractor vnfPackageExtractor) {
        this.vnfPackageDriver = vnfPackageDriver;
        this.vnfPackageExtractor = vnfPackageExtractor;
    }

    public List<VnfPkgInfo> getAllVnfPackageInfos(String groupName) {
        return vnfPackageDriver.queryAllVnfPkgInfos(groupName);
    }

    public VnfPkgInfo getVnfPackageInfo(String vnfPkgId) throws VNFPackageNotFoundException {
        return vnfPackageDriver.getVnfPkgInfo(vnfPkgId);
    }

    public String getVnfdAsYaml(String vnfPkgId) throws UnexpectedPackageContentsException, VNFPackageNotFoundException {

        Resource vnfPackageZip = vnfPackageDriver.getVnfPackage(vnfPkgId);
        String vnfd = vnfPackageExtractor.extractVnfdAsYaml(vnfPkgId, vnfPackageZip);
        return vnfd;

    }

    public Resource getVnfdAsZip(String vnfPkgId) throws VNFPackageNotFoundException {

        Resource vnfPackageZip = vnfPackageDriver.getVnfPackage(vnfPkgId);
        Resource vnfdPackage = vnfPackageExtractor.extractVnfdAsZip(vnfPkgId, vnfPackageZip);
        return vnfdPackage;
    }

    public Resource getVnfPackageContent(String vnfPkgId, String contentRange) throws PackageStateConflictException, ContentRangeNotSatisfiableException, VNFPackageNotFoundException {
        Resource vnfPackageZip = vnfPackageDriver.getVnfPackage(vnfPkgId);
        // TODO handle content range
        return vnfPackageZip;
    }

    public Resource getVnfPackageArtifact(String vnfPkgId, String artifactPath, String contentRange) throws PackageStateConflictException, ContentRangeNotSatisfiableException,
                                                                                                            VNFPackageNotFoundException {

        Resource vnfPackageZip = vnfPackageDriver.getVnfPackage(vnfPkgId);
        Resource vnfArtifact = vnfPackageExtractor.extractVnfPackageArtifact(vnfPkgId, artifactPath, vnfPackageZip);
        // TODO handle content range
        return vnfArtifact;
    }

}
