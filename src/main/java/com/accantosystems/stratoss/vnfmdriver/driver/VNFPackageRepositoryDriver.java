package com.accantosystems.stratoss.vnfmdriver.driver;

import java.util.List;

import org.etsi.sol003.packagemanagement.VnfPkgInfo;
import org.springframework.core.io.Resource;

public interface VNFPackageRepositoryDriver {

    Resource getVnfPackage(String vnfPackageId) throws VNFPackageNotFoundException;

    List<VnfPkgInfo> queryAllVnfPkgInfos(String groupName);

    VnfPkgInfo getVnfPkgInfo(String vnfPackageId) throws VNFPackageNotFoundException;

}
