package com.accantosystems.stratoss.vnfmdriver.service;

import static com.accantosystems.stratoss.vnfmdriver.test.TestConstants.loadFileIntoByteArray;
import static com.accantosystems.stratoss.vnfmdriver.test.TestConstants.loadFileIntoString;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;

import org.etsi.sol003.packagemanagement.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.test.context.ActiveProfiles;

import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageNotFoundException;
import com.accantosystems.stratoss.vnfmdriver.driver.VNFPackageRepositoryDriver;
import com.accantosystems.stratoss.vnfmdriver.test.TestConstants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.io.ByteStreams;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles({ "test" })
public class PackageManagementServiceTest {

    private static final String VNF_PACKAGE_FILENAME = "examples/VnfPackage-vMRF.zip";
    private static final String VNF_PACKAGE_FILENAME_MISSING_TOSCA_METADATA = "examples/VnfPackage-MissingToscaMetadata-vMRF.zip";
    private static final String VNF_PACKAGE_FILENAME_MULTIPLE_DEFINITIONS = "examples/VnfPackage-MultipleDefinitions-vMRF.zip";
    private static final String VNF_PACKAGE_FILENAME_NO_DEFINITIONS = "examples/VnfPackage-NoDefinitions-vMRF.zip";
    private static final String VNF_PACKAGE_ID = "vMRF";

    @MockBean
    private VNFPackageRepositoryDriver vnfPackageDriver;

    @Autowired
    private PackageManagementService packageManagementService;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    public void testGetAllVnfPackageInfos() throws Exception {
        final VnfPkgInfo exampleVnfPkgInfo = objectMapper.readValue(loadFileIntoString("/examples/vnfPackageId.pkgInfo"), VnfPkgInfo.class);
        when(vnfPackageDriver.queryAllVnfPkgInfos(eq("groupName"))).thenReturn(Collections.singletonList(exampleVnfPkgInfo));

        final List<VnfPkgInfo> vnfPackageInfoList = packageManagementService.getAllVnfPackageInfos("groupName");
        assertThat(vnfPackageInfoList).hasSize(1);
    }

    @Test
    public void testGetVnfPackageInfo() throws Exception {
        final VnfPkgInfo exampleVnfPkgInfo = objectMapper.readValue(loadFileIntoString("/examples/vnfPackageId.pkgInfo"), VnfPkgInfo.class);
        when(vnfPackageDriver.getVnfPkgInfo(eq("vnfPackageId"))).thenReturn(exampleVnfPkgInfo);

        final VnfPkgInfo vnfPackageInfo = packageManagementService.getVnfPackageInfo("vnfPackageId");
        assertThat(vnfPackageInfo).isNotNull();
        assertThat(vnfPackageInfo.getId()).isEqualTo("vnfPackageId");
        assertThat(vnfPackageInfo.getVnfProductName()).isEqualTo("vMRF");
        assertThat(vnfPackageInfo.getVnfProvider()).isEqualTo("Acme");
        assertThat(vnfPackageInfo.getOnboardingState()).isEqualTo(PackageOnboardingStateType.ONBOARDED);
        assertThat(vnfPackageInfo.getOperationalState()).isEqualTo(PackageOperationalStateType.ENABLED);

        assertThat(vnfPackageInfo.getAdditionalArtifacts()).isNotEmpty();
        assertThat(vnfPackageInfo.getAdditionalArtifacts()).extracting(VnfPackageArtifactInfo::getArtifactPath).containsExactlyInAnyOrder(
                "MRF.mf",
                "Definitions/MRF.yaml",
                "Files/ChangeLog.txt",
                "Files/Licenses/README",
                "Files/Tests/README",
                "Scripts/install.sh",
                "TOSCA-Metadata/TOSCA.meta");

        assertThat(vnfPackageInfo.getSoftwareImages()).isNotEmpty();
        assertThat(vnfPackageInfo.getSoftwareImages()).extracting(VnfPackageSoftwareImageInfo::getImagePath).containsExactlyInAnyOrder("Files/Images/01-VPC-CF-IMAGE");
    }

    @Test
    public void testGetVnfPackageInfoPackageNotFound() throws Exception {
        final String packageId = "not-existant-package-id";
        when(vnfPackageDriver.getVnfPkgInfo(eq(packageId))).thenThrow(new VNFPackageNotFoundException("Not Found"));
        assertThatThrownBy(() -> packageManagementService.getVnfPackageInfo(packageId))
                .isInstanceOf(VNFPackageNotFoundException.class);
    }

    @Test
    public void testGetVnfPackageYamlDescriptor() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        String vnfd = packageManagementService.getVnfdAsYaml(VNF_PACKAGE_ID);
        assertThat(vnfd).isNotBlank();
    }

    @Test
    public void testGetVnfPackageYamlDescriptorPackageNotFound() throws Exception {

        String packageId = "not-existant-package-id";

        when(vnfPackageDriver.getVnfPackage(eq(packageId))).thenThrow(new VNFPackageNotFoundException("Not Found"));

        assertThatThrownBy(() -> packageManagementService.getVnfdAsYaml(packageId))
                .isInstanceOf(VNFPackageNotFoundException.class);
    }

    @Test
    public void testGetVnfPackageYamlDescriptorInvalidZip() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME_MISSING_TOSCA_METADATA);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        assertThatThrownBy(() -> packageManagementService.getVnfdAsYaml(VNF_PACKAGE_ID))
                .isInstanceOf(VNFPackageExtractionException.class)
                .hasMessage("Unable to locate Tosca Metadata File on path [TOSCA-Metadata/TOSCA.meta] within Vnf Package with id [vMRF]");
    }

    @Test
    public void testGetVnfPackageYamlNoDefinitions() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME_NO_DEFINITIONS);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        assertThatThrownBy(() -> packageManagementService.getVnfdAsYaml(VNF_PACKAGE_ID))
                .isInstanceOf(VNFPackageExtractionException.class)
                .hasMessage("Unable to find any Definitions within VnfPackage with id [vMRF]");
    }

    @Test
    public void testGetVnfPackageYamlMultipleDefinitions() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME_MULTIPLE_DEFINITIONS);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        assertThatThrownBy(() -> packageManagementService.getVnfdAsYaml(VNF_PACKAGE_ID))
                .isInstanceOf(UnexpectedPackageContentsException.class)
                .hasMessage("Found multiple VNFDs when expecting only one within VnfPackage with id [vMRF]");
    }

    @Test
    public void testGetVnfPackageZipDescriptor() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        Resource vnfdPackage = packageManagementService.getVnfdAsZip(VNF_PACKAGE_ID);
        assertThat(vnfdPackage).isNotNull();
        List<String> zipContents = TestConstants.listZipContents(vnfdPackage.getInputStream());
        assertThat(zipContents).containsExactlyInAnyOrder("Definitions/MRF.yaml", "TOSCA-Metadata/TOSCA.meta");
    }

    @Test
    public void testGetVnfPackageContent() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        Resource vnfPackageResponse = packageManagementService.getVnfPackageContent(VNF_PACKAGE_ID, "");
        assertThat(ByteStreams.toByteArray(vnfPackageResponse.getInputStream())).isEqualTo(vnfPackageAsByteArray);
    }

    @Test
    public void testGetVnfPackageArtifact() throws Exception {

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        Resource vnfPackageResponse = packageManagementService.getVnfPackageArtifact(VNF_PACKAGE_ID, "Scripts/install.sh", null);
        assertThat(ByteStreams.toByteArray(vnfPackageResponse.getInputStream())).isNotNull();
    }

    @Test
    public void testGetVnfPackageInfoListValidArtifacts() throws Exception {
        final VnfPkgInfo exampleVnfPkgInfo = objectMapper.readValue(loadFileIntoString("/examples/vnfPackageId.pkgInfo"), VnfPkgInfo.class);
        when(vnfPackageDriver.getVnfPkgInfo(eq(VNF_PACKAGE_ID))).thenReturn(exampleVnfPkgInfo);

        byte[] vnfPackageAsByteArray = loadFileIntoByteArray(VNF_PACKAGE_FILENAME);
        ByteArrayResource vnfPackageAsResource = new ByteArrayResource(vnfPackageAsByteArray);
        when(vnfPackageDriver.getVnfPackage(eq(VNF_PACKAGE_ID))).thenReturn(vnfPackageAsResource);

        VnfPkgInfo vnfPackageInfo = packageManagementService.getVnfPackageInfo(VNF_PACKAGE_ID);
        assertThat(vnfPackageInfo.getAdditionalArtifacts()).isNotEmpty();
        assertThat(vnfPackageInfo.getSoftwareImages()).isNotEmpty();

        // verify that each additional artifact listed can be found in the package
        for (VnfPackageArtifactInfo vnfArtifact : vnfPackageInfo.getAdditionalArtifacts()) {
            assertThat(packageManagementService.getVnfPackageArtifact(VNF_PACKAGE_ID, vnfArtifact.getArtifactPath(), null)).isNotNull();
        }

        // verify that each software image listed can be found in the package
        for (VnfPackageSoftwareImageInfo softwareImage : vnfPackageInfo.getSoftwareImages()) {
            assertThat(packageManagementService.getVnfPackageArtifact(VNF_PACKAGE_ID, softwareImage.getImagePath(), null)).isNotNull();
        }
    }

}
