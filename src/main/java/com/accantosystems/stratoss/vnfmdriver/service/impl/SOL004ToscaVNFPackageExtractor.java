package com.accantosystems.stratoss.vnfmdriver.service.impl;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.etsi.sol003.packagemanagement.VnfPkgInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;

import com.accantosystems.stratoss.vnfmdriver.service.VNFPackageExtractionException;
import com.accantosystems.stratoss.vnfmdriver.service.VNFPackageExtractor;
import com.accantosystems.stratoss.vnfmdriver.web.etsi.ResponseTypeNotAcceptableException;

@Service("SOL004ToscaVNFPackageExtractor")
public class SOL004ToscaVNFPackageExtractor extends VNFPackageExtractor {

    private final static Logger logger = LoggerFactory.getLogger(SOL004ToscaVNFPackageExtractor.class);

    public static final String PATH_TOSCA_METADATA_DIRECTORY = "TOSCA-Metadata/";
    public static final String PATH_TOSCA_METADATA = PATH_TOSCA_METADATA_DIRECTORY + "TOSCA.meta";
    public static final String PATH_TOSCA_DEFINITIONS_DIRECTORY = "Definitions/";
    public static final String KEY_ENTRY_MANIFEST = "Entry-Manifest";
    public static final String KEY_VNF_PRODUCT_NAME = "vnf_product_name";
    public static final String KEY_VNF_PROVIDER_ID = "vnf_provider_id";
    public static final String KEY_VNF_PACKAGE_VERSION = "vnf_package_version";
    public static final String KEY_VNF_RELEASE_DATA_TIME = "vnf_release_date_time";

    public VnfPkgInfo populateVnfPackageInfo(String vnfPkgId, Resource vnfPackageZip) {

        logger.info("Extracting VNF package info from VNF package with id [{}]", vnfPkgId);

        VnfPkgInfo vnfPkgInfo = new VnfPkgInfo();
        vnfPkgInfo.setId(vnfPkgId);

        try {
            String toscaMetadata = ensureToscaMetadata(vnfPackageZip, vnfPkgId);
            Map<String, String> toscaMetaData = parseManifestFile(toscaMetadata);
            String entryManifestPath = toscaMetaData.get(KEY_ENTRY_MANIFEST);
            if (entryManifestPath == null) {
                throw new VNFPackageExtractionException(String.format("Unable to locate [%s] definition within [%s] for Vnf Package with id [%s]", KEY_ENTRY_MANIFEST, PATH_TOSCA_METADATA, vnfPkgId));
            }

            byte[] entryManifestByteArray = extractArtifactFromZip(vnfPackageZip, entryManifestPath);
            if (entryManifestByteArray == null) {
                throw new VNFPackageExtractionException(String.format("Unable to locate Entry Manifest definition on path [%S] within Vnf Package with id [%s]", entryManifestPath, vnfPkgId));
            }
            Map<String, String> entryManifest = parseManifestFile(new String(entryManifestByteArray));
            vnfPkgInfo.setVnfProductName(entryManifest.get(KEY_VNF_PRODUCT_NAME));
            vnfPkgInfo.setVnfProvider(entryManifest.get(KEY_VNF_PROVIDER_ID));

        } catch (IOException e) {
            handleGenericExtractionException(e, vnfPkgId);
        }

        return vnfPkgInfo;
    }

    public String extractVnfdAsYaml(String vnfPkgId, Resource vnfPackageZip) throws ResponseTypeNotAcceptableException {

        logger.info("Extracting VNFD yaml from VNF package with id [{}]", vnfPkgId);

        try {
            // verify package is in the format that includes a TOSCA-Metadata directory
            ensureToscaMetadata(vnfPackageZip, vnfPkgId);

            Map<String, byte[]> definitions = extractArtifactsFromZip(vnfPackageZip, PATH_TOSCA_DEFINITIONS_DIRECTORY);
            if (definitions.isEmpty()) {
                throw new VNFPackageExtractionException(String.format("Unable to find any Definitions within VnfPackage with id [%s]", vnfPkgId));
            } else if (definitions.size() > 1) {
                throw new ResponseTypeNotAcceptableException(String.format("Found multiple VNFDs when expecting only one within VnfPackage with id [%s]", vnfPkgId));
            }
            Entry<String, byte[]> definitionEntry = definitions.entrySet().iterator().next();
            logger.info("Located VNFD yaml on path [{}] from VNF package with id [{}]", definitionEntry.getKey(), vnfPkgId);
            return new String(definitionEntry.getValue());
        } catch (IOException e) {
            handleGenericExtractionException(e, vnfPkgId);
        }
        return null;
    }

    public Resource extractVnfdAsZip(String vnfPkgId, Resource vnfPackageZip) throws ResponseTypeNotAcceptableException {

        logger.info("Extracting VNFD zip package from VNF package with id [{}]", vnfPkgId);

        try {
            // verify package is in the format that includes a TOSCA-Metadata directory
            ensureToscaMetadata(vnfPackageZip, vnfPkgId);

            Map<String, byte[]> metadataArtifacts = extractArtifactsFromZip(vnfPackageZip, PATH_TOSCA_METADATA_DIRECTORY);
            if (metadataArtifacts.isEmpty()) {

            }
            Map<String, byte[]> definitions = extractArtifactsFromZip(vnfPackageZip, PATH_TOSCA_DEFINITIONS_DIRECTORY);
            if (definitions.isEmpty()) {
                throw new VNFPackageExtractionException(String.format("Unable to find any Definitions within VnfPackage with id [%s]", vnfPkgId));
            }

            // combine metadata into definitions and rezip
            definitions.putAll(metadataArtifacts);
            Resource definitionsAsZip = createZipFromArtifacts(definitions);
            return definitionsAsZip;

        } catch (IOException e) {
            handleGenericExtractionException(e, vnfPkgId);
        }
        return null;
    }

    private Map<String, String> parseManifestFile(String manifestFile) {

        Map<String, String> manifestEntries = new HashMap<String, String>();
        String[] lines = manifestFile.split("\n");
        int indexOfSeparator;
        for (String line : lines) {
            if ((indexOfSeparator = line.indexOf(":")) > 0) {
                String key = line.substring(0, indexOfSeparator).trim();
                String value = line.substring(indexOfSeparator + 1).trim();
                manifestEntries.put(key, value);
            }
        }
        return manifestEntries;
    }

    private String ensureToscaMetadata(Resource vnfPackageZip, String vnfPkgId) throws IOException {

        byte[] toscaMetadataByteArray = extractArtifactFromZip(vnfPackageZip, PATH_TOSCA_METADATA);
        if (toscaMetadataByteArray == null) {
            throw new VNFPackageExtractionException(String.format("Unable to locate Tosca Metadata File on path [%s] within Vnf Package with id [%s]", PATH_TOSCA_METADATA, vnfPkgId));
        }
        logger.info("VNF package with id [{}] mactches the expected Tosca format.", vnfPkgId);

        return new String(toscaMetadataByteArray);
    }

}
