# Configuring a package repository for retrieving VNF Packages

The VNFM driver can be configured with a location from which it can retrieve VNF packages. This can be configured via the Helm values file by setting the following property during the Helm install.

**Currently, only Sonatype Nexus repositories are supported**

It is assumed that each VNF package will be stored as two files:
- `{vnfPackageId}.pkgInfo` - A JSON representation of the VnfPkgInfo for the package
- `{vnfPackageId}.zip` - A zip file containing the full VNF package

These file should be present in the same directory on the Nexus repository (configurable below).

###### Example of values passed to Helm chart during install
```yaml
app:
  config:
    packageRepositoryUrl: "http://package-server:8081"
    repositoryName: vnfm-packages
    nexusGroupName: path/to/files
```

**NOTES**:
- the `packageRepositoryUrl` must reference the Sonatype Nexus instance
  - **IMPORTANT: This is different to previous versions**
- the `repositoryName` should match a repository within Nexus (should be of type "raw")
- the `nexusGroupName` property should match the base path where the files reside in the Nexus repository

### Authentication

If required, authentication details for communicating with Nexus can be supplied as follows (during the Helm install)
```yaml
app:
  config:
    authenticationProperties:
      type: BASIC
      username: jack
      password: jack
```

