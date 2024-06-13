# Adding a SOL003-compliant VNFM as a Deployment Location in ALM

The deployment location for the target VNFM can be added in the TNC-O UI, supplying the following information for infrastructure properties.

###### Example of JSON structure for Deployment Location
```jsonc
{
    "vnfmServerUrl": "http://vnfm-test-harness:8297",
    # Authentication details
    "authenticationType": "BASIC",
    "username": "xxx",
    "password": "yyy"
}
```

##### Examples of Authentication Details

###### Basic Authentication

```jsonc
{
    "authenticationType": "BASIC",
    "username": "xxx",
    "password": "yyy"
}
```

###### OAuth2 Authentication

```jsonc
{
    "authenticationType": "OAUTH2",
    "accessTokenUri": "https://vnfm:port/oauth2/token",
    "client_id": "",
    "client_secret": "",
    "grant_type": "",                                   # Optional
    "scope": ""                                         # Optional
}
```

###### Cookie-based Session Authentication

```jsonc
{
    "authenticationType": "COOKIE",
    "authenticationUrl": "",
    "username": "xxx",
    "password": "yyy",
    "usernameTokenName": "",                # Optional (default: IDToken1)
    "passwordTokenName": ""                 # Optional (default: IDToken2)
}
```

## Subscribing to VnfLcmOpOcc notifications from the VNFM

In order for the driver to receive lifecycle notifications from the VNFM, the following command should be run.

**NOTES**:
- It is important that the command is run from a location where the VNFM can be reached
- The address (for the driver) used in the content of the message below should be considered from the point of view of the VNFM itself (in cases where addresses or ports may be subject to NAT or proxying) 

```bash
curl -X POST \
  http://vnfm-address:port/vnflcm/v2/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{
    "callbackUri" : "https://sol003-lifecycle-driver:8296/vnflcm/v2/notifications",
    "filter" : {
      "notificationTypes" : [ "VnfLcmOperationOccurrenceNotification" ],
      "operationStates" : [ "COMPLETED", "FAILED", "FAILED_TEMP", "ROLLED_BACK" ]
    }
}'
```