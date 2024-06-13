/*
 This is the generic message creation logic for ChangeExtVnfConnectivityRequest messages based on the 3.5.1 version of the ETSI SOL003 specification
 */
logger.debug('Generating ChangeExtVnfConnectivityRequest message for ETSI SOL003 v3.5.1');
load('classpath:scripts/lib.js');

// Create the message object to be returned
var message = {extVirtualLinks: {}, vimConnectionInfo: {}, additionalParams: {}};

for (var key in executionRequest.getProperties()) {
    if (key.startsWith('additionalParams.') || key.startsWith('extVirtualLinks.') || key.startsWith('vimConnectionInfo.')) {
        // print('Got property [' + key + '], value = [' + executionRequest.properties[key] + ']');
        addProperty(message, key, executionRequest.properties[key]);
    }
}

logger.debug('Message generated successfully');
// Turn the message object into a JSON string to be returned back to the Java driver
JSON.stringify(message);