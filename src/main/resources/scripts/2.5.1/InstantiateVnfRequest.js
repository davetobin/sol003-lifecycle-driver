print('Generating InstantiateVnfRequest message for ETSI SOL003 v2.5.1');

var message = {};
message['vnfdId'] = 'xxx-xxx-xxx-xxx';
message.vnfInstanceName = executionRequest.getLifecycleName();
message.vnfInstanceDescription = executionRequest.getProperties().get('description');

logger.debug('Message generated successfully');

JSON.stringify(message);