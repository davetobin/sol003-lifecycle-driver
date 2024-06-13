package com.accantosystems.stratoss.vnfmdriver.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.kafka.annotation.EnableKafka;
import org.springframework.kafka.core.KafkaTemplate;

import com.accantosystems.stratoss.vnfmdriver.driver.VNFLifecycleManagementDriver;
import com.accantosystems.stratoss.vnfmdriver.service.ExternalMessagingService;
import com.accantosystems.stratoss.vnfmdriver.service.LcmOpOccPollingService;
import com.accantosystems.stratoss.vnfmdriver.service.impl.KafkaExternalMessagingServiceImpl;
import com.accantosystems.stratoss.vnfmdriver.service.impl.LoggingExternalMessagingServiceImpl;
import com.fasterxml.jackson.databind.ObjectMapper;

@Configuration("KafkaConfiguration")
public class KafkaConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(KafkaConfiguration.class);

    @Configuration("KafkaConfigurationEnabled")
    @ConditionalOnProperty(value = "vnfmdriver.kafka.enabled", matchIfMissing = true)
    @EnableKafka
    public static class KafkaConfigurationEnabled {

        @Bean
        @Primary
        public ExternalMessagingService getKafkaEMS(VNFMDriverProperties properties, KafkaTemplate<String, String> kafkaTemplate, ObjectMapper objectMapper) {
            logger.info("Creating Kafka EMS Bus Connector");
            return new KafkaExternalMessagingServiceImpl(properties, kafkaTemplate, objectMapper);
        }

        @Bean
        public LcmOpOccPollingService lcmOpOccPollingService(VNFLifecycleManagementDriver driver, ExternalMessagingService externalMessagingService, ObjectMapper objectMapper) {
            return new LcmOpOccPollingService(driver, externalMessagingService, objectMapper);
        }
    }

    @Bean
    @ConditionalOnMissingBean
    public ExternalMessagingService getLoggingEMS() {
        logger.info("Creating Logging EMS Bus Connector");
        return new LoggingExternalMessagingServiceImpl();
    }

}