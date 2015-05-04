package org.osiam.resource_server;

import java.util.Arrays;

import javax.servlet.Filter;

import org.osiam.resource_server.security.authorization.AccessTokenValidationService;
import org.osiam.resource_server.security.authorization.DynamicHTTPMethodScopeEnhancer;
import org.osiam.resource_server.security.helper.SSLRequestLoggingFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.vote.ScopeVoter;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

@SpringBootApplication
@EnableWebMvc
@EnableWebMvcSecurity
@EnableTransactionManagement
@RestController
@EnableAspectJAutoProxy(proxyTargetClass = true)
public class ResourceServer {

    private static final Logger LOG = LoggerFactory.getLogger(ResourceServer.class);

    public static void main(String[] args) {
        System.err.println("Configuration Location: " + args[0]);
        SpringApplication.run(ResourceServer.class, args);
    }

    @Bean
    public Filter characterEncodingFilter() {
        CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
        characterEncodingFilter.setEncoding("UTF-8");
        characterEncodingFilter.setForceEncoding(true);
        return characterEncodingFilter;
    }

    @Bean
    public Filter createSSLFilter() {
        return new SSLRequestLoggingFilter();
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    // @Bean
    // public MeasureDurationTimeOfMethods createProfiling() {
    // return new MeasureDurationTimeOfMethods();
    // }

    // @Bean(initMethod = "migrate")
    // @Autowired
    // public Flyway flyway(DataSource dataSource) {
    // Flyway flyway = new Flyway();
    // flyway.setBaselineOnMigrate(true);
    // flyway.setDataSource(dataSource);
    // flyway.setLocations("db/migration/postgresql");
    // flyway.setTable("resource_server_schema_version");
    // MigrationVersion version = MigrationVersion.fromVersion("0");
    // flyway.setBaselineVersion(version);
    // return flyway;
    // }

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Autowired
        private AccessTokenValidationService accessTokenValidationService;

        @Bean
        public OAuth2AuthenticationEntryPoint createEntryPoint() {
            OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
            entryPoint.setRealmName("oauth2-authorization-server");
            return entryPoint;
        }

        @Bean
        public OAuth2AccessDeniedHandler createOauthAccessDeniedHandler() {
            return new OAuth2AccessDeniedHandler();
        }

        @Bean
        public UnanimousBased accessDecisionManager() {
            DynamicHTTPMethodScopeEnhancer dynamicHTTPMethodScopeEnhancer = new DynamicHTTPMethodScopeEnhancer(
                    new ScopeVoter());
            return new UnanimousBased(Arrays.asList(new AccessDecisionVoter[] { dynamicHTTPMethodScopeEnhancer }));
        }

        @Bean
        public ShaPasswordEncoder passwordEncoder() {
            ShaPasswordEncoder passwordEncoder = new ShaPasswordEncoder(512);
            passwordEncoder.setIterations(1000);
            return passwordEncoder;
        }

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) {
            resources
                    .resourceId("oauth2res")
                    .tokenServices(accessTokenValidationService);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/**").hasRole("SCOPE_DYNAMIC");
            http
                    .exceptionHandling()
                    .accessDeniedHandler(createOauthAccessDeniedHandler());
        }
    }
}
