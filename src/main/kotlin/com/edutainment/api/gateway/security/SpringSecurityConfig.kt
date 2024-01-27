package com.edutainment.api.gateway.security

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpMethod
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.SecurityWebFiltersOrder
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import reactor.core.publisher.Mono


@EnableWebFluxSecurity
class SpringSecurityConfig {


    @Autowired
    private lateinit var authenticationFilter: JwtAuthenticationFilter

    @Bean
    fun configure(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http.authorizeExchange()

//            ADMIN ROLES

            .pathMatchers(
                HttpMethod.GET,
                "/edutainment/person/userProfileController/findPersonByIdentification/{personIdentification}",
                "/edutainment/person/userProfileController/findStudents"
            ).hasRole("ADMIN")

//            USER LOGED ROLES

            .pathMatchers(
                "/edutainment/dialogues/sequenceController/**",
                "/edutainment/person/userProfileController/findPersonByID/{personID}",
                "/edutainment/person/userProfileController/updatePerson/{personID}",
                "/edutainment/person/userProfileController/createPerson"
            ).hasAnyRole("ADMIN", "USER")

//            OPEN SERVICES

            .pathMatchers(
                "/edutainment/oauth/**",
                "/edutainment/person/genderController/findAllGender").permitAll()
            .pathMatchers(HttpMethod.GET).access { _, exchange ->
                Mono.just(
                    AuthorizationDecision(
                        exchange.exchange.request.uri.path.contains("webjars/swagger-ui")
                                or
                                exchange.exchange.request.uri.path.contains("v3/api-docs")
                    )
                )
            }
            .anyExchange().authenticated()
            .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .csrf().disable()
            .build()
    }


}