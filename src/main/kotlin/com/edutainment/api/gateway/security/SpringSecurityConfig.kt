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
                "/edutainment/person/userProfileController/findStudents",
                "/edutainment/repositorie/api/crud/tags/{id}",
            ).hasRole("ADMIN")
            .pathMatchers(
                HttpMethod.POST,
                "/edutainment/repositorie/api/crud/tags",
            ).hasRole("ADMIN")
            .pathMatchers(
                HttpMethod.DELETE,
                "/edutainment/repositorie/api/crud/tags/**",
            ).hasRole("ADMIN")
            .pathMatchers(
                HttpMethod.PATCH,
                "/edutainment/repositorie/api/crud/tags/**",
            ).hasRole("ADMIN")

//            COMBINATED ROLES
            .pathMatchers(
                "/edutainment/dialogues/sequenceController/**",
                "/edutainment/person/userProfileController/findPersonByID/{personID}",
                "/edutainment/person/userProfileController/updatePerson/{personID}",
                "/edutainment/person/userProfileController/findPersonByUserID/{userId}",
//
                "/edutainment/repositorie/api/crud/tags",
            ).hasAnyRole("ADMIN", "USER")

            .pathMatchers(
                HttpMethod.POST,
                "/edutainment/repositorie/api/crud/resources",
                "/edutainment/repositorie/api/crud/repositories",
                "/edutainment/repositorie/api/crud/games",
                "/edutainment/filesystem/api/data/delete/resource",
                "/edutainment/filesystem/api/data/delete/repositorie",
                "/edutainment/filesystem/api/data/upload",
            ).hasAnyRole("ADMIN", "USER")
            .pathMatchers(
                HttpMethod.GET,
                "/edutainment/repositorie/api/crud/resources/**",
                "/edutainment/repositorie/api/crud/resources/slug/**",
            ).hasAnyRole("ADMIN", "USER")
            .pathMatchers(
                HttpMethod.PATCH,
                "/edutainment/repositorie/api/crud/resources/**",
                "/edutainment/repositorie/api/crud/repositories/**",
                "/edutainment/repositorie/api/crud/games/**",
            ).hasAnyRole("ADMIN", "USER")
            .pathMatchers(
                HttpMethod.DELETE,
                "/edutainment/repositorie/api/crud/repositories/**",
                "/edutainment/repositorie/api/crud/games/**"
            ).hasAnyRole("ADMIN", "USER")
            .pathMatchers(
                HttpMethod.PUT,
                "/edutainment/filesystem/api/data/update/resource",
                "/edutainment/filesystem/api/data/update-names",
            ).hasAnyRole("ADMIN", "USER")


//            OPEN SERVICES

            .pathMatchers(
                "/edutainment/oauth/**",
                "/edutainment/person/genderController/findAllGender",
                "/edutainment/person/userProfileController/createPerson",
                "/edutainment/repositorie/api/crud/tags",
                "/edutainment/repositorie/api/crud/tags/search/{name}",
                "/edutainment/repositorie/api/crud/resources",
                "/edutainment/repositorie/api/crud/resources/search",
                "/edutainment/repositorie/api/crud/resources/kind",
                "/edutainment/repositorie/api/crud/repositories/**",
                "/edutainment/repositorie/api/crud/repositories/slug/**",
                "/edutainment/repositorie/api/crud/games",
                "/edutainment/repositorie/api/crud/games/**",
                "/edutainment/repositorie/api/crud/games/slug/**",
                "/edutainment/filesystem/api/data/download",
            ).permitAll()
            .pathMatchers(HttpMethod.GET).access { _, exchange ->
                Mono.just(
                    AuthorizationDecision(
                        exchange.exchange.request.uri.path.contains("webjars/swagger-ui")
                                or
                                exchange.exchange.request.uri.path.contains("v3/api-docs")
                                or
                                exchange.exchange.request.uri.path.contains("encrypt-internal-controller/encrypt-password")
                    )
                )
            }
            .anyExchange().authenticated()
            .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .csrf().disable()
            .build()
    }


}