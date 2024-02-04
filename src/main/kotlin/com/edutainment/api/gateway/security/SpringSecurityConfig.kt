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


/**
 * The `SpringSecurityConfig` class is responsible for configuring the HTTP security for the application.
 *
 * @constructor Creates a new instance of the `SpringSecurityConfig` class.
 */
@EnableWebFluxSecurity
class SpringSecurityConfig {


    /**
     * The `authenticationFilter` property is a Spring WebFilter that performs JWT token authentication.
     * It is used to authenticate requests using a JWT token.
     *
     * @property authenticationFilter The JwtAuthenticationFilter instance.
     * @see JwtAuthenticationFilter
     */
    @Autowired
    private lateinit var authenticationFilter: JwtAuthenticationFilter

    /**
     * Configures the HTTP security for the application.
     *
     * @param http The ServerHttpSecurity instance to configure.
     * @return The configured SecurityWebFilterChain.
     */
    @Bean
    fun configure(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http.authorizeExchange()
            .let { setupAdminRoles(it) }
            .let { setupCombinedRolesAdminRepository(it) }
            .let { setupCombinedRolesAdminUser(it) }
            .let { setupOpenServices(it) }
            .anyExchange().authenticated()
            .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .csrf().disable()
            .build()
    }

    /**
     * Sets up the admin roles for authorization.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec instance to configure.
     * @return The configured ServerHttpSecurity.AuthorizeExchangeSpec instance.
     */
    private fun setupAdminRoles(http: ServerHttpSecurity.AuthorizeExchangeSpec): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                HttpMethod.GET,
                "/edutainment/person/userProfileController/findPersonByIdentification/{personIdentification}",
                "/edutainment/person/userProfileController/findStudents",
                "/edutainment/repositorie/api/crud/tags/{id}",
            )
            .hasRole("ADMIN")
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
    }

    /**
     * Setup combined roles for specific paths in the HTTP security configuration.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec object.
     * @return The modified ServerHttpSecurity.AuthorizeExchangeSpec object.
     */
    private fun setupCombinedRolesAdminRepository(http: ServerHttpSecurity.AuthorizeExchangeSpec): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                "/edutainment/dialogues/sequenceController/**",
                "/edutainment/person/userProfileController/findPersonByID/{personID}",
                "/edutainment/person/userProfileController/updatePerson/{personID}",
                "/edutainment/person/userProfileController/findPersonByUserID/{userId}",
                "/edutainment/repositorie/api/crud/tags",
            )
            .hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.POST,
                "/edutainment/repositorie/api/crud/resources",
                "/edutainment/repositorie/api/crud/repositories",
                "/edutainment/repositorie/api/crud/games",
                "/edutainment/filesystem/api/data/delete/resource",
                "/edutainment/filesystem/api/data/delete/repositorie",
                "/edutainment/filesystem/api/data/upload",
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.GET,
                "/edutainment/repositorie/api/crud/resources/**",
                "/edutainment/repositorie/api/crud/resources/slug/**",
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.PATCH,
                "/edutainment/repositorie/api/crud/resources/**",
                "/edutainment/repositorie/api/crud/repositories/**",
                "/edutainment/repositorie/api/crud/games/**",
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.DELETE,
                "/edutainment/repositorie/api/crud/repositories/**",
                "/edutainment/repositorie/api/crud/games/**"
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.PUT,
                "/edutainment/filesystem/api/data/update/resource",
                "/edutainment/filesystem/api/data/update-names",
            ).hasAnyRole("ADMIN", "REPOSITORY")
    }
    private fun setupCombinedRolesAdminUser(http: ServerHttpSecurity.AuthorizeExchangeSpec): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                "/edutainment/dialogues/sequenceController/**",
                "/edutainment/person/userProfileController/findPersonByID/{personID}",
                "/edutainment/person/userProfileController/updatePerson/{personID}",
                "/edutainment/person/userProfileController/findPersonByUserID/{userId}",
            )
            .hasAnyRole("ADMIN", "USER")

    }

    /**
     * Sets up the open services for authorization.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec object.
     * @return The modified ServerHttpSecurity.AuthorizeExchangeSpec object with open services configuration.
     */
    private fun setupOpenServices(http: ServerHttpSecurity.AuthorizeExchangeSpec): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                "/edutainment/oauth/**",
                "/edutainment/person/genderController/findAllGender",
                "/edutainment/person/userProfileController/createPerson",
                "/edutainment/student/student-controller/createStudent",
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
            )
            .permitAll()
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
    }


}