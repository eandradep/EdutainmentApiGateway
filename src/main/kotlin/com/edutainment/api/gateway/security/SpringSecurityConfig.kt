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
//            .let { getAdminConfigurations(it) }
            .let { getAdminRepositoryConfigurations(it) }
//            .let { getUserConfigurations(it) }
//            .let { getAdminUserConfigurations(it) }

            .let { getNoAuthRequiredConfigurations(it) }

//            COMBINATED ROUTES ADMIN AND USER

//            OPEN PATHS.

            .anyExchange().authenticated()
            .and().addFilterAt(authenticationFilter, SecurityWebFiltersOrder.AUTHENTICATION)
            .csrf().disable()
            .build()
    }

    /**
     * Retrieves the admin configurations for the given ServerHttpSecurity.AuthorizeExchangeSpec.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec to configure the admin configurations.
     * @return The configured ServerHttpSecurity.AuthorizeExchangeSpec with admin configurations.
     */
    private fun getAdminConfigurations(http: ServerHttpSecurity.AuthorizeExchangeSpec): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                HttpMethod.POST,
                "/edutainment/repositorie/api/crud/tags",
            )
            .hasRole("ADMIN")
            .pathMatchers(
                HttpMethod.DELETE,
                "/edutainment/repositorie/api/crud/tags/{id}",
            )
            .hasRole("ADMIN")
            .pathMatchers(
                HttpMethod.PATCH,
                "/edutainment/repositorie/api/crud/tags/{id}",
            )
            .hasRole("ADMIN")
            .pathMatchers(
//                ADMIN ROUTES
                HttpMethod.GET,
                "/edutainment/person/userProfileController/findPersonByIdentification/**",
                "/edutainment/person/userProfileController/findStudents",
                "/edutainment/repositorie/api/crud/tags/**",
                "/edutainment/project/projectController/findAllProjects/**",
            )
            .hasRole("ADMIN")

    }

    /**
     * Configures the admin repository configurations for the given ServerHttpSecurity.AuthorizeExchangeSpec instance.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec instance to configure.
     * @return The configured ServerHttpSecurity.AuthorizeExchangeSpec.
     */
    private fun getAdminRepositoryConfigurations(
        http: ServerHttpSecurity.AuthorizeExchangeSpec
    ): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                HttpMethod.POST,
                "/edutainment/filesystem/api/data/upload",
                "/edutainment/filesystem/api/data/delete/resource",
                "/edutainment/filesystem/api/data/delete/repositorie",
                "/edutainment/repositorie/api/crud/games/createGame",
                "/edutainment/repositorie/api/crud/repositories/createRepositorie",
                "/edutainment/repositorie/api/crud/resources/createResource",
                "/edutainment/repositorie/api/crud/tags/createTag",
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.PUT,
                "/edutainment/filesystem/api/data/update/resource",
                "/edutainment/filesystem/api/data/update-names",
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.PATCH,
                "/edutainment/repositorie/api/crud/games/updateGameById/{id}",
                "/edutainment/repositorie/api/crud/repositories/updateRepositorieById/{id}",
                "/edutainment/repositorie/api/crud/resources/updateResourceById/{id}",
                "/edutainment/repositorie/api/crud/tags/updateTagById/{id}",
            ).hasAnyRole("ADMIN", "REPOSITORY")
            .pathMatchers(
                HttpMethod.DELETE,
                "/edutainment/repositorie/api/crud/games/deleteGameById/{id}",
                "/edutainment/repositorie/api/crud/repositories/deleteRepositorieById/{id}",
                "/edutainment/repositorie/api/crud/resources/deleteResourceById/{id}",
                "/edutainment/repositorie/api/crud/tags/deleteTagById/{id}",
            ).hasAnyRole("ADMIN", "REPOSITORY")
    }

    /**
     * Retrieves the configurations for admin users in the HTTP security.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec to configure the admin user configurations.
     * @return The modified ServerHttpSecurity.AuthorizeExchangeSpec with the admin user configurations applied.
     */
    private fun getAdminUserConfigurations(
        http: ServerHttpSecurity.AuthorizeExchangeSpec
    ): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                HttpMethod.GET,
                "/edutainment/person/userProfileController/findPersonByID/**",
                "/edutainment/person/userProfileController/updatePerson/**",
                "/edutainment/person/userProfileController/findPersonByUserID/**",
                "/edutainment/project/projectController/findProjectById/**",
                "/edutainment/game/entryRecordController/findRegisterByPersonAndGameId/**",
                "/edutainment/game/gameController/finGameById/**",
                "/edutainment/game/gameController/findGameByProjectId/**",
            )
            .hasAnyRole("ADMIN", "USER")

    }

    private fun getUserConfigurations(
        http: ServerHttpSecurity.AuthorizeExchangeSpec
    ): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(
                HttpMethod.POST,
                "/edutainment/game/entryRecordController/createEntryRecord",
            )
            .hasAnyRole("ADMIN", "USER")

    }

    /**
     * Retrieves the configurations for endpoints that do not require authentication.
     *
     * @param http The ServerHttpSecurity.AuthorizeExchangeSpec instance to configure.
     * @return The configured ServerHttpSecurity.AuthorizeExchangeSpec.
     */
    private fun getNoAuthRequiredConfigurations(
        http: ServerHttpSecurity.AuthorizeExchangeSpec
    ): ServerHttpSecurity.AuthorizeExchangeSpec {
        return http
            .pathMatchers(HttpMethod.OPTIONS,
                "/**")
            .permitAll()
            .pathMatchers(
                "/edutainment/oauth/**",
                "/edutainment/person/genderController/findAllGender",
                "/edutainment/person/userProfileController/createPerson",
                "/edutainment/student/student-controller/createStudent",

                "/edutainment/repositorie/api/crud/games/findGameById/{id}",
                "/edutainment/repositorie/api/crud/games/findGameBySlug/{slug}",
                "/edutainment/repositorie/api/crud/games/findAllGamesByPagination",
                "/edutainment/repositorie/api/crud/repositories/findRepositorieById/{id}",
                "/edutainment/repositorie/api/crud/repositories/findRepositorieBySlug/{slug}",
                "/edutainment/repositorie/api/crud/repositories/findAllRepositoriesByPagination",
                "/edutainment/repositorie/api/crud/resources/findResourceById/{id}",
                "/edutainment/repositorie/api/crud/resources/findResourceBySlug/{slug}",
                "/edutainment/repositorie/api/crud/resources/findAllResourcesByPagination",
                "/edutainment/repositorie/api/crud/resources/findAllResourcesPaginatedByName/search",
                "/edutainment/repositorie/api/crud/resources/findAllResourcesPaginatedByKindAndTags/kind",
                "/edutainment/repositorie/api/crud/resources/findAllResourcesPaginatedByKindAndTags/kind",

                "/edutainment/repositorie/api/crud/tags/findTagById/{id}",
                "/edutainment/repositorie/api/crud/tags/findAllTagsByPagination",
                "/edutainment/repositorie/api/crud/tags/findAllTagsPaginatedByName/{name}",

                "/edutainment/filesystem/api/data/download-resource",
                "/edutainment/media-references/**",
                "/edutainment/resources/**",
            )
            .permitAll()
            .pathMatchers(HttpMethod.GET).access { _, exchange ->
                Mono.just(
                    AuthorizationDecision(
                        exchange.exchange.request.uri.path.contains("webjars/swagger-ui")
                                or
                                exchange.exchange.request.uri.path.contains("v3/api-docs")
                    )
                )
            }

    }

}