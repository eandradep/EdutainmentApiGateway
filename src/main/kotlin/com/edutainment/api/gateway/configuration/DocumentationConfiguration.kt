package com.edutainment.api.gateway.configuration

import org.springdoc.core.GroupedOpenApi
import org.springframework.cloud.gateway.route.RouteDefinition
import org.springframework.cloud.gateway.route.RouteDefinitionLocator
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/**
 * This class is responsible for configuring documentation.
 */
@Configuration
class DocumentationConfiguration {

    /**
     * Retrieves a list of GroupedOpenApi objects based on the provided RouteDefinitionLocator.
     *
     * @param locator The RouteDefinitionLocator used to find route definitions.
     * @return A list of GroupedOpenApi objects.
     */
    @Bean
    fun apis(locator: RouteDefinitionLocator): List<GroupedOpenApi> {
        val groups: List<GroupedOpenApi> = ArrayList()
        val definitions = locator.routeDefinitions.collectList().block()!!
        definitions.stream().filter { routeDefinition: RouteDefinition ->
            routeDefinition.id.matches(regex = Regex(".*-service"))
        }.forEach { routeDefinition: RouteDefinition ->
            val name = routeDefinition.id.replace("-service".toRegex(), "")
            GroupedOpenApi.builder().pathsToMatch("/$name/**").group(name).build()
        }
        return groups
    }

}