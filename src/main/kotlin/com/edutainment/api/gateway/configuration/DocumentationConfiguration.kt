package com.edutainment.api.gateway.configuration

import org.springdoc.core.GroupedOpenApi
import org.springframework.cloud.gateway.route.RouteDefinition
import org.springframework.cloud.gateway.route.RouteDefinitionLocator
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class DocumentationConfiguration {

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