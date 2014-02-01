<?php

namespace Metaclass\AuthenticationGuardBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * This is the class that validates and merges configuration from your app/config files
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html#cookbook-bundles-extension-config-class}
 */
class Configuration implements ConfigurationInterface
{
    /**
     * {@inheritDoc}
     */
    public function getConfigTreeBuilder()
    {
        $treeBuilder = new TreeBuilder();
        $rootNode = $treeBuilder->root('metaclass_authentication_guard');

        $rootNode
            ->children()
                ->arrayNode('entity_manager_login')
                    ->children()
                        ->scalarNode('name')->defaultValue('')->end()
                    ->end()                    
                ->end()
                ->arrayNode('tresholds_governor_params')
                    ->children()
                        ->scalarNode('counterDurationInSeconds')->defaultValue(300)->end()
                        ->scalarNode('blockUsernamesFor')->defaultValue('30 days')->end()
                        ->scalarNode('limitPerUserName')->defaultValue(3)->end()
                        ->scalarNode('blockIpAddressesFor')->defaultValue('15 minutes')->end()
                        ->scalarNode('limitBasePerIpAddress')->defaultValue(10)->end()
                        ->scalarNode('allowReleasedUserOnAddressFor')->defaultValue('30 days')->end()
                        ->scalarNode('allowReleasedUserOnAgentFor')->defaultValue('10 days')->end()
                        ->scalarNode('releaseUserOnLoginSuccess')->defaultValue(false)->end()
                        ->scalarNode('distinctiveAgentMinLength')->defaultValue(30)->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
