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
                ->arrayNode('db_connection')
                    ->children()
                        ->scalarNode('name')->defaultValue('')->end()
                    ->end()                    
                ->end()
                ->arrayNode('tresholds_governor_params')
                    ->children()
                        ->scalarNode('counterDurationInSeconds')->defaultValue(180)->end()
                        ->scalarNode('blockUsernamesFor')->defaultValue('25 minutes')->end()
                        ->scalarNode('limitPerUserName')->defaultValue(3)->end()
                        ->scalarNode('blockIpAddressesFor')->defaultValue('17 minutes')->end()
                        ->scalarNode('limitBasePerIpAddress')->defaultValue(10)->end()
                        ->scalarNode('allowReleasedUserOnAddressFor')->defaultValue('30 days')->end()
                        ->scalarNode('releaseUserOnLoginSuccess')->defaultValue(false)->end()
                        ->scalarNode('keepCountsFor')->defaultValue('4 days')->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
