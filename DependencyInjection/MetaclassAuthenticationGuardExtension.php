<?php

namespace Metaclass\AuthenticationGuardBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * Loads and manages your bundle configuration.
 */
class MetaclassAuthenticationGuardExtension extends Extension
{
    /**
     * {@inheritdoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        $container->setParameter('metaclass_auth_guard.db_connection.name', $config['db_connection']['name']);
        $container->setParameter('metaclass_auth_guard.ui.dateTimeFormat', $config['ui']['dateTimeFormat']);
        $container->setParameter('metaclass_auth_guard.statistics.template', $config['ui']['statistics']['template']);
        $container->setParameter('metaclass_auth_guard.tresholds_governor_params', $config['tresholds_governor_params']);

        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yml');
    }
}
