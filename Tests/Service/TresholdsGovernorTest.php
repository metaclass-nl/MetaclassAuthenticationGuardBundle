<?php

namespace Metaclass\AuthenticationGuardBundle\Tests\Service;

use Metaclass\TresholdsGovernor\Tests\Service\FunctionalTest;

/**
 * To run Metaclass\TresholdsGovernor\Tests\Service\FunctionalTest with
 * doctrines default connection.
 */
class TresholdsGovernorTest extends FunctionalTest // \PHPUnit_Framework_TestCase
{
    public function setup()
    {
        global $kernel;
        if (!isset($kernel)) {
            $kernel = new \AppKernel('test', true);
            $kernel->boot();
        }
        if ('AppCache' == get_class($kernel)) {
            $kernel = $kernel->getKernel();
        }
        $container = $kernel->getContainer();
        $connectionName = $container->getParameter('metaclass_auth_guard.db_connection.name');
        $this->assertNotNull($connectionName, 'metaclass_auth_guard.db_connection.name');

        $doctrine = $container->get('doctrine');
        $connection = $doctrine->getConnection($connectionName);
        $this->assertNotNull($connection, 'connection retieved from doctrine service');

        $service = $container->get('metaclass_auth_guard.tresholds_governor');
        $this->assertNotNull($service, 'metaclass_auth_guard.tresholds_governor');

        //we don't want to to use the same governor that may be used in handling the request to the UnitTestController
        $this->governor = clone $service;

        $this->governor->dtString = '1980-07-01 00:00:00';
        $this->governor->counterDurationInSeconds = 300; //5 minutes
        $this->governor->blockUsernamesFor = '30 days';
        $this->governor->blockIpAddressesFor = '30 days'; //not very realistic, but should still work
        $this->governor->allowReleasedUserOnAddressFor = '30 days';
        $this->governor->allowReleasedUserByCookieFor = '10 days';

        $this->statisticsManager = $container->get('metaclass_auth_guard.statistics_manager');
    }
}
