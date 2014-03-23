<?php 
namespace Metaclass\AuthenticationGuardBundle\Tests\Service;

use Metaclass\TresholdsGovernor\Tests\Service\TresholdsGovernorTest as Delegate;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

class TresholdsGovernorTest extends WebTestCase // \PHPUnit_Framework_TestCase 
{
    function setup() 
    {
        global $kernel;
        if (!isSet($kernel)) {
            $kernel = static::createKernel();
            $kernel->boot();
        }
        if ('AppCache' == get_class($kernel)) {
            $kernel = $kernel->getKernel();
        }
        $container = $kernel->getContainer();
        
        $service = $container->get('metaclass_auth_guard.tresholds_governor');
        
        $this->delegate = new Delegate();
        //we don't want to to use the same governor that may be used in handling the request to the UnitTestController
        $this->delegate->governer = clone $service;
        $this->delegate->setup();
    }

    
    function testGetRequestCountsDt()
    {
        $this->delegate->testGetRequestCountsDt();
    }
    
    function testInitFor() 
    {
        $this->delegate->testInitFor();
    }
    
    function testRegisterAuthenticationFailure() 
    {
        $this->delegate->testRegisterAuthenticationFailure();
    }

    function checkAuthenticationJustFailed() 
    {
        $this->delegate->checkAuthenticationJustFailed();
    }
    
    function testCheckAuthenticationUnreleased() 
    {
        $this->delegate->testCheckAuthenticationUnreleased();
    }
    
    function testRegisterAuthenticationSuccess() 
    {
        $this->delegate->testRegisterAuthenticationSuccess();
    }
    
    function testRegisterAuthenticationFailureAfterSuccess() 
    {
        $this->delegate->testRegisterAuthenticationFailureAfterSuccess();
    }
    
    function testCheckAuthenticationWithUserReleasedOnIpAddressAndCookie() 
    {
        $this->delegate->testCheckAuthenticationWithUserReleasedOnIpAddressAndCookie();
    }
    
    function testBlockingDurations() 
    {
        $this->delegate->testBlockingDurations();
    }

    function testReleaseDurations() 
    {
        $this->delegate->testReleaseDurations();
    }
 
    function testDeleteData1() 
    {
        $this->delegate->testDeleteData1();
    }

    function testRegisterAuthenticationSuccessReleasingUser() 
    {
        $this->delegate->testRegisterAuthenticationSuccessReleasingUser();
    }        
    
    function testCheckAuthenticationWithUserReleased() 
    {
        $this->delegate->testCheckAuthenticationWithUserReleased();
    }
        
    function testDeleteData2() 
    {
        $this->delegate->testDeleteData2();
    }

    function testPackData()
    {
        $this->delegate->testPackData();
    }

}
?>