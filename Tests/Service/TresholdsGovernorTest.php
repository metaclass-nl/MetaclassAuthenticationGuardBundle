<?php 
namespace Metaclass\AuthenticationGuardBundle\Tests\Service;

use Metaclass\CoreBundle\Controller\UnitTestController;
use Metaclass\AuthenticationGuardBundle\Service\TresholdsGovernor;
use Metaclass\AuthenticationGuardBundle\Exception\AuthenticationBlockedException;
use Metaclass\AuthenticationGuardBundle\Exception\IpAddressBlockedException;
use Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedException;
use Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedForAgentException;
use Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedForIpAddressException;

class TresholdsGovernorTest extends \PHPUnit_Framework_TestCase 
{
    function setup() 
    {
        global $kernel;
        if ('AppCache' == get_class($kernel)) {
            $kernel = $kernel->getKernel();
        }
        $container = $kernel->getContainer();
        
        $service = $container->get('metaclass_auth_guard.tresholds_governor');
        //we don't want to to use the same governor that may be used in handling the request to the UnitTestController
        $this->governer = clone $service;

        $this->governer->dtString = '1980-07-01 00:00:00';
        $this->governer->distinctiveAgentMinLength = 6;
        $this->governer->counterDurationInSeconds = 300; //5 minutes
        $this->governer->blockUsernamesFor = '30 days'; 
        $this->governer->blockIpAddressesFor = '30 days'; //not very realistic, but should still work
        $this->governer->allowReleasedUserOnAddressFor = '30 days'; //30 days does not work properly
    }
    
    protected function get($propName)
    {
        $rClass = new \ReflectionClass($this->governer);
        $rProp = $rClass->getProperty($propName);
        $rProp->setAccessible(true);
        return $rProp->getValue($this->governer);
    }
    
    function testSetup()
    {
        $dt = new \DateTime($this->governer->dtString);
        $this->assertEquals('1980-07-01 00:00:00', $dt->format('Y-m-d H:i:s'), 'DateTime is properly constructed');
    }
    
    /** test that the request counts dtFrom will be set floored to 5 minutes, as setup has configured $this->governor */
    function testGetRequestCountsDt()
    {
        $this->assertEquals('1980-07-01 00:00:00', $this->governer->getRequestCountsDt('1980-07-01 00:00:00')->format('Y-m-d H:i:s'));
        $this->assertEquals('1980-07-01 00:00:00', $this->governer->getRequestCountsDt('1980-07-01 00:00:01')->format('Y-m-d H:i:s'));
        $this->assertEquals('1980-07-01 00:00:00', $this->governer->getRequestCountsDt('1980-07-01 00:04:59')->format('Y-m-d H:i:s'));
        $this->assertEquals('1980-07-01 00:05:00', $this->governer->getRequestCountsDt('1980-07-01 00:05:00')->format('Y-m-d H:i:s'));
    }
    
    function testInitFor() 
    {
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count for ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count for username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
    }
    
    function testRegisterAuthenticationFailure() 
    {
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->registerAuthenticationFailure();
        
        $this->governer->initFor('192.168.255.250', 'testuserX', 'xxx', 'agentX');
        $this->governer->registerAuthenticationFailure();
        
        $this->governer->initFor('192.168.255.255', 'testuser2', 'whattheheck', 'agent1');
        $this->assertEquals(1, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by other username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for other username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for other username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is other user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is other user released on agent');
         
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by other ip address');
        $this->assertEquals(1, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on other address');
        $this->assertEquals(1, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent!');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on other address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->assertEquals(1, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(1, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(1, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on other agent');        
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on other agent');
    }

    function checkAuthenticationJustFailed() 
    {
        $this->governer->limitPerUserName = 2;
        $this->governer->limitBasePerIpAddress = 2;
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(1, $this->get('failureCountForIpAddress'), 'failure count for ip address');
        $this->assertEquals(1, $this->get('failureCountForUserName'), 'failure count for username');
        $this->assertEquals(1, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(1, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        
        $this->governer->checkAuthentication(true); //assert no exception
        $this->assertEquals(2, $this->get('failureCountForIpAddress'), 'failure count for ip address');
        $this->assertEquals(2, $this->get('failureCountForUserName'), 'failure count for username');
        $this->assertEquals(2, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(2, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        
        //count increments because 'just failed' are transient, governor is reinitialized in next test
    }
    
    function testCheckAuthenticationUnreleased() 
    {
        $this->governer->limitPerUserName = 3;
        $this->governer->limitBasePerIpAddress = 1;
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->checkAuthentication(); //assert no exception

        $this->governer->limitBasePerIpAddress = 0;
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure, but that only shows up when $this->governer->initFor
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\IpAddressBlockedException', $result);
        $this->assertEquals("IP Adress '192.168.255.255' is blocked: 1 attempts failed", $result->getMessage());
        
        $this->governer->limitPerUserName = 1;
        $this->governer->limitBasePerIpAddress = 3;
        $this->governer->checkAuthentication(); //assert no exception
        
        $this->governer->limitPerUserName = 0;
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure, but that only shows up when $this->governer->initFor
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedException', $result);
        $this->assertEquals("Username 'testuser1' is blocked: 1 attempts failed", $result->getMessage());
    }
    
    function testRegisterAuthenticationSuccess() 
    {
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->registerAuthenticationSuccess();
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(3, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(3, $this->get('failureCountForUserName'), 'failure count by  username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->initFor('192.168.255.255', 'testuser2', 'whattheheck', 'agent1');
        $this->assertEquals(3, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by other username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for other username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for other username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is other user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is other user released on agent');
        
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by other ip address');
        $this->assertEquals(3, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on other address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on other address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->assertEquals(3, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(3, $this->get('failureCountForUserName'), 'failure count by username, other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address, other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on other agent');        
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on other agent');
        
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent2');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by other ip address');
        $this->assertEquals(3, $this->get('failureCountForUserName'), 'failure count by username, other addres and other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on other address, other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on other agent, other address');        
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on other address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on other agent');
    }
    
    function testRegisterAuthenticationFailureAfterSuccess() 
    {
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->registerAuthenticationFailure();
        
        $this->governer->initFor('192.168.255.255', 'testuser2', 'whattheheck', 'agent1');
        $this->assertEquals(4, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by other username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for other username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for other username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is other user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is other user released on agent');
         
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by other ip address');
        $this->assertEquals(4, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on other address');
        $this->assertEquals(1, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent!');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on other address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->assertEquals(4, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(4, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(1, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on other agent');        
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on other agent');
    }
    
    function testCheckAuthenticationWithUserReleasedOnIpAddressAndAgent() 
    {
        $this->governer->dtString = '1980-07-01 00:05:00'; //5 minutes later
        
        $this->governer->limitPerUserName = 1;
        $this->governer->limitBasePerIpAddress = 4;
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->checkAuthentication(); //assert no exception
    
        $this->governer->limitBasePerIpAddress = 3;
        $this->governer->checkAuthentication(); //assert no exception
    
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->checkAuthentication(); //assert no exception because of agent released
    
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->governer->checkAuthentication(); //assert no exception because of ip address released
    
        $this->governer->limitPerUserName = 4;
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent2');
        $this->governer->checkAuthentication(); //assert no exception on other ip address
    
        $this->governer->limitBasePerIpAddress = 3;
        $this->governer->limitPerUserName = 1;
        $this->governer->initFor('192.168.255.255', 'testuser2', 'whattheheck', 'agent1');
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure for testuser2
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\IpAddressBlockedException', $result);
        $this->assertEquals("IP Adress '192.168.255.255' is blocked: 4 attempts failed", $result->getMessage());

        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->checkAuthentication(); //assert no exception because of agent released
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->governer->checkAuthentication(); //assert no exception because of ip address released
        
        $this->governer->limitPerUserName = 0;
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure on agent2 and ip 255
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedForIpAddressException', $result);
        $this->assertEquals("Username 'testuser1' is blocked for IP Address '192.168.255.255': 1 attempts failed", $result->getMessage());

        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure on ip 254 and agent1
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedForAgentException', $result);
        $this->assertEquals("Username 'testuser1' is blocked for agent 'agent1': 1 attempts failed", $result->getMessage());

        $this->governer->limitPerUserName = 1;
        $this->governer->checkAuthentication(); //assert no exception because of agent released
        
        $this->governer->distinctiveAgentMinLength = 7;
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure on ip 254 and agent1
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedException', $result);
        $this->assertEquals("Username 'testuser1' is blocked: 5 attempts failed", $result->getMessage());
        
        
    }
    
    function testBlockingDurations() 
    {
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(6, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(7, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(2, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(3, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is other released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->dtString = '1980-07-10 23:59:59';  //just less then 10 days after first request
        
        $this->governer->blockUsernamesFor = '10 days';
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(6, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(7, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(2, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(3, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->blockUsernamesFor = '863995 seconds'; //5 seconds less then 10 days
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(6, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(3, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(1, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(2, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');

        $this->governer->blockIpAddressesFor = '10 days';
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(6, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        
        $this->governer->blockIpAddressesFor = '863995 seconds'; //5 seconds less then 10 days
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(2, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        
    }
/* */
    function testReleaseDurations() 
    {
        $this->governer->dtString = '1980-07-11 00:00:00'; //10 days after first request and releases
        
        $this->governer->allowReleasedUserOnAddressFor = '10 days';
        $this->governer->allowReleasedUserOnAgentFor = '10 days';
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->allowReleasedUserOnAddressFor = '863995 seconds'; //5 seconds less then 10 days
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        //should not be influenced:
        $this->assertEquals(2, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(3, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
                
        $this->governer->allowReleasedUserOnAddressFor = '10 days';
        $this->governer->allowReleasedUserOnAgentFor = '863995 seconds'; //5 seconds less then 10 days
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        //should not be influenced:
        $this->assertEquals(2, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(3, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        
    }
    
    function testDeleteCounts1() 
    {
        $this->get('requestCountsRepo')->deleteCountsUntil(new \DateTime('1981-01-01'));
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on agent');
    }

    function testRegisterAuthenticationSuccessReleasingUser() {
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->releaseUserOnLoginSuccess = true;
        $this->governer->registerAuthenticationFailure();
        $this->governer->registerAuthenticationSuccess();
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(1, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by  username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->initFor('192.168.255.255', 'testuser2', 'whattheheck', 'agent1');
        $this->assertEquals(1, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by other username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for other username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for other username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is other user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is other user released on agent');
        
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by other ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on other address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on other address');
        $this->assertTrue($this->get('isUserReleasedOnAgent'), 'is user released on agent');
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->assertEquals(1, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by username, other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address, other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on other agent');
        $this->assertTrue($this->get('isUserReleasedOnAddress'), 'is user released on address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on other agent');
        
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent2');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by other ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by username, other addres and other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on other address, other agent');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on other agent, other address');
        $this->assertFalse($this->get('isUserReleasedOnAddress'), 'is user released on other address');
        $this->assertFalse($this->get('isUserReleasedOnAgent'), 'is user released on other agent');
    }        
    
    function testCheckAuthenticationWithUserReleased() 
    {
        $this->governer->limitPerUserName = 1;
        $this->governer->limitBasePerIpAddress = 1;
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->checkAuthentication(); //assert no exception, which is normal

        $this->governer->limitBasePerIpAddress = 0;
        $this->governer->checkAuthentication(); //assert no exception

        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent1');
        $this->governer->checkAuthentication(); //assert no exception because of agent released
        
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent2');
        $this->governer->checkAuthentication(); //assert no exception because of ip address released
        
        $this->governer->limitBasePerIpAddress = 1;
        $this->governer->limitPerUserName = 0;
        $this->governer->initFor('192.168.255.254', 'testuser1', 'whattheheck', 'agent2');
        $this->governer->checkAuthentication(); //assert no exception because user released
        
        $this->governer->limitBasePerIpAddress = 0;
        $this->governer->initFor('192.168.255.255', 'testuser2', 'whattheheck', 'agent1');
        try {
            $result = $this->governer->checkAuthentication(); //registers authentication failure for testuser2
        } catch (AuthenticationBlockedException $e) {
            $result = $e;
        }
        $this->assertNotNull($result, 'result');
        $this->assertInstanceOf('Metaclass\AuthenticationGuardBundle\Exception\IpAddressBlockedException', $result);
        $this->assertEquals("IP Adress '192.168.255.255' is blocked: 1 attempts failed", $result->getMessage());
    }
        
    function testDeleteCounts2() 
    {
        $this->get('requestCountsRepo')->deleteCountsUntil(new \DateTime('1981-01-01'));
        $this->governer->initFor('192.168.255.255', 'testuser1', 'whattheheck', 'agent1');
        $this->assertEquals(0, $this->get('failureCountForIpAddress'), 'failure count by ip address');
        $this->assertEquals(0, $this->get('failureCountForUserName'), 'failure count by username');
        $this->assertEquals(0, $this->get('failureCountForUserOnAddress'), 'failure count for username on address');
        $this->assertEquals(0, $this->get('failureCountForUserOnAgent'), 'failure count for username on agent');
    }

    function assertNoException($value, $message = '') 
    {
        //assertNotNull crashes on exception.
        // workaround for ugly $this->assertThat($result, $this->logicalNot(new \PHPUnit_Framework_Constraint_Exception('Exception')) );
        if ($value instanceOf \Exception) {
            $this->assertTrue(true); // replaces self::$count += count($constraint); wich does not work because $count is private :-(
    
            $failureDescription = "Failed asserting no Exception: \n"
                    . get_class($value) . " with message '". $value->getMessage();
            $failureDescription .= "' in ". $value->getFile(). ':'. $value->getLine();
    
            if (!empty($message)) {
                $failureDescription = $message . "\n" . $failureDescription;
            }
            throw new \PHPUnit_Framework_ExpectationFailedException($failureDescription, null);
        }
    }
    
}
?>