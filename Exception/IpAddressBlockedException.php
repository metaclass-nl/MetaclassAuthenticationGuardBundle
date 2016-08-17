<?php 
namespace Metaclass\AuthenticationGuardBundle\Exception;

/**
 * Thrown when authentication is blocked because more requests then configured
 * in 'limitBasePerIpAddress' from the ip address have failed within the
 * time period confiugured in 'blockIpAddressesFor' minus 'counterDurationInSeconds'.
 */
class IpAddressBlockedException extends AuthenticationBlockedException {
    
}

?>