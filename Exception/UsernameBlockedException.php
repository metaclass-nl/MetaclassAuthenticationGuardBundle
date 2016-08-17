<?php 
namespace Metaclass\AuthenticationGuardBundle\Exception;

/**
 * Thrown when authentication is blocked because more requests then configured
 * in 'limitPerUserName' with the username have failed within the
 * time period confiugured in 'blockUsernamesFor' minus 'counterDurationInSeconds'.
 */
class UsernameBlockedException extends AuthenticationBlockedException {
    
}

?>