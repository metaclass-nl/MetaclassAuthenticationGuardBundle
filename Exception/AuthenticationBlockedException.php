<?php 
namespace Metaclass\AuthenticationGuardBundle\Exception;

use Symfony\Component\Security\Core\Exception\AuthenticationException;

/**
 * Thrown when authentication is blocked, i.e. an authentication
 *  request came in (the form was posted) but actual authentication
 *  was not attempted because the tresholds governor decided against it
 *  for reasons depending on the subclass of this.
 */
class AuthenticationBlockedException extends AuthenticationException {

}
?>