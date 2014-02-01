<?php 
namespace Metaclass\AuthenticationGuardBundle\Service;

use Symfony\Component\Security\Core\User\UserChecker as SymfonyUserChecker;
use Symfony\Component\Security\Core\User\UserInterface;

class UserChecker extends SymfonyUserChecker {
    
    public function checkPreAuth(UserInterface $user)
    {
        //checking isCredentialsNonExpired before authentication will leak user existence through response time
    }
    
    public function checkPostAuth(UserInterface $user)
    {
        parent::checkPreAuth($user); //TODO (somewhere else): redirect to change password form on CredentialsExpiredException
    
        parent::checkPostAuth($user);
    }
}
?>