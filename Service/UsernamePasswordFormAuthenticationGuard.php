<?php 
/* parts of the code in this file are copied from UsernamePasswordFormAuthenticationListener
 * and thus (c) Fabien Potencier <fabien@symfony.com>, 
 * the rest is (c) MetaClass Groningen.
 */

namespace Metaclass\AuthenticationGuardBundle\Service;

use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;
use Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Psr\Log\LoggerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface;
use Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface;
use Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface;
use Symfony\Component\Security\Http\HttpUtils;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\AuthenticationServiceException;
use Symfony\Component\Security\Core\Exception\ProviderNotFoundException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
//also uses Metaclass\AuthenticationGuardBundle\Service\TresholdsGovernor

class UsernamePasswordFormAuthenticationGuard extends AbstractAuthenticationListener {
    
    protected $csrfProvider;
    protected $mySecurityContext;
    
    protected $governor;
    protected $usernamePattern = '/([^\\x20-\\x7E])/u'; //default is to allow all 1 to 1 visible ASCII characters (from space to ~). This excludes CR, LF, Tab , FF
    protected $passwordPattern; //if not set, usernamePattern is used
    
    /**
     * {@inheritdoc}
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, SessionAuthenticationStrategyInterface $sessionStrategy, HttpUtils $httpUtils, $providerKey, AuthenticationSuccessHandlerInterface $successHandler, AuthenticationFailureHandlerInterface $failureHandler, array $options = array(), LoggerInterface $logger = null, EventDispatcherInterface $dispatcher = null, CsrfProviderInterface $csrfProvider = null)
    {
        parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $successHandler, $failureHandler, array_merge(array(
                'username_parameter' => '_username',
                'password_parameter' => '_password',
                'csrf_parameter'     => '_csrf_token',
                'intention'          => 'authenticate',
                'post_only'          => true,
        ), $options), $logger, $dispatcher);
    
        $this->csrfProvider = $csrfProvider;
        $this->mySecurityContext = $securityContext;
    }
    
    public function setGovenor(TresholdsGovernor $governor) {
        $this->governor = $governor;
        return $this;
    }
    
    public function setValidationPatterns($usernamePattern, $passwordPattern=null) {
        $this->usernamePattern = $usernamePattern;
        if ($passwordPattern !== null) {
            $this->passwordPattern = $passwordPattern;
        }
    }
    
    /**
     * {@inheritdoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('POST')) {
            return false;
        }

        return parent::requiresAuthentication($request);
    }
    
    /**
     * {@inheritdoc}
     */
    protected function attemptAuthentication(Request $request)
    {
        $originalCred = $this->getCredentials($request);
        $filteredCred = $this->filterCredentials($originalCred);
        $request->getSession()->set(SecurityContextInterface::LAST_USERNAME, $originalCred[0]);
        
        if (null !== $this->csrfProvider) {
            $this->checkCrsfToken($request);
        }
        
        //initialize the governer so that we can register a failure
        $this->governor->initFor(
                 $request->getClientIp()
                , $filteredCred[0]
                , $filteredCred[1]
                , $request->headers->get('user-agent')
             );
        
        if ($originalCred != $filteredCred) { //we can not accept invalid characters
            $this->governor->registerAuthenticationFailure();
            throw new BadCredentialsException('Credentials contain invalid character(s)');
        }
        
        $this->governor->checkAuthentication(); //may register failure and throw AuthenticationBlockedException
        
        //not blocked, try to authenticate
        try {
            $newToken = $this->authenticationManager->authenticate(new UsernamePasswordToken($filteredCred[0], $filteredCred[1], $this->providerKey));
        } catch (AuthenticationException $e) {
            if ($this->isClientResponsibleFor($e)) {
                $this->governor->registerAuthenticationFailure();
            } //else do not register service errors as failures
            throw $e;
        }
        
        //authenticated!
        $this->governor->registerAuthenticationSuccess();
        
        //when the user goes to the login page without logging out or on reauthentication because of 
        //an InsufficientAuthenticationException there may still be a UsernamePasswordToken 
        $oldToken = $this->mySecurityContext->getToken();
        $oldUserName = $oldToken instanceof UsernamePasswordToken ? $oldToken->getUserName() : '';
        if ($newToken instanceof UsernamePasswordToken && trim($newToken->getUserName()) != trim($oldUserName)) {
            //user has changed without logout, clear session so that the data of the old user can not leak to the new user
            $request->getSession()->clear();
        }

        return $newToken;
    }
    
    protected function checkCrsfToken(Request $request) 
    {
        $csrfToken = $request->get($this->options['csrf_parameter'], null, true);
    
        if (false === $this->csrfProvider->isCsrfTokenValid($this->options['intention'], $csrfToken)) {
            throw new InvalidCsrfTokenException('Invalid CSRF token.');
        }
    }    
    
    protected function getCredentials(Request $request) 
    {
        if ($this->options['post_only']) {
            $username = trim($request->request->get($this->options['username_parameter'], null, true));
            $password = $request->request->get($this->options['password_parameter'], null, true);
        } else {
            $username = trim($request->get($this->options['username_parameter'], null, true));
            $password = $request->get($this->options['password_parameter'], null, true);
        }
        
        return array($username, $password);
    }
    
    /** Filter the credentials to protect against invalid UTF-8 characters */
    protected function filterCredentials($usernameAndPassword) {
        return array(
            preg_replace($this->usernamePattern, ' ', $usernameAndPassword[0]), 
            preg_replace( ($this->passwordPattern === null ? $this->usernamePattern : $this->passwordPattern), ' ', $usernameAndPassword[1]),
        );
    }
    
    static public function isClientResponsibleFor(AuthenticationException $e) {
        //imho AuthenticationServiceException and ProviderNotFoundException signal bad service plumming
        return !($e instanceOf AuthenticationServiceException 
                    || $e instanceOf ProviderNotFoundException);
    }
}
?>