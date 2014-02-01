<?php 
namespace Metaclass\AuthenticationGuardBundle\Service;

use Doctrine\ORM\EntityManager;

use Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedException;
use Metaclass\AuthenticationGuardBundle\Exception\IpAddressBlockedException;
use Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedForAgentException;
use Metaclass\AuthenticationGuardBundle\Exception\UsernameBlockedForIpAddressException;
use Metaclass\AuthenticationGuardBundle\Entity\RequestCounts;

class TresholdsGovernor {

    //dependencies
    protected $entityManager;
    protected $requestCountsRepo;
    public $dtString; //Y-m-d H:i:s
    
    //config 
    public $counterDurationInSeconds; //how long each counter counts
    public $blockUsernamesFor; //like: '30 days'
    public $limitPerUserName;
    public $blockIpAddressesFor; //like: '15 minutes'
    public $limitBasePerIpAddress; //limit may be higher, depending on successfull logins and requests (NYI)
    public $allowReleasedUserOnAddressFor; //if empty feature is switched off
    public $allowReleasedUserOnAgentFor; //if empty feature is switched off
    public $releaseUserOnLoginSuccess;
    public $distinctiveAgentMinLength;
    
    //variables
    protected $failureCountForIpAddress;
    protected $failureCountForUserName;
    protected $isUserReleasedOnAddress;
    protected $failureCountForUserOnAddress;
    protected $isUserReleasedOnAgent;
    protected $failureCountForUserOnAgent;

            
    public function __construct(EntityManager $em, $requestCountsClass, $params) {
        $this->entityManager = $em;
        $this->requestCountsRepo = $em->getRepository($requestCountsClass); //'Metaclass\AuthenticationGuardBundle\Entity\RequestCounts'
        $this->dtString = date('Y-m-d H:i:s');
        $this->setPropertiesFromParams($params);
    }
    
    /** @throws ReflectionException */
    protected function setPropertiesFromParams($params)
    {
        $rClass = new \ReflectionClass($this);
        forEach($params as $key => $value)
        {
            $rProp = $rClass->getProperty($key);
            if (!$rProp->isPublic()) {
                throw new \ReflectionException("Property must be public: '$key'");
            }
            $rProp->setValue($this, $value);
        }
    }
    
    public function initFor($ipAddress, $username, $password, $userAgent) 
    {
        //cast to string because null is used for control in some Repo functions
        $this->ipAddress = (string) $ipAddress;
        $this->username = (string) $username;
        $this->agent = (string) $userAgent; 
        //$this->password = (string) $password;
        
        
        $timeLimit = new \DateTime("$this->dtString - $this->blockIpAddressesFor");
        $this->failureCountForIpAddress  = $this->requestCountsRepo->countWhereSpecifiedAfter('loginsFailed', null, $ipAddress, null, $timeLimit, 'addresReleasedAt');

        $timeLimit = new \DateTime("$this->dtString - $this->blockUsernamesFor");
        $this->failureCountForUserName = $this->requestCountsRepo->countWhereSpecifiedAfter('loginsFailed', $username,  null, null, $timeLimit, 'userReleasedAt');
        $this->failureCountForUserOnAddress = $this->requestCountsRepo->countWhereSpecifiedAfter('loginsFailed', $username, $ipAddress, null, $timeLimit, 'userReleasedForAddressAndAgentAt');
        $this->failureCountForUserOnAgent = $this->requestCountsRepo->countWhereSpecifiedAfter('loginsFailed', $username, null, $userAgent, $timeLimit, 'userReleasedForAddressAndAgentAt');

        $relativeTo = new \DateTime("$this->dtString");
        $timeLimit = new \DateTime("$this->dtString - $this->allowReleasedUserOnAddressFor");
        $this->isUserReleasedOnAddress = $this->requestCountsRepo->isUserReleasedOnAddressFrom($username, $ipAddress, $timeLimit);
        $timeLimit = new \DateTime("$this->dtString - $this->allowReleasedUserOnAgentFor");
        $this->isUserReleasedOnAgent = $this->requestCountsRepo->isUserReleasedOnAgentFrom($username, $userAgent, $timeLimit);
    }

    /**
     * 
     * @throws AuthenticationBlockedException
     */
    public function checkAuthentication($justFailed=false) 
    {
        $error = null;
        if ($justFailed) { // failure that occurred during the current authentication attempt are not yet registered, add them here
            $this->failureCountForUserName++;
            $this->failureCountForIpAddress++;
            $this->failureCountForUserOnAddress++;
            $this->failureCountForUserOnAgent++;
            //WARNING, these increments must be done BEFORE decision making, but unit tests do not test that 
        }
        if ($this->isUserReleasedOnAddress) {
            if ($this->failureCountForUserOnAddress > $this->limitPerUserName) { 
                $error = new UsernameBlockedForIpAddressException("Username '$this->username' is blocked for IP Address '$this->ipAddress': $this->failureCountForUserOnAddress attempts failed");
            }
        } elseif ($this->isUserReleasedOnAgent && $this->isAgentDistinctive()) { 
            if ($this->failureCountForUserOnAgent > $this->limitPerUserName) {
                $error = new UsernameBlockedForAgentException("Username '$this->username' is blocked for agent '$this->agent': $this->failureCountForUserOnAgent attempts failed");
            }
        } else {
            if ($this->failureCountForIpAddress > $this->limitBasePerIpAddress) {
                $error = new IpAddressBlockedException("IP Adress '$this->ipAddress' is blocked: $this->failureCountForIpAddress attempts failed");
            }
            if ($this->failureCountForUserName > $this->limitPerUserName) {
                $error = new UsernameBlockedException("Username '$this->username' is blocked: $this->failureCountForUserName attempts failed");
            }
        }
       if ($justFailed || $error) {
           $this->registerAuthenticationFailure();
           if ($error) {
               throw $error;
           }
       }
    }
    
    public function isAgentDistinctive() {
        return strLen($this->agent) >= $this->distinctiveAgentMinLength;
    }
    
    /**
     * 
     * @param string $dtString DateTime string  
     * @return int the seconds since UNIX epoch for the RequestCounts dtFrom
     */
    public function getRequestCountsDt($dtString)
    {
        $dt = new \DateTime($dtString);
        $remainder = $dt->getTimestamp() % $this->counterDurationInSeconds;
        return $remainder
            ? $dt->sub(new \DateInterval('PT'.$remainder.'S'))
            : $dt;
    }
    
    public function registerAuthenticationSuccess() 
    {
        //? should we releaseUserNameForIpAddress? And should'nt that have a shorter effect then release from e-mail?
        //? should we register (some) other failures in the session and release those here? 
        
        $dateTime = $this->getRequestCountsDt($this->dtString);
        $id = $this->requestCountsRepo->getIdWhereDateAndUsernameAndIpAddressAndAgent($dateTime, $this->username, $this->ipAddress, $this->agent);
        if ($id) {
            $this->requestCountsRepo->incrementColumnWhereId('loginsSucceeded', $id);
        } else {
            $counts = $this->requestCountsRepo->createWith($dateTime, $this->ipAddress, $this->username, $this->agent);
            $counts->setLoginsSucceeded(1);
            $this->entityManager->flush();
        }
        if ($this->releaseUserOnLoginSuccess) {
            $this->releaseUserName();
        } 
        $this->releaseUserNameForIpAddressAndUserAgent();
    }
    
    public function registerAuthenticationFailure() 
    {
        //SBAL/Query/QueryBuilder::execute does not provide QueryCacheProfile to the connection, so the query will not be cached
        $dateTime = $this->getRequestCountsDt($this->dtString);
        $id = $this->requestCountsRepo->getIdWhereDateAndUsernameAndIpAddressAndAgent($dateTime, $this->username, $this->ipAddress, $this->agent);
        if ($id) {
            return $this->requestCountsRepo->incrementColumnWhereId('loginsFailed', $id); 
        }
        $counts = $this->requestCountsRepo->createWith($dateTime, $this->ipAddress, $this->username, $this->agent);
        $counts->setLoginsFailed(1);
        $this->entityManager->flush();
    }
    
    /** only to be combined with new password */
    public function releaseUserName() 
    {
        $dateTime = new \DateTime($this->dtString);
        $timeLimit = new \DateTime("$this->dtString - $this->blockUsernamesFor");
        $this->requestCountsRepo->updateColumnWhereColumnNullAfterSupplied(
            'userReleasedAt', $dateTime->format('Y-m-d'), $timeLimit, $this->username, null, null);
    }
    
    public function releaseUserNameForIpAddressAndUserAgent()
    {
        $dateTime = new \DateTime($this->dtString);
        $timeLimit = new \DateTime("$this->dtString - $this->blockUsernamesFor");
        $this->requestCountsRepo->updateColumnWhereColumnNullAfterSupplied(
            'userReleasedForAddressAndAgentAt', $dateTime->format('Y-m-d'), $timeLimit, $this->username, $this->ipAddress, null);
        $this->requestCountsRepo->updateColumnWhereColumnNullAfterSupplied(
            'userReleasedForAddressAndAgentAt', $dateTime->format('Y-m-d'), $timeLimit, $this->username, null, $this->agent);
    }

    public function adminReleaseIpAddress()
    {
        $dateTime = new \DateTime($this->dtString);
        $timeLimit = new \DateTime("$this->dtString - $this->blockIpAddressesFor");
        $this->requestCountsRepo->updateColumnWhereColumnNullAfterSupplied(
            'addresReleasedAt', $dateTime->format('Y-m-d'), $timeLimit, null, $this->ipAddress, null);
    }

}

?>