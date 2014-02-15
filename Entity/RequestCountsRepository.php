<?php 
namespace Metaclass\AuthenticationGuardBundle\Entity;

use Doctrine\ORM\EntityRepository;
use Doctrine\ORM\Query\ResultSetMapping;

class RequestCountsRepository extends EntityRepository {
    
    //WARNING: $counterColumn, $releaseColumn vurnerable for SQL injection!!
    public function countWhereSpecifiedAfter($counterColumn, $username, $ipAddress, $userAgent, $dtLimit, $releaseColumn=null)
    {
        if ($username === null && $ipAddress == null && $userAgent == null) {
            throw new BadFunctionCallException ('At least one of username, ipAddress, agent must be supplied');
        }
        $qb =$this->getEntityManager()->getConnection()->createQueryBuilder();
        $qb->select("sum(r.$counterColumn)")
            ->from('secu_requests', 'r')
            ->where("r.dtFrom > :dtLimit")
            ->setParameter('dtLimit', $dtLimit->format('Y-m-d H:i:s'));
        if ($username !== null) {
            $qb->andWhere("r.username = :username")
                ->setParameter('username', $username);
        }
        if ($ipAddress !== null) {
            $qb->andWhere("r.ipAddress = :ipAddress")
                ->setParameter('ipAddress', $ipAddress);
        }
        if ($userAgent !== null) {
            $qb->andWhere("r.agent = :agent")
                ->setParameter('agent', $userAgent);
        }
        if ($releaseColumn !== null) {
            $qb->andWhere("$releaseColumn IS NULL");
        }
        return (int) $qb->execute()->fetchColumn();
    }
    
    //currently not used
    public function getDateLastLoginSuccessAfter($dtLimit, $username, $ipAddress=null, $userAgent=null) {
        $qb =$this->getEntityManager()->getConnection()->createQueryBuilder();
        $qb->select("r.date")
            ->from('secu_requests', 'r')
            ->where("r.dtFrom > :dtLimit")
            ->andWhere("r.username = :username")
            ->setParameter('dtLimit', $dtLimit->format('Y-m-d H:i:s'))
            ->setParameter('username', $username);
        if ($ipAddress !== null) {
            $qb->andWhere("r.ipAddress = :ipAddress")
                ->setParameter('ipAddress', $ipAddress);
        }
        if ($userAgent !== null) {
               $qb->andWhere("(r.agent = :agent)")
                  ->setParameter('agent', $userAgent);
        }
    }
    
    public function isUserReleasedOnAddressFrom($username, $ipAddess, $releaseLimit)
    {
        $sql = "SELECT id
        FROM secu_requests r
        WHERE userReleasedForAddressAndAgentAt >= ?
                AND r.username = ? AND r.ipAddress = ? 
        LIMIT 1";
        
        $conn = $this->getEntityManager()->getConnection();
        return (boolean) $conn->fetchColumn($sql, array($releaseLimit->format('Y-m-d H:i:s'), $username, $ipAddess));
    }
    
    public function isUserReleasedOnAgentFrom($username, $userAgent, $releaseLimit)
    {
        $sql = "SELECT id
        FROM secu_requests r
        WHERE userReleasedForAddressAndAgentAt >= ?
                AND r.username = ? AND r.agent = ? 
        LIMIT 1";
        
        $conn = $this->getEntityManager()->getConnection();
        return (boolean) $conn->fetchColumn($sql, array($releaseLimit->format('Y-m-d H:i:s'), $username, $userAgent));
    }
    
    public function findByDateAndUsernameAndIpAddressAndAgent($dateTime, $ipAddress, $username)
    {
        $qb = $this->createQueryBuilder('r');
        $this->qbWhereDateAndIpAddressAndUsername($qb, $dateTime, $ipAddress, $username);

        return $qb->getQuery()->getOneOrNullResult();
    }
    
    public function getIdWhereDateAndUsernameAndIpAddressAndAgent($dateTime, $username, $ipAddress, $userAgent) {
        $conn =$this->getEntityManager()->getConnection();
        $qb = $conn->createQueryBuilder();
        $qb->select('r.id')
            ->from('secu_requests', 'r');
        $this->qbWhereDateAndUsernameAndIpAddressAndAgent($qb, $dateTime, $username, $ipAddress, $userAgent);
        return $qb->execute()->fetchColumn();
    }
    
    //WARNING: $releaseColumn vurnerable for SQL injection!!
    protected function qbWhereDateAndUsernameAndIpAddressAndAgent($qb, $dateTime, $username, $ipAddress, $userAgent) {
        $qb->where('r.username = :username')
            ->andWhere('r.ipAddress = :ipAddress')
            ->andWhere('r.dtFrom = :dtFrom')
            ->andWhere('r.agent = :agent')
            ->andWhere("addresReleasedAt IS NULL")
            ->andWhere("userReleasedAt IS NULL")
            ->andWhere("userReleasedForAddressAndAgentAt IS NULL")
            ->setParameter('username', $username)
            ->setParameter('ipAddress', $ipAddress)
            ->setParameter('dtFrom', $dateTime->format('Y-m-d H:i:s') )
            ->setParameter('agent', $userAgent);
            ;
    }
    
    public function createWith($datetime, $ipAdrdess, $username, $userAgent, $loginSucceeded)
    {
        $conn =$this->getEntityManager()->getConnection();
        $counter = $loginSucceeded ? 'loginsSucceeded' : 'loginsFailed';
        $params = array(
            'dtFrom' => $datetime,
            'username' => $username,
            'ipAddress' => $ipAdrdess,
            'agent' => $userAgent,
            $counter => 1 );
        $columns = implode(', ', array_keys($params));
        $values = ':'. implode(', :', array_keys($params));
        $sql = "INSERT INTO secu_requests ($columns) VALUES ($values)";
        $conn->executeUpdate($sql, $params, $types);
    }
    
    //WARNING: $columnToUpdate vurnerable for SQL injection!!
    public function incrementColumnWhereId($columnToUpdate, $id)
    {
        $conn =$this->getEntityManager()->getConnection();
        $qb = $conn->createQueryBuilder();
        $qb->update('secu_requests', 'r')
            ->set($columnToUpdate, "$columnToUpdate + 1")
            ->where("id = :id")
            ->setParameter('id', $id)
            ->execute();
    }
    
    //WARNING: $columnToUpdate vurnerable for SQL injection!!
    public function updateColumnWhereColumnNullAfterSupplied($columnToUpdate, $value, $dtLimit, $username, $ipAddress, $userAgent) {
        if ($username === null && $ipAddress == null) {
            throw new BadFunctionCallException ('At least one of username and ip address must be supplied');
        }
        $conn =$this->getEntityManager()->getConnection();
        $qb = $conn->createQueryBuilder();
        $qb->update('secu_requests', 'r')
            ->set($columnToUpdate, ':value')
            ->setParameter('value', $valuet->format('Y-m-d H:i:s'))
            ->where("$columnToUpdate IS NULL")
            ->andWhere("r.dtFrom > :dtLimit")
            ->setParameter('dtLimit', $dtLimit->format('Y-m-d H:i:s'));
        if ($username !== null) {
            $qb->andWhere("r.username = :username")
                ->setParameter('username', $username);
        }
        if ($ipAddress != null) {
            $qb->andWhere("r.ipAddress = :ipAddress")
                ->setParameter('ipAddress', $ipAddress);
        }
        if ($userAgent !== null) {
            $qb->andWhere("r.agent = :agent")
                ->setParameter('agent', $userAgent);
        }
        $qb->execute();
    }
    
    public function deleteCountsUntil(\DateTime $dtLimit) {
        if (!$dtLimit) {
            throw new \Exception('DateTime limit must be specified');
        }
        $conn = $this->getEntityManager()->getConnection();
        $qb = $conn->createQueryBuilder();
        $qb->delete('secu_requests')
        ->where("dtFrom < :dtLimit")
        ->setParameter('dtLimit', $dtLimit->format('Y-m-d H:i:s'));
        $qb->execute();
    }
    
}

?>