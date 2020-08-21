<?php
namespace App\Traits;

use LdapRecord\Laravel\Auth\BindException;
use LdapRecord\Connection;
use LdapRecord\Container;
use LdapRecord\Models\ActiveDirectory\User;
use LdapRecord\Models\ActiveDirectory\Group;
use App\Models\Info;
use Illuminate\Database\Eloquent\ModelNotFoundException;

/**
 * Created by PhpStorm.
 * User: SubSide
 * Date: 10/11/2017 / edit&stolen at 2020-08-15 <3
 * Time: 6:01 PM
 */
trait LdapHelpers
{
    protected $connection;

    public function __construct(){
        $this->connection = Container::getDefaultConnection();
       
    } 
        
    private function getLdapInfoBy($field, $value){
        return $this->connection->query()
            ->in(config('baragenda.ldap.user_base'))
            ->findBy($field, $value);
    }

    public function searchLdapUsers($name){
        if(!preg_match('/^[a-zA-Z0-9 _]+$/', $name)){
            return '';
        }
        $users = $this->connection->query()
            ->in(config('baragenda.ldap.user_base'))
            ->rawFilter('(cn=*'.$name.'*)')
            ->limit(10)
            ->get();

        return $users->map(function ($user){
            return [
                'name' => $user->cn[0],
                'employeeId' => $user->employeeId[0]
            ];
        }, $users);
    }

    public function isLdapUser($username, $password){
            // We bind the user to check if we can actually sign in
           
            $user = User::findByOrFail('samaccountname', $username);
            if ($this->connection->auth()->attempt($user->getDn(),  $password)) {
                // Credentials are valid!
                return true;
            }
            else {
                $message = $connection->getLdapConnection()->getDiagnosticMessage();
                return $message;
                /* if (strpos($message, '532') !== false) {
                    return "Your password has expired.";
                } */
            }
    } 
    
    //todo: fix nesting of groups, get all groups of user while  groups are member of parent Group
    public function getUserGroups($user){
        return $user
            ->groups()->recursive()
            ->map(function($obj){ return $obj->distinguishedname[0]; });
    }

    public function isUserInGroup($user, $group){
        return $user->groups()->exists(config('baragenda.ldap.admin_group'));
        //return $this->getUserGroups($user)->contains(config('baragenda.ldap.admin_group'));
    }

    public function saveLdapUser($user){
        $dbUser = null;
        try {
            // We first check if we already have this user in our database
             echo('<pre>');print_r($user); //die;
            $dbUser = User::findByOrFail('samaccountname',$user['samaccountname']['0']);
        } catch(ModelNotFoundException $e){
            // If not, we create a new user
            $dbUser = new User();
            $dbUser->username=$user->samaccountname[0];
            // Save it back to the database
            $dbUser->save();
        }
        // We update all the information of the user
        $info = $dbUser->info ?: new Info;
        $info->objectGUID = bin2hex($user['objectguid'][0]);
        $info->lidnummer = $user['employeenumber'][0];
        $info->relatienummer = $user['employeeid'][0];
        $info->name = $user['cn'][0];
        $info->email = $user['mail'][0];
        
        // We save the info with relation to user
        $dbUser->info()->save($info);
        
        // Check if the user is a baragenda admin (only superadmin)
        $dbUser->info()->admin = $user->memberof != null && $this->isUserInGroup($user, config('baragenda.ldap.admin_group'));
        #echo('<pre>');print_r( $this->isUserInGroup($user, config('baragenda.ldap.admin_group')));die;


        // And return it so we can use it
        return $dbUser;
    }


    public function getLdapUserBy($field, $value){
        $ldapInfo = $this->getLdapInfoBy($field, $value);

        if($ldapInfo == null)
            return null;

        return $this->saveLdapUser($ldapInfo);
    }
}
