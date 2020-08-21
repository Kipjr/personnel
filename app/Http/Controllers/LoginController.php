<?php

namespace App\Http\Controllers;

use Adldap\Auth\BindException;
use Adldap\Laravel\Facades\Adldap;
use App\Models\User;
use App\Traits\LdapHelpers;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    use LdapHelpers;
    //
    public function login(Request $request){
        if($request->isMethod('get')){  
            return view('login');
        }
        if(App::environment('local', 'dev')){
            if (User::with('info')->get()->contains('username', strtolower($request->username))){
                $user=User::where('username',$request->username)->first();
                #print_r($user); die;
                Auth::login($user, true);
                return redirect(route('home'));
            }
        }
        // Do LDAP login stuff

        // If we're already logged in we redirect back to the homepage
        if(Auth::check())
            return redirect(route('home'));

        // Yay! LDAP login stuff!
        $canLogin = $this->isLdapUser($request->input('username'), $request->input('password'));
        if($canLogin !== true){
            return view('login', [ 'msg' => $canLogin ]);
        }

        // Then we grab the user object from LDAP using the samaccountname
        $user = $this->getLdapInfoBy('samaccountname', $request->input('username'));
        if($user == null){
            return view('login', ['msg' => 'Something went wrong, contact '.config('baragenda.contact.mail').' for more information (samaccountname not found in base user dn)']);
        }
        //echo('<pre>');print_r($user); die;
        // We check if the user is in the ADLDAP allowed group that we defined in the .env file
        if($user['memberof']['count'] == 0 || !in_array(config('baragenda.ldap.allowed_group'), $user['memberof'])){
            return view('login', ['msg' => 'Something went wrong, contact '.config('baragenda.contact.mail').' for more information (not found in allowed group)']);
        }

        $dbUser = $this->saveLdapUser($user);

        // And we log in with the found/newly created user
        Auth::login($dbUser, $request->has('remember'));

        // And redirect to home
        return redirect(route('home'));
    }        


    

    public function logout(){
        Auth::logout();
        return redirect(route('home'));
    }

}
