<?php
namespace App\Http\Controllers;

use App\User;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Facades\JWTFactory;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\PayloadFactory;
use Tymon\JWTAuth\JWTManaget as JWT;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{   
    public function register(Request $request){
        $validate = Validator::make($request ->json()->all() ,[
            'name' => 'min:2',
            'email'=> 'string',
            'password' => 'min:6'
        ]);
        if($validate ->fails()){
            return \response() -> json($validate->errors()->toJson(),400);
        }

        $user =User::create([
            'name'=>$request->input('name'),
            'email'=>$request->input('email'),
            'password' => Hash::make($request->json()->get('password')),
        ]);

        
        $token = JWTAuth::fromUser($user);
            
        return \response()->json(compact('user','token'),201);
    }

    public function login(Request $request){
        $creadentials = $request ->json()->all();
        // return \response()->json($creadentials);
        try{
            if(! $token = JWTAuth::attempt($creadentials)){
                return response() -> json(['error' => 'invalid_vreadentials'],400);

            }
        }catch(JWTException $e){
            return \response()->json(['error'=>'could_not create token'],500);
        }
        return \response()->json(compact('token')); 
    }

    public function getAuthenticatedUser(){
        try{
            if(! $user = JWTAuth :: parseToken() ->authenticate()){
                return response() -> json(['user_not_found'],404);
            }
        }catch(Tymon\JWTAuth\Exceptions\TokenExpiredException $e){
            return response()->json(['token_invalid'],$e->getStatusCode());
        }catch(Tymon\JWTAuth\Exceptions\TokenInvalidException $e){
            return response()->json(['token_invalid'],$e->getStatusCode());
        }catch(Tymon\JWTAuth\Exceptions\JWTException $e){
            return response()->json(['token_invalid'],$e->getStatusCode());
        }

        return response()->json(compact('user'));

    }
}  