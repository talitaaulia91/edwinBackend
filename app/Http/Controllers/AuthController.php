<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */


    public function register(Request $request){
        $validateData = $request->validate([
            'username' => 'required|min:5|max:50|unique:users',
            'email'    => 'required|email|unique:users|max:50',
            'password' => 'required|min:8|'
        ]);

        $validateData['password'] = Hash::make($request->password);

        $user = User::create($validateData);
        $accessToken = $user -> createToken('authToken')->accessToken;

        return response(['user'=> $user, 'access_token'=>$accessToken], 201);
    } 



    public function Login(Request $request){
        $loginData = $request ->validate([
            'username' => 'required',
            'password' => 'required'
        ]);


        if(!auth()->attempt($loginData)){
            return response(['message'=>'User tidak terdaftar!'], 400);
        };

        $accessToken = auth()->user()->createToken('authToken')->accessToken;
        return response(['user'=>auth()->user(), 'access_token' => $accessToken]);
    }




    // public function login(Request $request){
    //     $validator = Validator::make(
    //         $request->all(),
    //         [
    //             'username' => 'required',
    //             'password' => 'required'
    //         ],
    //     );

    //     if ($validator->fails()) {
    //         return $this->responseFailValidation($validator->errors());
    //     }

    //    $validData = $validator->validated();

    //     if (!$token = JWTAuth::attempt($validData)) {
    //         return $this->responseError("The email or password is incorrect.", 401);
    //     }

       
    //     $data = [
    //         "user" => Auth::user(),
    //         "token" => $token,
    //         "type" => "Bearer",
    //     ];

    //     return $this->responseSuccessWithData("login successful", $data);
    // }














    public function index()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        //
    }

    /**
     * Display the specified resource.
     *
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function show(User $user)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, User $user)
    {
        //
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  \App\Models\User  $user
     * @return \Illuminate\Http\Response
     */
    public function destroy(User $user)
    {
        //
    }
}
