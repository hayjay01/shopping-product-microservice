<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
class PassportController extends Controller
{
    public function register(Request $request)
    {
        $this->validate($request, [
            'name' => 'required|min:3',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);
 
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);
 		
 		// We then create the token using the createToken method and passing the name as an argument. 
        $token = $user->createToken('TutsForWeb')->accessToken;
 
        return response()->json(['token' => $token], 200);
    }

    // In the login method, we attempt to authenticate using the request details. Then, we return an appropriate response based on the success or failure of the attempt.
    public function login(Request $request)
    {
        $credentials = [
            'email' => $request->email,
            'password' => $request->password
        ];

        if (auth()->attempt($credentials)) {
            //create token in oauth2_access_token everytime a user logs in with thesame found user id using auth()->user()
            $token = auth()->user()->createToken('TutsForWeb')->accessToken;
            return response()->json(['token' => $token, 'message' => 'Login Successful!'], 200);
        } else {
            return response()->json(['error' => 'UnAuthorised'], 401);
        }
    }

    /**
     * Returns Authenticated User Details
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function details()
    {
        return response()->json(['user' => auth()->user()], 200);
    }
}
