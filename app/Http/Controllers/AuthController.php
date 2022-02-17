<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $input = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed',
        ]);

        $user = User::create([
            'name' => $input['name'],
            'email' => $input['email'],
            'password' => bcrypt($input['password']),
        ]);

        $token = $user->createToken('Token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 201);
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Logged Out',
        ];
    }

    public function login(Request $request)
    {
        $input = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        //CheckEmail
        $user = User::where('email', $input['email'])->first();

        //CheckPassword
        if (!$user || !Hash::check($input['password'], $user->password)) {
            return response([
                'message' => 'Bad Request',
            ], 401);
        }

        $token = $user->createToken('Token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token,
        ];

        return response($response, 200);
    }
}
