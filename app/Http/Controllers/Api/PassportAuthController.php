<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;

class PassportAuthController extends Controller
{
    /**
     * Registration Request
     */
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|min:4',
            'location' => 'required|min:4',
            'email' => 'required|email',
            'password' => 'required|min:8',
        ]);
        if ($validator->fails())
        {
            return response(['errors'=>$validator->errors()->all()], 422);
        }

        $user = User::create([
            'name' => $request->name,
            'location' => $request->location,
            'email' => $request->email,
            'password' => bcrypt($request->password)
        ]);

        $token = $user->createToken('Laravel8PassportAuth')->accessToken;

        return response()->json(['token' => $token], 200);
    }

    /**
     * Login Request
     */
    public function login(Request $request)
    {
        $data = [
            'email' => $request->email,
            'password' => $request->password
        ];

        if (auth()->attempt($data)) {
            $token = auth()->user()->createToken('Laravel8PassportAuth')->accessToken;
            return response()->json(['token' => $token], 200);
        } else {
            return response()->json(['error' => 'Unauthorised'], 401);
        }
    }

    // Get user Info
    public function userInfo()
    {

        $user = auth()->user();

        return response()->json(['user' => $user], 200);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, User $user)
    {
        $input = $request->all();
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'location' => 'required',
        ]);
        if ($validator->fails())
        {
            return response(['errors'=>$validator->errors()->all()], 422);
        }
        $user->name = $input['name'];
        $user->location = $input['location'];
        $user->update();
        return response()->json([
            "success" => true,
            "message" => "User updated successfully.",
            "data" => $user
        ], 201);
    }

    // password Update
    public function changePassword(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'old_password' => 'required',
            'password' => 'required|min:8|confirmed',
        ]);
        if ($validator->fails())
        {
            return response(['errors'=>$validator->errors()->all()], 422);
        }
        $user = User::findOrFail(auth()->user()->id);
        if (password_verify($request->old_password, $user->password)) {
            $user->password = Hash::make($request->password);
            if($request->old_password === $request->password){
                return response()->json([
                    "success" => false,
                    "message" => "New password is same with old password",
                ], 403);
            }
            if ($user->save()) {
                return response()->json([
                    "success" => true,
                    "message" => "Password updated successfully.",
                    "data" => $user
                ], 201);
            }
        }else{
            return response()->json([
                "success" => false,
                "message" => "Password not correct"
            ], 400);
        }
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  int  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy(User $user)
    {
        $user->delete();
        return response()->json([
            "success" => true,
            "message" => "User deleted successfully.",
        ], 200);
    }
}
