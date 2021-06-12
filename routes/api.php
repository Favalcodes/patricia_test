<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\API\PassportAuthController;
use App\Models\User;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:api')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::post('register', [PassportAuthController::class, 'register']);
Route::post('login', [PassportAuthController::class, 'login']);


Route::group(['middleware' => ['auth:api']], function () {
    Route::get('get-user', [PassportAuthController::class, 'userInfo']);

    Route::put('update-user', [PassportAuthController::class, 'update']);

    Route::put('change-password', [PassportAuthController::class, 'changePassword']);

    Route::delete('delete', [PassportAuthController::class, 'destroy']);

});
