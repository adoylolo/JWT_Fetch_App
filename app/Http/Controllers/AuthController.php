<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Support\Arr;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Tymon\JWTAuth\Exceptions\TokenInvalidException;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login','register']]);
    }

    public function register()
    {
        $validator = Validator::make(request()->all(),[
            'nik' => 'required|numeric|digits:16|unique:users',
            'role' => 'required',
            'password' => 'required',
        ]);

        if($validator->fails()){
            return response()->json($validator->messages());
        }

        $user = User::create([
            'nik' => request('nik'),
            'role' => request('role'),
            'password' => Hash::make(request('password')),
        ]);
        if($user){
            return response()->json(['message' => 'Pendaftaran Berhasil']);
        }else{
            return response()->json(['message' => 'Pendaftaran Gagal']);
        }
    }
    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login()
    {
        $credentials = request(['nik', 'password']);

        if (! $token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Login gagal. Silahkan coba kembali'], 401);
        }

        return $this->respondWithToken($token);
    }

    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function me()
    {
        
        $api_url = 'https://60c18de74f7e880017dbfd51.mockapi.io/api/v1/jabar-digital-services/product';

        $file = json_decode(file_get_contents($api_url), true);
        $array = [];

        if (auth()->user()->role == "Admin") {

            foreach ($file as $files) {
                $array[] = array([
                    'Harga (Rp.)' => round($files['price'] * 14756.80),
                    'Departemen' => $files['department'],
                    'Produk' => $files['product'],
                ]);
            }

            $sorted = collect($array)->sort();
            return response($sorted);

        }else {
            
            foreach ($file as $files) {
                $array[] = array([
                    'ID' => $id[] = $files['id'],
                    'Produk' => $product[] = $files['product'],
                    'Departemen' => $department[] = $files['department'],
                    'Harga (USD)' => $price[] = '$'.$files['price'],
                    'Harga (IDR)' => $idr[] = 'Rp.'.round($files['price'] * 14756.80),
                ]);
            }
              
            return response($array);
        }

    }

    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        $newToken = auth()->refresh();

        return response()->json([
            'message' => 'Successfully refresh',
            //$this->respondWithToken(auth()->refresh())
            'new_token' => $newToken,
        ]);
        
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            'message' => 'Successfully login',
            'NIK' => auth()->user()->nik,
            'Role' => auth()->user()->role,
            'access_token' => $token,
            //'token_type' => 'bearer',
            //'expires_in' => auth()->factory()->getTTL() * 60,
        ]);
    }
}
