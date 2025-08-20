<?php
namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use App\Models\License;
use App\Services\LicenseSigner;
use Illuminate\Support\Carbon;

class LicenseController extends Controller
{
    public function activate(Request $r, LicenseSigner $signer)
    {
        $data = $r->validate([
            'license_key'=>'required|string',
            'device_id'=>'required|string|max:255',
            'device_name'=>'nullable|string|max:255'
        ]);

        $license = License::where('key',$data['license_key'])->firstOrFail();
        if ($license->revoked) return response()->json(['error'=>'LICENSE_REVOKED'],403);
        if ($license->expires_at && now('UTC')->greaterThan($license->expires_at))
            return response()->json(['error'=>'LICENSE_EXPIRED'],403);

        $activeCount = DB::table('activations')->where('license_id',$license->id)->count();
        if ($activeCount >= $license->seat_limit) {
            $exists = DB::table('activations')
                ->where(['license_id'=>$license->id,'device_id'=>$data['device_id']])
                ->first();
            if (!$exists) return response()->json(['error'=>'SEAT_LIMIT_REACHED'],403);
        }

        DB::table('activations')->updateOrInsert(
            ['license_id'=>$license->id,'device_id'=>$data['device_id']],
            ['device_name'=>$data['device_name'] ?? null,'status'=>'active','last_heartbeat_at'=>now('UTC')]
        );

        $token = $signer->signToken([
            'license_key'=>$license->key,
            'device_id'=>$data['device_id'],
            'plan'=>$license->plan,
            'exp'=> now('UTC')->addDays(3)->unix() // 72h offline
        ]);

        return response()->json([
            'token'=>$token,
            'plan'=>$license->plan,
            'expires_at'=>$license->expires_at,
            'seat_limit'=>$license->seat_limit
        ]);
    }

    public function heartbeat(Request $r, LicenseSigner $signer)
    {
        $data = $r->validate(['license_key'=>'required','device_id'=>'required']);
        $license = License::where('key',$data['license_key'])->firstOrFail();
        if ($license->revoked) return response()->json(['error'=>'LICENSE_REVOKED'],403);

        DB::table('activations')->where(['license_id'=>$license->id,'device_id'=>$data['device_id']])
            ->update(['last_heartbeat_at'=>now('UTC')]);

        $token = $signer->signToken([
            'license_key'=>$license->key,
            'device_id'=>$data['device_id'],
            'plan'=>$license->plan,
            'exp'=> now('UTC')->addDays(3)->unix()
        ]);

        return response()->json(['token'=>$token]);
    }

    public function deactivate(Request $r)
    {
        $data = $r->validate(['license_key'=>'required','device_id'=>'required']);
        $license = License::where('key',$data['license_key'])->first();
        if ($license) {
            DB::table('activations')->where([
                'license_id'=>$license->id,
                'device_id'=>$data['device_id']
            ])->delete();
        }
        return response()->json(['ok'=>true]);
    }
}
