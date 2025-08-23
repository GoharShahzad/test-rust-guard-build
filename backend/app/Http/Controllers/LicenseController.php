<?php

namespace App\Http\Controllers;

use App\Models\License;
use App\Models\LicenseActivation;
use App\Models\AuditLog;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Str;

class LicenseController extends Controller
{
    public function validateLicense(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'license_key' => 'required|string',
            'hardware_id' => 'required|string',
            'device_name' => 'nullable|string',
            'device_info' => 'nullable|array',
            'signature' => 'required|string'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        // Verify cryptographic signature
        if (!$this->verifySignature($request->license_key, $request->hardware_id, $request->signature)) {
            AuditLog::create([
                'event_type' => 'license_validation_failed',
                'description' => 'Invalid signature provided',
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'created_at' => now()
            ]);
            
            return response()->json(['error' => 'Invalid signature'], 401);
        }

        $license = License::where('key', $request->license_key)->first();

        if (!$license) {
            AuditLog::create([
                'event_type' => 'license_validation_failed',
                'description' => 'License not found: ' . $request->license_key,
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'created_at' => now()
            ]);
            
            return response()->json(['error' => 'License not found'], 404);
        }

        if (!$license->isValid()) {
            AuditLog::create([
                'event_type' => 'license_validation_failed',
                'description' => 'Invalid license: ' . $license->key,
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'created_at' => now()
            ]);
            
            return response()->json(['error' => 'License is invalid or expired'], 403);
        }

        // Check for existing activation
        $activation = $license->activations()
            ->where('hardware_id', $request->hardware_id)
            ->first();

        if ($activation) {
            // Update last validation timestamp
            $activation->update([
                'last_validation' => now(),
                'ip_address' => $request->ip()
            ]);
        } else {
            // Check if we can activate a new seat
            if (!$license->canActivate()) {
                AuditLog::create([
                    'event_type' => 'license_activation_failed',
                    'description' => 'Seat limit exceeded for license: ' . $license->key,
                    'ip_address' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'created_at' => now()
                ]);
                
                return response()->json(['error' => 'Seat limit exceeded'], 403);
            }

            // Create new activation
            $activation = LicenseActivation::create([
                'license_id' => $license->id,
                'hardware_id' => $request->hardware_id,
                'device_name' => $request->device_name,
                'device_info' => $request->device_info,
                'activated_at' => now(),
                'last_validation' => now(),
                'ip_address' => $request->ip(),
                'is_active' => true
            ]);

            $license->incrementUsedSeats();
            
            AuditLog::create([
                'event_type' => 'license_activated',
                'loggable_id' => $license->id,
                'loggable_type' => License::class,
                'description' => 'New device activated: ' . $request->hardware_id,
                'ip_address' => $request->ip(),
                'user_agent' => $request->userAgent(),
                'created_at' => now()
            ]);
        }

        // Generate short-lived access token
        $token = $license->createToken('api-token', ['*'], now()->addHours(2));

        return response()->json([
            'access_token' => $token->plainTextToken,
            'expires_at' => $token->accessToken->expires_at,
            'license_type' => $license->license_type,
            'seat_limit' => $license->seat_limit,
            'used_seats' => $license->used_seats
        ]);
    }

    public function revokeLicense(Request $request, $licenseId)
    {
        $license = License::findOrFail($licenseId);
        
        $validator = Validator::make($request->all(), [
            'reason' => 'required|string'
        ]);

        if ($validator->fails()) {
            return response()->json(['error' => $validator->errors()], 400);
        }

        $license->revoke($request->reason);
        
        AuditLog::create([
            'event_type' => 'license_revoked',
            'loggable_id' => $license->id,
            'loggable_type' => License::class,
            'description' => 'License revoked: ' . $request->reason,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'created_at' => now()
        ]);

        return response()->json(['message' => 'License revoked successfully']);
    }

    public function getLicenseInfo(Request $request, $licenseId)
    {
        $license = License::with('activations')->findOrFail($licenseId);
        
        return response()->json([
            'license' => $license,
            'activations' => $license->activations
        ]);
    }

    public function deactivateDevice(Request $request, $activationId)
    {
        $activation = LicenseActivation::findOrFail($activationId);
        $activation->deactivate();
        
        AuditLog::create([
            'event_type' => 'device_deactivated',
            'loggable_id' => $activation->license_id,
            'loggable_type' => License::class,
            'description' => 'Device deactivated: ' . $activation->hardware_id,
            'ip_address' => $request->ip(),
            'user_agent' => $request->userAgent(),
            'created_at' => now()
        ]);

        return response()->json(['message' => 'Device deactivated successfully']);
    }

    private function verifySignature($licenseKey, $hardwareId, $signature)
    {
        // This should be implemented with your Rust module
        // Using asymmetric cryptography for better security
        $data = $licenseKey . $hardwareId;
        $publicKey = config('license.public_key');
        
        return openssl_verify($data, base64_decode($signature), $publicKey, OPENSSL_ALGO_SHA256) === 1;
    }
}