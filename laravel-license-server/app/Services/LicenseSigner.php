<?php
namespace App\Services;

use ParagonIE\ConstantTime\Base64UrlSafe;
use Illuminate\Support\Carbon;

class LicenseSigner
{
    private string $secretKey;

    public function __construct()
    {
        $b64 = env('LICENSE_PRIVATE_ED25519_B64');
        if (!$b64) throw new \RuntimeException('Missing LICENSE_PRIVATE_ED25519_B64');
        $this->secretKey = base64_decode($b64, true);
    }

    public function signToken(array $payload): string
    {
        $payload['srv']  = Carbon::now('UTC')->unix();
        $payload['nonce']= bin2hex(random_bytes(16));
        $payload['ver']  = 1;

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if (strlen($this->secretKey) === 32) {
            $kp = sodium_crypto_sign_seed_keypair($this->secretKey);
            $sk = sodium_crypto_sign_secretkey($kp);
        } else { $sk = $this->secretKey; }

        $sig = sodium_crypto_sign_detached($json, $sk);
        return Base64UrlSafe::encodeUnpadded($json).'.'.Base64UrlSafe::encodeUnpadded($sig);
    }
}
