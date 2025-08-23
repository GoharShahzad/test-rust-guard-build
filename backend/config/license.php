<?php

return [
    'public_key' => env('LICENSE_PUBLIC_KEY'),
    'token_expiry' => env('LICENSE_TOKEN_EXPIRY', 2), // hours
    'signature_algorithm' => env('LICENSE_SIGNATURE_ALGORITHM', 'sha256'),
];