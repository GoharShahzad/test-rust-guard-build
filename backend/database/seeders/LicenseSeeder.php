<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\License;
use Illuminate\Support\Str;
use Carbon\Carbon;

class LicenseSeeder extends Seeder
{
    public function run(): void
    {
        License::create([
            'key' => 'TEST-MONTHLY-001',
            'plan' => 'monthly',
            'seat_limit' => 2,
            'expires_at' => Carbon::now()->addMonths(1),
        ]);

        License::create([
            'key' => 'TEST-ANNUAL-001',
            'plan' => 'annual',
            'seat_limit' => 5,
            'expires_at' => Carbon::now()->addYear(),
        ]);

        License::create([
            'key' => 'TEST-TRIAL-001',
            'plan' => 'trial',
            'seat_limit' => 1,
            'expires_at' => Carbon::now()->addDays(7),
        ]);
    }
}
